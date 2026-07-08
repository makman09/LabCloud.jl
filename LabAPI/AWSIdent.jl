"""
    AWSIdent

Two ways of landing in the same `LabOperatorRole`, per its terraform trust policy
(`iam.tf`): `assume_lab_operator()` (refreshable, no MFA, `RoutineAutomationNoMfa` Sid) for
everything routine, and `assume_bypass_role(mfa_code)` (one-shot, `BypassDeleteRequiresMfa`
Sid, restricted to `var.bypass_user_arns`) for the delete flow's governance-retention version
wipe. `S3PhiBypassRole` used to be a separate role for that second path — it was folded into
`LabOperatorRole`, with the destructive S3 actions gated by their own
`aws:MultiFactorAuthPresent` condition in the role's permission policy instead of by being a
different role entirely. `get_admin_session()` exists only to bootstrap the MFA device
lookup, exactly like Python (now against the `AWS_BYPASS_PROFILE` local profile rather than a
hardcoded name).

AWS.jl has no `AWS_ENDPOINT_URL` support (unlike boto3/botocore), so every identity here is
carried as a `LabConfig` — an `AbstractAWSConfig` that, when `endpoint` is set, forces
EVERY service call through that single host, path-style (`https://endpoint/resource`,
resource already containing `/{Bucket}/{Key}` etc — see the `generate_service_url` override
below for why S3 doesn't need special-casing to avoid virtual-hosted-style addressing).
`endpoint === nothing` is real AWS: delegate straight to AWS.jl's own generator.
"""
module AWSIdent

using AWS: AWS, @service, AbstractAWSConfig, AWSCredentials
using Dates
using ..Config: config
using ..Util: AppError, as_vector, _parse_iso8601

# Each `@service` invocation `include()`s that service's generated function file into a
# fresh submodule here (S3.create_bucket, STS.assume_role, IAM.list_mfadevices,
# KMS.describe_key, ...) — see AWS.jl's `@service` docstring. There is no `AWS.S3`/`AWS.STS`
# etc built in; these submodules are ours.
@service S3
@service STS
@service IAM
@service KMS

export LabConfig, assume_lab_operator, assume_bypass_role, resolve_kms_key_arn, _error_code

"""
    LabConfig <: AWS.AbstractAWSConfig

Carries creds + region like `AWS.AWSConfig`, plus an optional `endpoint` override. When
`endpoint` is set (from `AWS_ENDPOINT_URL`, e.g. under the LocalStack contract harness),
every service call is redirected there instead of `*.amazonaws.com`.
"""
struct LabConfig <: AbstractAWSConfig
    creds::AWSCredentials
    region::String
    endpoint::Union{String,Nothing}
end

AWS.region(c::LabConfig) = c.region
AWS.credentials(c::LabConfig) = c.creds

"""
    AWS.generate_service_url(c::LabConfig, service, resource) -> String

`resource` already contains the bucket/key path for S3 (e.g. `/research-johnsmith/Data/x`,
built by AWS.jl's own `create_bucket`/`get_object`/etc before this is called) — so simply
prefixing our endpoint keeps every service, S3 included, path-style. No virtual-hosted-style
fixup is needed: AWS.jl never puts the bucket in the host to begin with.
"""
function AWS.generate_service_url(c::LabConfig, service::String, resource::String)
    if c.endpoint === nothing
        return AWS.generate_service_url(AWS.AWSConfig(; creds=c.creds, region=c.region), service, resource)
    end
    return string(rstrip(c.endpoint, '/'), resource)
end

"""
    AWS.sign_aws4!(aws::LabConfig, request::AWS.Request, time::Dates.DateTime) -> AWS.Request

Correctness fix for a real bug in installed `AWS.jl` 1.98.1's `sign_aws4!`. Its
`canonical_headers` are built by sorting the joined `"name:value"` strings, while
`signed_headers` (and the `SignedHeaders` it puts in the `Authorization` header) are built by
sorting header *names* only. Those two orderings diverge whenever one signed header name is a
strict prefix of another, because `-` (0x2D) sorts before `:` (0x3A): the longer name's
`"name:value"` string then sorts BEFORE the shorter name's, even though the shorter name must
come first when sorting by name alone. That's exactly what happens with S3's
`x-amz-server-side-encryption` / `x-amz-server-side-encryption-aws-kms-key-id` pair, which
`create_prefix_structure`/`create_lab_iam_user` send together — the client ends up signing a
canonical request in one header order while declaring `SignedHeaders` in the other, so AWS
recomputes a different hash and returns `SignatureDoesNotMatch`. Reproduced against real S3
(not caught by LocalStack's laxer signature verification, which is why the module docstring
in `Provision.jl` previously called this path "confirmed" safe).

Otherwise a byte-for-byte copy of `AWS.sign_aws4!`, with `canonical_headers` sorted by header
name (matching `signed_headers`) instead of by the joined string. Dispatches on `LabConfig`
so it only overrides signing for our own config type — every other `AbstractAWSConfig` keeps
using AWS.jl's stock method.
"""
function AWS.sign_aws4!(aws::LabConfig, request::AWS.Request, time::DateTime)
    date = Dates.format(time, dateformat"yyyymmdd")
    datetime = Dates.format(time, dateformat"yyyymmdd\THHMMSS\Z")

    authentication_scope = [date, AWS.region(aws), request.service, "aws4_request"]

    creds = AWS.refresh!(AWS.credentials(aws))
    signing_key = Vector{UInt8}("AWS4$(creds.secret_key)")
    for scope in authentication_scope
        signing_key = AWS.hmac_sha256(signing_key, scope)
    end
    authentication_scope = join(authentication_scope, "/")

    content_hash = bytes2hex(AWS.sha256(request.content))

    delete!(request.headers, "Authorization")
    merge!(
        request.headers,
        Dict(
            "x-amz-content-sha256" => content_hash,
            "x-amz-date" => datetime,
            "Content-MD5" => AWS.base64encode(AWS.md5(request.content)),
        ),
    )
    if !isempty(creds.token)
        request.headers["x-amz-security-token"] = creds.token
    end

    # The fix: sort by header NAME (matching `signed_headers`), not by the joined
    # "name:value" string — see docstring for why the two diverge.
    sorted_names = sort!(collect(keys(request.headers)); by=lowercase)
    canonical_headers = join(
        ["$(lowercase(k)):$(strip(request.headers[k]))" for k in sorted_names], "\n"
    )
    signed_headers = join([lowercase(k) for k in sorted_names], ";")

    uri = AWS.HTTP.URI(request.url)
    query = sort!(AWS.HTTP.URIs.queryparampairs(uri.query))

    canonical_form = string(
        request.request_method,
        "\n",
        request.service == "s3" ? uri.path : AWS.HTTP.escapepath(uri.path),
        "\n",
        AWS.HTTP.escapeuri(query),
        "\n",
        canonical_headers,
        "\n\n",
        signed_headers,
        "\n",
        content_hash,
    )

    canonical_hash = bytes2hex(AWS.sha256(canonical_form))
    string_to_sign = "AWS4-HMAC-SHA256\n$datetime\n$authentication_scope\n$canonical_hash"
    signature = bytes2hex(AWS.hmac_sha256(signing_key, string_to_sign))

    request.headers["Authorization"] = join(
        [
            "AWS4-HMAC-SHA256 Credential=$(creds.access_key_id)/$authentication_scope",
            "SignedHeaders=$signed_headers",
            "Signature=$signature",
        ],
        ", ",
    )

    return request
end

_endpoint() = get(ENV, "AWS_ENDPOINT_URL", nothing)

# AWS error `code` (`nothing` for non-AWS exceptions). Shared by `Lifecycle`/`Status`.
_error_code(e) = e isa AWS.AWSException ? e.code : nothing

"""
    make_config(profile; assume_role_arn=nothing, mfa=nothing, session_name="lab-session") -> LabConfig

Base config for `profile`, carrying the current `AWS_ENDPOINT_URL` (if any). With
`assume_role_arn`, returns a config wrapping the assumed-role temp creds instead (same
endpoint, so the assumed session still hits LocalStack under the harness).
"""
function make_config(profile; assume_role_arn=nothing, mfa=nothing, session_name="lab-session")
    base = LabConfig(AWSCredentials(; profile=profile), config().region, _endpoint())
    assume_role_arn === nothing && return base
    return assume(base, assume_role_arn; mfa=mfa, session_name=session_name)
end

"""
    _first_mfa_serial(mfa_resp, username) -> String

Extracts the first MFA device's `SerialNumber` from an `iam:ListMFADevices` response,
raising `AppError` with the exact `click.ClickException` message `src/aws.py` raises if none
is registered. The `MFADevices` element is itself XML-list-shaped: zero devices means no
`"member"` key at all (an empty `LittleDict`, NOT an empty `Vector`) — so the empty case must
be checked via `haskey` before reaching for `as_vector` (see `Util.as_vector`'s docstring).
"""
function _first_mfa_serial(mfa_resp, username)
    devices_elem = mfa_resp["ListMFADevicesResult"]["MFADevices"]
    devices = haskey(devices_elem, "member") ? as_vector(devices_elem["member"]) : []
    isempty(devices) && throw(AppError("No MFA device found for user '$username'"))
    return first(devices)["SerialNumber"]
end

"""
    assume(base, role_arn; mfa=nothing, session_name) -> LabConfig

Hand-rolled `sts:AssumeRole`, mirroring `src/aws.py`. Without `mfa`, a plain assume-role.
With `mfa`, first resolves the caller's IAM username (`sts:GetCallerIdentity`), looks up
their MFA device serial (`iam:ListMFADevices`) — raising the exact
`click.ClickException`-equivalent `AppError` message if none exists — then assumes with
`SerialNumber`/`TokenCode`. Returns a fresh `LabConfig` carrying the SAME endpoint, so the
assumed session still resolves against LocalStack under the harness.
"""
function assume(base::LabConfig, role_arn; mfa=nothing, session_name="lab-session")
    creds_dict = if mfa === nothing
        result = STS.assume_role(role_arn, session_name; aws_config=base)
        result["AssumeRoleResult"]["Credentials"]
    else
        identity = STS.get_caller_identity(; aws_config=base)
        username = split(identity["GetCallerIdentityResult"]["Arn"], "/")[end]

        mfa_resp = IAM.list_mfadevices(Dict("UserName" => username); aws_config=base)
        serial = _first_mfa_serial(mfa_resp, username)

        result = STS.assume_role(
            role_arn, session_name,
            Dict("SerialNumber" => serial, "TokenCode" => mfa);
            aws_config=base,
        )
        result["AssumeRoleResult"]["Credentials"]
    end

    new_creds = AWSCredentials(
        creds_dict["AccessKeyId"], creds_dict["SecretAccessKey"], creds_dict["SessionToken"]
    )
    return LabConfig(new_creds, base.region, base.endpoint)
end

"""
    _parse_expiry(s) -> DateTime

Parse an STS `Expiration` timestamp into the implicit-UTC `DateTime` that
`AWSCredentials.expiry` expects. Tolerates a `Z` or `+00:00` suffix and any fractional-
second precision (LocalStack emits microseconds, e.g. "2026-07-07T06:30:30.382856Z";
`Dates.DateTime` parses at most milliseconds, so extra digits are truncated).
"""
_parse_expiry(s) = _parse_iso8601(s)

"""
    assume_lab_operator() -> LabConfig

`LabOperatorRole`, assumed from the `AWS_PROFILE` static-key profile (default
`caucellcloud-lab-operator`). No MFA. Mirrors `src/aws.py`'s
`_refreshable_assume_role_session`: the returned config's credentials carry a `renew`
closure that re-runs `sts:AssumeRole` (`DurationSeconds=14400`, `RoleSessionName=
"lab-operator"`), and AWS.jl's `sign!` calls `refresh!` on every request — so a multi-hour
`push` transparently re-assumes the role when the temp creds are within 5 minutes of expiry
(`_is_expired`'s drift) instead of dying with `ExpiredToken`. `refresh!` copies every field
EXCEPT the `renew` closure itself back into the live credentials object (verified against
the installed AWS.jl source), so renewal keeps working across renewals.
"""
function assume_lab_operator()
    cfg = config()
    base = LabConfig(AWSCredentials(; profile=cfg.profile), cfg.region, _endpoint())
    fetch_creds = function ()
        result = STS.assume_role(
            cfg.role_arn, "lab-operator",
            Dict("DurationSeconds" => "14400");
            aws_config=base,
        )
        c = result["AssumeRoleResult"]["Credentials"]
        return AWSCredentials(
            c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"];
            expiry=_parse_expiry(c["Expiration"]),
        )
    end
    initial = fetch_creds()
    creds = AWSCredentials(
        initial.access_key_id, initial.secret_key, initial.token;
        expiry=initial.expiry, renew=fetch_creds,
    )
    return LabConfig(creds, cfg.region, base.endpoint)
end

"""
    get_admin_session() -> LabConfig

Base session for `config().bypass_profile` (env `AWS_BYPASS_PROFILE`, default
`caucellcloud`) — a local AWS CLI profile for a human admin identity listed in terraform's
`bypass_user_arns`, distinct from the `lab-operator` service user `assume_lab_operator()`
uses. Only exists to bootstrap the MFA device lookup in `assume_bypass_role`.
"""
get_admin_session() = make_config(config().bypass_profile)

"""
    assume_bypass_role(mfa_code) -> LabConfig

Assumes `LabOperatorRole` — the SAME role ARN as `assume_lab_operator()` — but via the
admin session's `BypassDeleteRequiresMfa` trust statement, gated on the admin user's TOTP MFA
code. That MFA claim on the resulting session is what unlocks the role's destructive
`BypassAndDeleteLockedObjects`/`ListResearchPhiBuckets` policy Sids (each carries its own
`aws:MultiFactorAuthPresent` condition — a `assume_lab_operator()` session can never satisfy
it, only this MFA'd one can). Raises `AppError` if the admin user has no MFA device
registered.
"""
function assume_bypass_role(mfa_code)
    admin = get_admin_session()
    return assume(admin, config().role_arn; mfa=mfa_code, session_name="bypass-delete")
end

"""
    resolve_kms_key_arn(cfg) -> String

Resolves `config().kms_alias` to its key ARN via `kms:DescribeKey`.
"""
function resolve_kms_key_arn(cfg)
    resp = KMS.describe_key(config().kms_alias; aws_config=cfg)
    return resp["KeyMetadata"]["Arn"]
end

end # module AWSIdent
