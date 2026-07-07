"""
    AWSIdent

Julia port of `src/aws.py` — the two-identity session model: `assume_lab_operator()` (the
consolidated LabOperatorRole, refreshable, no MFA) for everything routine, and
`assume_bypass_role(mfa_code)` (S3PhiBypassRole, MFA-gated, one-shot) for the delete flow's
governance-retention version wipe. `get_admin_session()` exists only to bootstrap the MFA
device lookup, exactly like Python.

AWS.jl has no `AWS_ENDPOINT_URL` support (unlike boto3/botocore), so every identity here is
carried as a `LabConfig` — an `AbstractAWSConfig` that, when `endpoint` is set, forces
EVERY service call through that single host, path-style (`https://endpoint/resource`,
resource already containing `/{Bucket}/{Key}` etc — see the `generate_service_url` override
below for why S3 doesn't need special-casing to avoid virtual-hosted-style addressing).
`endpoint === nothing` is real AWS: delegate straight to AWS.jl's own generator.
"""
module AWSIdent

using AWS: AWS, @service, AbstractAWSConfig, AWSCredentials
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

Plain `caucellcloud` admin profile (hardcoded name, matching `src/aws.py`).
"""
get_admin_session() = make_config("caucellcloud")

"""
    assume_bypass_role(mfa_code) -> LabConfig

`S3PhiBypassRole`, gated on the admin user's TOTP MFA code. Raises `AppError` if the admin
user has no MFA device registered.
"""
function assume_bypass_role(mfa_code)
    admin = get_admin_session()
    return assume(admin, config().bypass_role_arn; mfa=mfa_code, session_name="bypass-delete")
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
