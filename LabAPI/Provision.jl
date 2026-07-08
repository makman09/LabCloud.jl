"""
    Provision

Julia port of `src/provision.py` — bucket hardening (versioning, KMS encryption, public-access
block, TLS-only policy, multipart-abort lifecycle rule), prefix structure, and IAM user
creation for customers and vendors.

## AWS.jl gotcha: XML-body S3 config calls need a hand-rolled body

AWS.jl's generated `S3.put_bucket_versioning`/`put_bucket_encryption`/`put_bucket_tagging`/
`put_bucket_policy`/`put_bucket_lifecycle_configuration`/`put_public_access_block` wrap their
shape argument under its own name (e.g. `Dict("VersioningConfiguration" => cfg)`) and hand
that straight to `AWS.jl`'s generic REST-XML request functor. That functor only recognizes
two special keys — `"body"` (raw request content) and `"headers"` (a nested dict of real HTTP
headers) — everything else gets flattened into the query string via `HTTP.escapeuri`
(confirmed empirically against LocalStack: a `put_bucket_versioning` call this way produced
`PUT /bucket?versioning&VersioningConfiguration=Status=Enabled` — the shape landed in the
URL, not the body — and LocalStack 400'd with "The Versioning element must be specified").
So these six calls bypass the generated wrappers entirely: hand-build the XML (or, for the
bucket policy, plain JSON — S3 does NOT wrap the policy body in XML) and PUT it via the raw
`AWS.AWSServices.s3` REST-XML callable under `"body"`. Genuine header-shaped params (SSE
headers on `put_object`, the object-lock-enabled header on `create_bucket`) go through the
same functor's `"headers"` key instead — that path IS shape-correct in the generated
wrappers (the headers land as real HTTP headers, not query params), so
`create_prefix_structure`/`create_lab_iam_user` use them directly, no bypass needed. This is
the harness's "Risk #3" finding, cross-checked against boto3 on the same LocalStack instance
to confirm the intended shapes.

Separately (found against real AWS, not LocalStack): sending the SSE-KMS header pair
`x-amz-server-side-encryption`/`x-amz-server-side-encryption-aws-kms-key-id` together used to
trip a `SignatureDoesNotMatch` from installed `AWS.jl` 1.98.1's `sign_aws4!` — one header name
is a strict prefix of the other, which its canonical-header sort orders inconsistently with
`SignedHeaders`. Fixed via an `AWS.sign_aws4!(::LabConfig, ...)` override in `AWSIdent.jl`
(see that docstring); LocalStack never caught it because it doesn't strictly verify SigV4
canonical header ordering.
"""
module Provision

using AWS: AWS
using AWS.AWSServices: s3 as s3_raw
using JSON3

using ..Config: PREFIXES, config
using ..AWSIdent

export configure_bucket, create_prefix_structure, put_lab_customer_s3_policy,
       create_lab_iam_user, create_vendor_readme, create_order_prefix, create_vendor_iam_user

const S3_XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"

_already_exists(e) = e isa AWS.AWSExceptions.AWSException &&
                     e.code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists")

"""
    configure_bucket(cfg, bucket_name, kms_key_arn; purpose="research")

Create (idempotently) and harden a research/vendor-landing bucket: versioning, SSE-KMS
default encryption (bucket-key enabled), a full public-access block, tagging, the
`abort-incomplete-multipart-uploads` lifecycle rule, and a `DenyInsecureTransport` bucket
policy. Mirrors `src/provision.py::configure_bucket` line for line, including the
LocalStack-known no-op: the TLS-only policy is set but not enforced there (real AWS/moto do
enforce it — see `tests_contract/README.md` quirk #5).
"""
function configure_bucket(cfg, bucket_name, kms_key_arn; purpose="research")
    create_args = Dict{String,Any}("headers" => Dict("x-amz-bucket-object-lock-enabled" => "true"))
    if config().region != "us-east-1"
        create_args["body"] = """<CreateBucketConfiguration xmlns="$S3_XMLNS"><LocationConstraint>$(config().region)</LocationConstraint></CreateBucketConfiguration>"""
    end
    try
        AWSIdent.S3.create_bucket(bucket_name, create_args; aws_config=cfg)
    catch e
        _already_exists(e) || rethrow()
    end

    # Every hardening step is a `PUT /{bucket}?{subresource}` with a hand-built XML/JSON body
    # (see the module docstring for why these bypass AWS.jl's generated wrappers).
    put_sub(sub, body) = s3_raw("PUT", "/$(bucket_name)?$sub", Dict{String,Any}("body" => body); aws_config=cfg)

    put_sub("versioning", """<VersioningConfiguration xmlns="$S3_XMLNS"><Status>Enabled</Status></VersioningConfiguration>""")

    enc_xml = """<ServerSideEncryptionConfiguration xmlns="$S3_XMLNS"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>$(kms_key_arn)</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>"""
    put_sub("encryption", enc_xml)

    pab_xml = """<PublicAccessBlockConfiguration xmlns="$S3_XMLNS"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>"""
    put_sub("publicAccessBlock", pab_xml)

    # Reclaim parts from interrupted multipart uploads (safe under object lock — it only
    # touches incomplete uploads, never committed objects or versions).
    lifecycle_xml = """<LifecycleConfiguration xmlns="$S3_XMLNS"><Rule><ID>abort-incomplete-multipart-uploads</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status><AbortIncompleteMultipartUpload><DaysAfterInitiation>$(config().multipart_abort_days)</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>"""
    put_sub("lifecycle", lifecycle_xml)

    tag_xml = """<Tagging xmlns="$S3_XMLNS"><TagSet><Tag><Key>Purpose</Key><Value>$purpose</Value></Tag><Tag><Key>DataClass</Key><Value>PHI</Value></Tag><Tag><Key>ManagedBy</Key><Value>LabOperatorRole</Value></Tag></TagSet></Tagging>"""
    put_sub("tagging", tag_xml)

    policy = Dict(
        "Version" => "2012-10-17",
        "Statement" => [Dict(
            "Sid" => "DenyInsecureTransport",
            "Effect" => "Deny",
            "Principal" => "*",
            "Action" => "s3:*",
            "Resource" => ["arn:aws:s3:::$bucket_name", "arn:aws:s3:::$bucket_name/*"],
            "Condition" => Dict("Bool" => Dict("aws:SecureTransport" => "false")),
        )],
    )
    put_sub("policy", JSON3.write(policy))

    return nothing
end

_sse_headers(kms_key_arn) = Dict(
    "x-amz-server-side-encryption" => "aws:kms",
    "x-amz-server-side-encryption-aws-kms-key-id" => kms_key_arn,
)

"""
    create_prefix_structure(cfg, bucket_name, kms_key_arn)

Puts the empty `Archive/ Data/ Other/ Result/` prefix placeholders plus a root `README.md`,
all under the bucket's default SSE-KMS key. Mirrors `src/provision.py::create_prefix_structure`.
"""
function create_prefix_structure(cfg, bucket_name, kms_key_arn)
    headers = _sse_headers(kms_key_arn)
    for prefix in PREFIXES
        AWSIdent.S3.put_object(bucket_name, prefix,
            Dict{String,Any}("body" => UInt8[], "headers" => headers); aws_config=cfg)
    end
    AWSIdent.S3.put_object(bucket_name, "README.md",
        Dict{String,Any}("body" => "# Research Bucket\n", "headers" => headers); aws_config=cfg)
    return nothing
end

"""
    put_lab_customer_s3_policy(cfg, username, bucket_name)

(Re-)apply the researcher's inline S3 policy. Idempotent — safe to re-run on an existing
user to push policy changes without touching their access key (this is what
`migrate-policy-settings` calls). Deliberately omits `s3:ListAllMyBuckets` — see
`src/provision.py::put_lab_customer_s3_policy`'s docstring for the console-deep-link
rationale. Mirrors that function statement for statement.
"""
function put_lab_customer_s3_policy(cfg, username, bucket_name)
    policy_doc = Dict(
        "Version" => "2012-10-17",
        "Statement" => [
            Dict("Sid" => "ListOwnBucket", "Effect" => "Allow",
                 "Action" => ["s3:ListBucket", "s3:GetBucketLocation"],
                 "Resource" => "arn:aws:s3:::$bucket_name"),
            Dict("Sid" => "ReadAllPrefixes", "Effect" => "Allow", "Action" => "s3:GetObject",
                 "Resource" => "arn:aws:s3:::$bucket_name/*"),
            Dict("Sid" => "WriteIncomingOnly", "Effect" => "Allow", "Action" => "s3:PutObject",
                 "Resource" => "arn:aws:s3:::$bucket_name/Data/*"),
        ],
    )
    AWSIdent.IAM.put_user_policy(JSON3.write(policy_doc), "s3-bucket-access", username; aws_config=cfg)
    return nothing
end

"""
    create_lab_iam_user(cfg, customer_name, bucket_name, account_id) -> (user_arn, access_key_id, secret_key)

Creates `LabCustomer-{customer_name}` (idempotent against `EntityAlreadyExists`, mirroring
the Python `except ClientError` fallback to the deterministic ARN), attaches the scoped
`s3-bucket-access` inline policy via `put_lab_customer_s3_policy`, adds it to
`LAB_CUSTOMERS_GROUP`, and mints an access key. Mirrors
`src/provision.py::create_lab_iam_user`.
"""
function create_lab_iam_user(cfg, customer_name, bucket_name, account_id)
    username = "LabCustomer-$customer_name"

    user_arn = try
        resp = AWSIdent.IAM.create_user(username, Dict{String,Any}("Tags" => [
            Dict("Key" => "Purpose", "Value" => "research"),
            Dict("Key" => "DataClass", "Value" => "PHI"),
            Dict("Key" => "LabName", "Value" => customer_name),
        ]); aws_config=cfg)
        resp["CreateUserResult"]["User"]["Arn"]
    catch e
        if e isa AWS.AWSExceptions.AWSException && e.code == "EntityAlreadyExists"
            "arn:aws:iam::$account_id:user/$username"
        else
            rethrow()
        end
    end

    put_lab_customer_s3_policy(cfg, username, bucket_name)
    AWSIdent.IAM.add_user_to_group(config().lab_group, username; aws_config=cfg)

    key = AWSIdent.IAM.create_access_key(Dict{String,Any}("UserName" => username); aws_config=cfg)
    key = key["CreateAccessKeyResult"]["AccessKey"]
    return user_arn, key["AccessKeyId"], key["SecretAccessKey"]
end

"""
    create_vendor_readme(cfg, bucket_name, kms_key_arn)

Seeds the vendor landing bucket's root `README.md` (SSE-KMS). Mirrors
`src/provision.py::create_vendor_readme`.
"""
function create_vendor_readme(cfg, bucket_name, kms_key_arn)
    body = "# Vendor Landing Bucket\n\nUpload raw sequencing data under each order's `{uuid}/` prefix.\n"
    AWSIdent.S3.put_object(bucket_name, "README.md",
        Dict{String,Any}("body" => body, "headers" => _sse_headers(kms_key_arn)); aws_config=cfg)
    return nothing
end

"""
    create_order_prefix(cfg, bucket_name, order_id, kms_key_arn)

Creates the `{order_id}/` placeholder so an order is discoverable before any object lands.
Mirrors `src/provision.py::create_order_prefix`.
"""
function create_order_prefix(cfg, bucket_name, order_id, kms_key_arn)
    AWSIdent.S3.put_object(bucket_name, "$order_id/",
        Dict{String,Any}("body" => UInt8[], "headers" => _sse_headers(kms_key_arn)); aws_config=cfg)
    return nothing
end

"""
    create_vendor_iam_user(cfg, vendor_name, bucket_name, account_id) -> (user_arn, access_key_id, secret_key)

Creates `LabVendor-{vendor_name}` (idempotent against `EntityAlreadyExists`), attaches the
scoped `s3-bucket-access` inline policy — bucket-level `ListBucket`+`ListBucketMultipartUploads`
on the **bucket** ARN (NOT `/*`, or large `aws s3 sync` uploads AccessDeny in real AWS) plus
read/write on `/*` — adds it to `VENDOR_GROUP`, and mints an access key. Mirrors
`src/provision.py::create_vendor_iam_user`.
"""
function create_vendor_iam_user(cfg, vendor_name, bucket_name, account_id)
    username = "LabVendor-$vendor_name"

    user_arn = try
        resp = AWSIdent.IAM.create_user(username, Dict{String,Any}("Tags" => [
            Dict("Key" => "Purpose", "Value" => "vendor-landing"),
            Dict("Key" => "DataClass", "Value" => "PHI"),
            Dict("Key" => "VendorName", "Value" => vendor_name),
        ]); aws_config=cfg)
        resp["CreateUserResult"]["User"]["Arn"]
    catch e
        if e isa AWS.AWSExceptions.AWSException && e.code == "EntityAlreadyExists"
            "arn:aws:iam::$account_id:user/$username"
        else
            rethrow()
        end
    end

    policy_doc = Dict(
        "Version" => "2012-10-17",
        "Statement" => [
            Dict("Sid" => "ListAndMultipartOnBucket", "Effect" => "Allow",
                 "Action" => ["s3:ListBucket", "s3:ListBucketMultipartUploads"],
                 "Resource" => "arn:aws:s3:::$bucket_name"),
            Dict("Sid" => "ReadWriteObjects", "Effect" => "Allow",
                 "Action" => ["s3:PutObject", "s3:GetObject",
                              "s3:ListMultipartUploadParts", "s3:AbortMultipartUpload"],
                 "Resource" => "arn:aws:s3:::$bucket_name/*"),
        ],
    )
    AWSIdent.IAM.put_user_policy(JSON3.write(policy_doc), "s3-bucket-access", username; aws_config=cfg)
    AWSIdent.IAM.add_user_to_group(config().vendor_group, username; aws_config=cfg)

    key = AWSIdent.IAM.create_access_key(Dict{String,Any}("UserName" => username); aws_config=cfg)
    key = key["CreateAccessKeyResult"]["AccessKey"]
    return user_arn, key["AccessKeyId"], key["SecretAccessKey"]
end

end # module Provision
