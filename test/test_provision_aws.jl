# Re-authors tests/test_provision.py against Provision.jl — LocalStack-backed (gated on
# AWS_ENDPOINT_URL). Self-seeds its own KMS key + IAM group and uses uniquely-named resources
# so it never collides with contract-harness state. The deep behavior of these functions
# (versioning/encryption/tags/policy/lifecycle byte shapes) is asserted by the black-box
# contract suite; this is a native smoke that the real code path runs green against LocalStack.

import AWS

# IAM returns inline policy documents URL-encoded inside the XML response. The policy is
# pure ASCII, so a byte-wise percent-decode suffices (no URIs.jl dependency needed).
_unescapeuri(s) = replace(String(s), r"%[0-9A-Fa-f]{2}" => m -> string(Char(parse(UInt8, m[2:3]; base=16))))

@testset "Provision / S3 manifest (LocalStack)" begin
    endpoint = ENV["AWS_ENDPOINT_URL"]
    cfg = LabAPI.AWSIdent.LabConfig(AWS.AWSCredentials("test", "test"), "us-east-1", endpoint)
    sfx = string(rand(UInt32); base = 16)
    bucket = "research-unit-$sfx"

    kms_arn = LabAPI.AWSIdent.KMS.create_key(; aws_config = cfg)["KeyMetadata"]["Arn"]

    @testset "configure_bucket + create_prefix_structure" begin
        configure_bucket(cfg, bucket, kms_arn)
        create_prefix_structure(cfg, bucket, kms_arn)
        # build_s3_manifest with the empty prefix lists all objects but skips the trailing-slash
        # prefix placeholders, so the seeded root README.md is what remains.
        m = build_s3_manifest(cfg, bucket, "")
        @test haskey(m, "README.md")
        @test m["README.md"].size > 0
        @test m["README.md"].last_modified > 0
    end

    @testset "create_lab_iam_user" begin
        try
            LabAPI.AWSIdent.IAM.create_group(config().lab_group; aws_config = cfg)
        catch  # group may already exist on a warm LocalStack
        end
        arn, key_id, secret = create_lab_iam_user(cfg, "UnitUser$sfx", bucket, "000000000000")
        @test occursin("LabCustomer-UnitUser$sfx", arn)
        @test length(key_id) == 20
        @test !isempty(secret)
    end

    @testset "put_lab_customer_s3_policy is independently re-appliable" begin
        username = "LabCustomer-UnitUser$sfx"
        # Drift: remove the policy created above, re-apply standalone (the
        # migrate-policy-settings path), and re-apply again (idempotence).
        LabAPI.AWSIdent.IAM.delete_user_policy("s3-bucket-access", username; aws_config = cfg)
        put_lab_customer_s3_policy(cfg, username, bucket)
        put_lab_customer_s3_policy(cfg, username, bucket)
        resp = LabAPI.AWSIdent.IAM.get_user_policy("s3-bucket-access", username; aws_config = cfg)
        doc = JSON3.read(_unescapeuri(resp["GetUserPolicyResult"]["PolicyDocument"]))
        sids = Dict(String(s["Sid"]) => s for s in doc["Statement"])
        @test Set(keys(sids)) == Set(["ListOwnBucket", "ReadAllPrefixes", "WriteIncomingOnly"])
        @test Set(String.(sids["ListOwnBucket"]["Action"])) == Set(["s3:ListBucket", "s3:GetBucketLocation"])
    end
end
