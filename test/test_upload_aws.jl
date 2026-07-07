# Upload.jl resume semantics against LocalStack (gated on AWS_ENDPOINT_URL). The full
# push-level behavior (partial-failure progress file, cross-language resume, clean-run
# clear) is pinned black-box by tests_contract/test_push_contract.py; this exercises
# `upload_data_to_s3`'s own contract natively: failure collection (never raises), the
# {prefix}{rel}-keyed resume set, and skip-already-uploaded filtering.
#
# `upload_data_to_s3` calls `assume_lab_operator()` internally, so this seeds the same
# credential seam the contract harness uses: a temp AWS credentials/config file pair with a
# dummy static-key profile, plus LAB_OPERATOR_ROLE_ARN pointing at a role that needn't
# exist (STS against LocalStack without ENFORCE_IAM hands out temp creds regardless).

import AWS

@testset "Upload resume (LocalStack)" begin
    endpoint = ENV["AWS_ENDPOINT_URL"]
    root_cfg = LabAPI.AWSIdent.LabConfig(AWS.AWSCredentials("test", "test"), "us-east-1", endpoint)
    sfx = string(rand(UInt32); base = 16)
    bucket = "research-upload-$sfx"
    LabAPI.AWSIdent.S3.create_bucket(bucket; aws_config = root_cfg)

    mktempdir() do home
        creds_file = joinpath(home, "credentials")
        config_file = joinpath(home, "config")
        write(creds_file, "[caucellcloud-lab-operator]\naws_access_key_id = test\naws_secret_access_key = test\n")
        write(config_file, "[profile caucellcloud-lab-operator]\nregion = us-east-1\n")

        saved = Dict(k => get(ENV, k, nothing) for k in
                     ("AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_PROFILE", "SYNC_WORKERS"))
        ENV["AWS_SHARED_CREDENTIALS_FILE"] = creds_file
        ENV["AWS_CONFIG_FILE"] = config_file
        ENV["AWS_PROFILE"] = "caucellcloud-lab-operator"
        ENV["SYNC_WORKERS"] = "2"
        try
            withprogress() do progress_dir
                mktempdir() do data
                    write(joinpath(data, "good.txt"), "hello")
                    # "ghost.txt" is in the upload list but absent on disk → its read fails →
                    # collected as a failure, not raised.
                    uploaded, failed = upload_data_to_s3(
                        bucket, data, ["good.txt", "ghost.txt"], "UploadUnit"; prefix="Data/")
                    @test uploaded == 1
                    @test failed == 1

                    # Partial failure leaves the resume file, keyed by full S3 key.
                    @test load_progress("UploadUnit") == Set(["Data/good.txt"])
                    resp = LabAPI.AWSIdent.S3.get_object(bucket, "Data/good.txt"; aws_config = root_cfg)
                    @test String(resp) == "hello"

                    # Second run: the resume set filters good.txt out; the fixed file uploads.
                    write(joinpath(data, "ghost.txt"), "world")
                    uploaded2, failed2 = upload_data_to_s3(
                        bucket, data, ["good.txt", "ghost.txt"], "UploadUnit"; prefix="Data/")
                    @test uploaded2 == 2   # cumulative resume-set size
                    @test failed2 == 0
                    @test load_progress("UploadUnit") == Set(["Data/good.txt", "Data/ghost.txt"])
                end
            end
        finally
            for (k, v) in saved
                v === nothing ? delete!(ENV, k) : (ENV[k] = v)
            end
        end
    end
end
