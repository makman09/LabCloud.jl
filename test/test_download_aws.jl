# Download.jl streaming against LocalStack (gated on AWS_ENDPOINT_URL). Exercises
# `download_bucket_to_dir`'s own contract natively: ranged-GET streaming (incl. an object
# larger than DOWNLOAD_CHUNK, so the multi-range loop runs), whole-bucket key → local path
# mapping, failure collection (never raises), and the compute_download_delta skip on a
# re-pull of unchanged files.
#
# Same credential seam as test_upload_aws.jl: `download_bucket_to_dir` calls
# `assume_lab_operator()` internally, so a temp AWS credentials/config profile pair plus a
# LAB_OPERATOR_ROLE_ARN pointing at a role that needn't exist is seeded.

import AWS

@testset "Download streaming (LocalStack)" begin
    endpoint = ENV["AWS_ENDPOINT_URL"]
    root_cfg = LabAPI.AWSIdent.LabConfig(AWS.AWSCredentials("test", "test"), "us-east-1", endpoint)
    sfx = string(rand(UInt32); base = 16)
    bucket = "vendor-download-$sfx"
    LabAPI.AWSIdent.S3.create_bucket(bucket; aws_config = root_cfg)

    # Seed: a small root object, a nested-prefix object, and one larger than a single range
    # window so _download_one_file loops. Bytes are deterministic per position.
    small = "hello"
    nested = "nested-body"
    big = String(UInt8[UInt8((i * 7) % 251) for i in 1:(LabAPI.Download.DOWNLOAD_CHUNK + 4096)])
    LabAPI.AWSIdent.S3.put_object(bucket, "root.txt", Dict{String,Any}("body" => small); aws_config = root_cfg)
    LabAPI.AWSIdent.S3.put_object(bucket, "sub/dir/n.txt", Dict{String,Any}("body" => nested); aws_config = root_cfg)
    LabAPI.AWSIdent.S3.put_object(bucket, "big.bin", Dict{String,Any}("body" => big); aws_config = root_cfg)

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
            mktempdir() do dest
                cfg = LabAPI.assume_lab_operator()
                s3_manifest = build_s3_manifest(cfg, bucket, "")
                # Whole bucket, nothing local yet → everything is a download.
                to_download = compute_download_delta(s3_manifest, build_local_manifest(dest))
                @test Set(to_download) == Set(["root.txt", "sub/dir/n.txt", "big.bin"])

                downloaded, failed = download_bucket_to_dir(
                    bucket, dest, [(k, s3_manifest[k].size) for k in to_download])
                @test downloaded == 3
                @test failed == 0

                # Bytes + nested layout reproduced verbatim under dest.
                @test read(joinpath(dest, "root.txt"), String) == small
                @test read(joinpath(dest, "sub", "dir", "n.txt"), String) == nested
                @test read(joinpath(dest, "big.bin"), String) == big          # multi-range streamed
                @test filesize(joinpath(dest, "big.bin")) == length(big)

                # Re-pull: nothing changed on disk, so the delta is empty (skip path).
                @test isempty(compute_download_delta(s3_manifest, build_local_manifest(dest)))

                # A manifest entry with no matching object → per-file failure, not a raise.
                ghosted = merge(s3_manifest, Dict("ghost.txt" => (size = 4, last_modified = 0.0)))
                _, gfailed = download_bucket_to_dir(bucket, dest, [("ghost.txt", ghosted["ghost.txt"].size)])
                @test gfailed == 1
            end
        finally
            for (k, v) in saved
                v === nothing ? delete!(ENV, k) : (ENV[k] = v)
            end
        end
    end
end
