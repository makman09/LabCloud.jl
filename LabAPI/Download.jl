"""
    Download

The READ half of the sync engine — the S3→local mirror direction that powers the vendor
`pull`. No `aws` CLI: objects are pulled directly through the lab-operator session.

## Design notes

- AWS.jl has no managed transfer layer and materializes a response body fully in memory, so
  large objects are streamed to disk by hand via ranged GETs (`Range: bytes=s-e`) in
  `DOWNLOAD_CHUNK` windows — memory is bounded by chunk-size × in-flight tasks regardless of
  object size. This mirrors why `Upload.jl` hand-rolls multipart on the write side.
- SSE-KMS decryption is transparent on GET (the vendor bucket's default key applies), so no
  decryption headers are needed — the reverse of provisioning writes, which set `_sse_headers`.
- File-level concurrency is `asyncmap(...; ntasks=SYNC_WORKERS)`, the same network-bound
  overlap pattern as `upload_data_to_s3`. Shared counters are lock-guarded so a future move to
  `Threads.@spawn` doesn't introduce races. Per-file failures are collected, never raised —
  the caller reports them. Returns `(downloaded_count, failed_count)`.
- The per-object byte size comes from the caller's S3 manifest (`build_s3_manifest`), which
  drives the range loop; there is no separate HEAD.
"""
module Download

using ..AWSIdent: AWSIdent, assume_lab_operator
using ..Config: config
using ..Util: fmt_size

const S3 = AWSIdent.S3

# 8 MiB ranged-GET window. Bounds per-task memory for multi-GB seq files.
const DOWNLOAD_CHUNK = 8 * 1024 * 1024

export download_bucket_to_dir

"""
    _download_one_file(cfg, bucket_name, key, dest_path, size_bytes) -> (key, size_bytes)

Stream one object to `dest_path`, creating parent dirs. Loops ranged GETs
(`Range: bytes=offset-last`) in `DOWNLOAD_CHUNK` windows, appending each chunk, so memory
stays bounded no matter how large the object is. A zero-byte object just creates the empty
file (no GET). No SSE headers — decryption is transparent on GET.
"""
function _download_one_file(cfg, bucket_name, key, dest_path, size_bytes)
    mkpath(dirname(dest_path))
    open(dest_path, "w") do io
        offset = 0
        while offset < size_bytes
            last = min(offset + DOWNLOAD_CHUNK - 1, size_bytes - 1)
            body = S3.get_object(bucket_name, key,
                Dict{String,Any}("headers" => Dict("Range" => "bytes=$offset-$last")); aws_config=cfg)
            write(io, body)
            offset = last + 1
        end
    end
    return key, size_bytes
end

"""
    download_bucket_to_dir(bucket_name, local_dir, keys_with_sizes; workers=config().sync_workers)
        -> (downloaded_count, failed_count)

Download each `(key, size_bytes)` in `keys_with_sizes` to `joinpath(local_dir, key)` with
`workers`-way concurrency (the download inverse of `upload_data_to_s3`). Keys are whole-bucket
paths, so the bucket layout is reproduced verbatim under `local_dir`. Per-file failures are
collected and reported, never raised.
"""
function download_bucket_to_dir(bucket_name, local_dir, keys_with_sizes; workers=config().sync_workers)
    isempty(keys_with_sizes) && return 0, 0
    total = length(keys_with_sizes)
    total_bytes = sum(Int[sz for (_, sz) in keys_with_sizes])
    println("    starting download of $(total) file(s) ($(fmt_size(total_bytes))) over $(workers) threads...")
    cfg = assume_lab_operator()

    downloaded = 0
    failed = String[]
    bytes_done = 0
    state_lock = ReentrantLock()

    asyncmap(keys_with_sizes; ntasks=workers) do (key, size_bytes)
        dest = joinpath(local_dir, key)
        try
            _download_one_file(cfg, bucket_name, key, dest, size_bytes)
            @lock state_lock begin
                downloaded += 1
                bytes_done += size_bytes
            end
            println("    downloaded $(key) ($(fmt_size(size_bytes))) " *
                    "[$(downloaded)/$(total), $(fmt_size(bytes_done))/$(fmt_size(total_bytes))]")
        catch e
            @lock state_lock push!(failed, key)
            println("    FAILED $(key): $(sprint(showerror, e))")
        end
    end

    if !isempty(failed)
        println("    $(length(failed)) file(s) failed to download")
    end
    return downloaded, length(failed)
end

end # module Download
