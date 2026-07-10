"""
    Upload

Julia port of `src/upload.py` — the WRITE half of the sync engine: batched, concurrent,
resumable direct-to-S3 uploads via the lab-operator session (no `aws` CLI involved).

## Design notes vs Python

- Python uses `boto3 upload_file` + `TransferConfig` (64 MiB multipart threshold/chunk,
  4-way part concurrency) on a `ThreadPoolExecutor(SYNC_WORKERS)`. AWS.jl has no managed
  transfer layer and its request body is a fully-materialized `String`/`Vector{UInt8}` (no
  streaming), so both tiers are hand-rolled here with the same shape: files ≤ threshold go
  up as one `put_object`; larger files go through CreateMultipartUpload → per-chunk
  UploadPart → CompleteMultipartUpload. Memory is bounded by chunk-size × in-flight tasks.
- File-level concurrency is `asyncmap(...; ntasks=SYNC_WORKERS)`: uploads are network-bound
  and HTTP.jl yields to the task scheduler on socket I/O, so overlapping happens without
  requiring the CLI to be launched with `--threads`. (Shared state below is still guarded
  by a lock so a future move to `Threads.@spawn` doesn't introduce races.)
- Part ETags for CompleteMultipartUpload come from `ListParts` (XML body) rather than the
  UploadPart response headers — AWS.jl only exposes response headers through a deprecated
  code path.
- Python's 0.5 s background progress-printer thread is deliberately omitted (cosmetic,
  timing-dependent `\\r` output the contract suite never asserts on); the per-file
  "uploaded ..." lines and batch/summary lines are kept.
- Resume/flush semantics are identical: the shared `uploaded` set is keyed by FULL S3 key
  (prefix collisions), flushed via `Sync.save_progress` every 10 successes and once at the
  end; per-file failures are collected, never raised. Returns
  `(total_in_resume_set, failed_count)` exactly like Python.
"""
module Upload

using ..AWSIdent: AWSIdent, assume_lab_operator
using ..Config: MULTIPART_CHUNKSIZE, MULTIPART_CONCURRENCY, MULTIPART_THRESHOLD,
                UPLOAD_BATCH_SIZE, config
using ..Sync: load_progress, save_progress
using ..Util: as_vector, fmt_size
using AWS.AWSServices: s3 as s3_raw

const S3 = AWSIdent.S3

export upload_data_to_s3, delete_orphan_objects

"""
    _upload_multipart(cfg, bucket_name, local_file, s3_key)

Hand-rolled multipart upload: 64 MiB chunks, at most `MULTIPART_CONCURRENCY` parts in
flight (mirroring Python's `TransferConfig(max_concurrency=4)` memory footprint). Each part
task opens/seeks/reads its own chunk. On any part failure the upload is aborted (so no
orphaned parts linger beyond the bucket's abort-incomplete-multipart lifecycle rule) and
the error is rethrown for the caller's per-file failure handling.
"""
function _upload_multipart(cfg, bucket_name, local_file, s3_key)
    total = filesize(local_file)
    nparts = cld(total, MULTIPART_CHUNKSIZE)
    upload_id = S3.create_multipart_upload(bucket_name, s3_key; aws_config=cfg)["UploadId"]

    try
        asyncmap(1:nparts; ntasks=MULTIPART_CONCURRENCY) do part_number
            offset = (part_number - 1) * MULTIPART_CHUNKSIZE
            len = min(MULTIPART_CHUNKSIZE, total - offset)
            chunk = open(local_file, "r") do io
                seek(io, offset)
                read(io, len)
            end
            S3.upload_part(
                bucket_name, s3_key, part_number, upload_id,
                Dict{String,Any}("body" => chunk);
                aws_config=cfg,
            )
        end

        # Collect part ETags via ListParts (paginated at 1000 parts/page) and complete.
        parts = Tuple{Int,String}[]
        marker = ""
        while true
            params = Dict{String,Any}("uploadId" => upload_id)
            isempty(marker) || (params["part-number-marker"] = marker)
            resp = s3_raw("GET", "/$(bucket_name)/$(s3_key)", params; aws_config=cfg)
            if haskey(resp, "Part")
                for p in as_vector(resp["Part"])
                    push!(parts, (parse(Int, string(p["PartNumber"])), String(p["ETag"])))
                end
            end
            get(resp, "IsTruncated", "false") == "true" || break
            marker = string(get(resp, "NextPartNumberMarker", ""))
            isempty(marker) && break
        end
        sort!(parts; by=first)

        parts_xml = join(
            ("<Part><ETag>$(etag)</ETag><PartNumber>$(n)</PartNumber></Part>" for (n, etag) in parts)
        )
        body = """<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">$(parts_xml)</CompleteMultipartUpload>"""
        S3.complete_multipart_upload(
            bucket_name, s3_key, upload_id, Dict{String,Any}("body" => body); aws_config=cfg
        )
    catch
        try
            S3.abort_multipart_upload(bucket_name, s3_key, upload_id; aws_config=cfg)
        catch
        end
        rethrow()
    end
    return nothing
end

"""
    _upload_one_file(cfg, bucket_name, base, rel_path, prefix) -> (rel_path, size_mb)

Single-file upload: one `put_object` under the multipart threshold, hand-rolled multipart
above it. No SSE headers — the bucket's default SSE-KMS encryption applies, exactly as with
Python's `upload_file`.
"""
function _upload_one_file(cfg, bucket_name, base, rel_path, prefix)
    local_file = joinpath(base, rel_path)
    s3_key = "$(prefix)$(rel_path)"
    size_bytes = filesize(local_file)
    if size_bytes > MULTIPART_THRESHOLD
        _upload_multipart(cfg, bucket_name, local_file, s3_key)
    else
        S3.put_object(
            bucket_name, s3_key,
            Dict{String,Any}("body" => read(local_file));
            aws_config=cfg,
        )
    end
    return rel_path, size_bytes / (1024 * 1024)
end

"""
    upload_data_to_s3(bucket_name, data_dir, files_to_upload, researcher_name; prefix="Data/")
        -> (uploaded_total, failed_count)

Mirrors `src/upload.py::upload_data_to_s3`: loads the resume set, filters already-uploaded
keys, uploads the remainder in `UPLOAD_BATCH_SIZE` batches with `SYNC_WORKERS`-way
concurrency, flushes progress every 10 successes, collects (never raises) per-file
failures. `uploaded_total` is the cumulative size of the shared resume set — the caller
(`push`) assigns, not sums, across prefixes, and decides whether to `clear_progress`.
"""
function upload_data_to_s3(bucket_name, data_dir, files_to_upload, researcher_name; prefix="Data/")
    workers = config().sync_workers
    already_uploaded = load_progress(researcher_name)

    remaining = [f for f in files_to_upload if !("$(prefix)$(f)" in already_uploaded)]
    total_upload_bytes = sum(Int[filesize(joinpath(data_dir, rel)) for rel in remaining])
    if !isempty(already_uploaded)
        println("    resuming — $(length(already_uploaded)) already uploaded, " *
                "$(length(remaining)) remaining ($(fmt_size(total_upload_bytes)))")
    end
    isempty(remaining) && return length(already_uploaded), 0

    println("    starting upload of $(length(remaining)) file(s) over $(workers) threads...")
    cfg = assume_lab_operator()

    uploaded = 0
    failed = String[]
    pending_flush = 0
    total_remaining = length(remaining)
    bytes_done = 0
    state_lock = ReentrantLock()

    for batch_start in 1:UPLOAD_BATCH_SIZE:total_remaining
        batch = remaining[batch_start:min(batch_start + UPLOAD_BATCH_SIZE - 1, total_remaining)]
        println("    batch $(cld(batch_start, UPLOAD_BATCH_SIZE)) — " *
                "files $(batch_start)-$(batch_start + length(batch) - 1) of $(total_remaining)")
        asyncmap(batch; ntasks=workers) do rel
            try
                _, size_mb = _upload_one_file(cfg, bucket_name, data_dir, rel, prefix)
                @lock state_lock begin
                    push!(already_uploaded, "$(prefix)$(rel)")
                    uploaded += 1
                    pending_flush += 1
                    bytes_done += filesize(joinpath(data_dir, rel))
                    if pending_flush >= 10
                        save_progress(researcher_name, already_uploaded)
                        pending_flush = 0
                    end
                end
                println("    uploaded $(rel) ($(round(size_mb; digits=1)) MB) " *
                        "[$(uploaded)/$(total_remaining), $(fmt_size(bytes_done))/$(fmt_size(total_upload_bytes))]")
            catch e
                @lock state_lock push!(failed, rel)
                println("    FAILED $(rel): $(sprint(showerror, e))")
            end
        end
    end

    if pending_flush > 0
        save_progress(researcher_name, already_uploaded)
    end

    if !isempty(failed)
        println("    $(length(failed)) file(s) failed to upload")
    end
    return length(already_uploaded), length(failed)
end

"""
    delete_orphan_objects(bucket_name, orphan_keys) -> (deleted, failed)

The mirror direction of `upload_data_to_s3`: remove S3 keys that no longer exist on NAS
(computed by `Sync.compute_bucket_orphans`). A plain `S3.delete_object` on a versioned
bucket writes a delete marker — this hides the current object without purging version
history (a true erase would need the MFA/governance-bypass path in `Lifecycle`). Runs on the
routine `assume_lab_operator()` session (`s3:DeleteObject` on `research-*/*` needs no MFA).
Collects per-object failures and never raises, mirroring the upload half.
"""
function delete_orphan_objects(bucket_name, orphan_keys)
    isempty(orphan_keys) && return 0, 0
    cfg = assume_lab_operator()
    deleted = 0
    failed = 0
    for key in orphan_keys
        try
            S3.delete_object(bucket_name, key; aws_config=cfg)
            deleted += 1
            println("    removed $(key)")
        catch e
            failed += 1
            println("    FAILED to remove $(key): $(sprint(showerror, e))")
        end
    end
    return deleted, failed
end

end # module Upload
