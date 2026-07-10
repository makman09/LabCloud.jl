"""
    Sync

Julia port of `src/sync.py` — the READ-ONLY half of the sync engine: manifest builders
(`build_local_manifest`, `build_root_readme_local_manifest`, `build_s3_manifest`), the pure
`compute_sync_delta`, NAS discovery, and the resumable-upload progress-file store.

Manifest shapes mirror Python's:
- local:  `rel_path => (size, mtime)` — `mtime` is a Float64 Unix timestamp (`Base.mtime`).
- S3:     `key => (size, last_modified)` — `last_modified` parsed from the ListObjectsV2
  `LastModified` ISO8601 string into epoch seconds, so it compares directly against `mtime`.

Progress files (`SYNC_PROGRESS_DIR/{researcher}.json`, shape `{"uploaded": [keys]}`) are
FORMAT-compatible with Python's `src/sync.py` — either implementation can resume the
other's partial push: same key name, same sorted array-of-full-S3-key shape, same
`.tmp`-sibling + atomic-rename write, same legacy bare-list tolerance on read.
"""
module Sync

using Dates: datetime2unix
using JSON3

using ..Config: EXCLUDED_NAS_DIRS, PREFIXES, config
using ..Util: AppError, NAME_PATTERN, as_vector, _parse_iso8601
using ..AWSIdent: AWSIdent

const S3 = AWSIdent.S3

export README_NAME, discover_nas_researchers, build_local_manifest,
       build_root_readme_local_manifest, build_s3_manifest, compute_sync_delta,
       progress_path, load_progress, save_progress, clear_progress,
       build_researcher_keyset, list_bucket_current_keys, compute_bucket_orphans

# The researcher-root README.md syncs to the bucket-root `README.md` key (no prefix).
const README_NAME = "README.md"

const LocalEntry = NamedTuple{(:size, :mtime),Tuple{Int,Float64}}
const S3Entry = NamedTuple{(:size, :last_modified),Tuple{Int,Float64}}

"""
    discover_nas_researchers(nas_path) -> Vector{String}

Sorted TitleCase researcher dirs under `nas_path`, skipping dotfiles and `EXCLUDED_NAS_DIRS`.
Raises `AppError` (the `click.ClickException` analog) if the path isn't a mounted directory.
Mirrors `src/sync.py::discover_nas_researchers`.
"""
function discover_nas_researchers(nas_path)
    isdir(nas_path) || throw(AppError("NAS path '$nas_path' is not accessible. Is the volume mounted?"))
    researchers = String[]
    for name in sort(readdir(nas_path))
        startswith(name, ".") && continue
        isdir(joinpath(nas_path, name)) || continue
        name in EXCLUDED_NAS_DIRS && continue
        match(NAME_PATTERN, name) === nothing && continue
        push!(researchers, name)
    end
    return researchers
end

"""
    build_local_manifest(data_dir) -> Dict{String,LocalEntry}

Recursive `rel_path => (size, mtime)` manifest for `data_dir`, skipping files whose own
name starts with `.` (matches Python's `rglob("*")` + `name.startswith(".")` skip). Mirrors
`src/sync.py::build_local_manifest`.
"""
function build_local_manifest(data_dir)
    manifest = Dict{String,LocalEntry}()
    isdir(data_dir) || return manifest
    for (root, _dirs, files) in walkdir(data_dir)
        for f in files
            startswith(f, ".") && continue
            full = joinpath(root, f)
            isfile(full) || continue
            manifest[relpath(full, data_dir)] = (size=filesize(full), mtime=mtime(full))
        end
    end
    return manifest
end

"""
    build_root_readme_local_manifest(researcher_root) -> Dict{String,LocalEntry}

Single-entry manifest for the researcher-root `README.md`, or empty if absent. Deliberately
not a recursive scan — only the top-level README is a sync candidate. Mirrors
`src/sync.py::build_root_readme_local_manifest`.
"""
function build_root_readme_local_manifest(researcher_root)
    p = joinpath(researcher_root, README_NAME)
    isfile(p) || return Dict{String,LocalEntry}()
    return Dict{String,LocalEntry}(README_NAME => (size=filesize(p), mtime=mtime(p)))
end

"""
    _parse_last_modified(s) -> Float64

ListObjectsV2 `LastModified` ("2026-07-06T18:00:00.000Z") → epoch seconds, directly
comparable against `Base.mtime`'s Float64 (Python compares `st_mtime` against
`LastModified.timestamp()` the same way). Tolerates a `Z`/`+00:00` suffix and any
fractional-second precision (`Dates.DateTime` parses at most milliseconds).
"""
_parse_last_modified(s) = datetime2unix(_parse_iso8601(s))

"""
    build_s3_manifest(cfg, bucket_name, s3_prefix="Data/") -> Dict{String,S3Entry}

Paginates `s3:ListObjectsV2` under `s3_prefix` into a `key => (size, last_modified)`
manifest, skipping "directory" placeholder keys (ending `/`). Mirrors
`src/sync.py::build_s3_manifest`.
"""
function build_s3_manifest(cfg, bucket_name, s3_prefix="Data/")
    manifest = Dict{String,S3Entry}()
    token = ""
    while true
        params = Dict{String,Any}("prefix" => s3_prefix)
        isempty(token) || (params["continuation-token"] = token)
        page = S3.list_objects_v2(bucket_name, params; aws_config=cfg)
        if haskey(page, "Contents")
            for obj in as_vector(page["Contents"])
                key = obj["Key"]
                endswith(key, "/") && continue
                manifest[key] = (
                    size=parse(Int, string(obj["Size"])),
                    last_modified=_parse_last_modified(obj["LastModified"]),
                )
            end
        end
        get(page, "IsTruncated", "false") == "true" || break
        token = get(page, "NextContinuationToken", "")
        isempty(token) && break
    end
    return manifest
end

"""
    compute_sync_delta(local_manifest, s3_manifest, s3_prefix="Data/") -> Vector{String}

aws-s3-sync-style delta: upload if missing, size differs, or the local file is newer than
the S3 object. A same-size file edited without a newer mtime won't be caught — the same
trade-off `aws s3 sync` itself accepts. Pure function of the two manifests (no AWS calls,
no local I/O). Mirrors `src/sync.py::compute_sync_delta`.
"""
function compute_sync_delta(local_manifest, s3_manifest, s3_prefix="Data/")
    to_upload = String[]
    for (rel_path, local_info) in local_manifest
        s3_key = "$(s3_prefix)$(rel_path)"
        s3_info = get(s3_manifest, s3_key, nothing)
        # `||` short-circuits before `.last_modified` when the object is missing/size-differs,
        # so this is identical to the original if/elseif (both pushed the same value).
        if s3_info === nothing || s3_info.size != local_info.size || local_info.mtime > s3_info.last_modified
            push!(to_upload, rel_path)
        end
    end
    return to_upload
end

# ---------------------------------------------------------------------------------------
# Bucket-side drift — the mirror direction `compute_sync_delta` deliberately ignores. These
# power the plain-push drift warning and the `push --overwrite` orphan removal: whole-bucket
# listing minus the keys NAS would legitimately produce.
# ---------------------------------------------------------------------------------------

"""
    build_researcher_keyset(researcher_root) -> Set{String}

Every S3 object key a push would legitimately produce for one researcher: each managed
prefix's local files (as `"\$prefix\$rel"`) plus the root `README.md` when present on NAS.
This is `Status.jl`'s `local_keys` set-difference operand lifted to cover the whole
researcher — the reference set `compute_bucket_orphans` subtracts the live listing against.
"""
function build_researcher_keyset(researcher_root)
    keyset = Set{String}()
    for prefix in PREFIXES
        sub_dir = joinpath(researcher_root, rstrip(prefix, '/'))
        for rel in keys(build_local_manifest(sub_dir))
            push!(keyset, "$(prefix)$(rel)")
        end
    end
    isempty(build_root_readme_local_manifest(researcher_root)) || push!(keyset, README_NAME)
    return keyset
end

"""
    list_bucket_current_keys(cfg, bucket_name) -> Vector{String}

Every current-version object key in the whole bucket (empty prefix), with "directory"
placeholder keys (ending `/`) already dropped — reuses `build_s3_manifest`'s pagination and
placeholder-skip under an empty prefix. The current-view counterpart used for drift detection.
"""
list_bucket_current_keys(cfg, bucket_name) = collect(keys(build_s3_manifest(cfg, bucket_name, "")))

"""
    compute_bucket_orphans(cfg, bucket_name, researcher_root) -> Vector{String}

Bucket-side drift: current S3 keys with no corresponding NAS file. The provisioned root
`README.md` placeholder is always treated as managed state (never an orphan), matching the
`Status.jl:88` guard, so neither the drift warning nor `--overwrite` disturbs it.
"""
function compute_bucket_orphans(cfg, bucket_name, researcher_root)
    keyset = build_researcher_keyset(researcher_root)
    return [k for k in list_bucket_current_keys(cfg, bucket_name)
            if k != README_NAME && !(k in keyset)]
end

# ---------------------------------------------------------------------------------------
# Resumable-upload progress store — the sync engine's ONE persistence store (ephemeral
# in-flight state; `status` must never touch it).
# ---------------------------------------------------------------------------------------

progress_path(researcher_name) = joinpath(config().sync_progress_dir, "$researcher_name.json")

"""
    load_progress(researcher_name) -> Set{String}

The set of already-uploaded full S3 keys from a previous partial push (empty if no file,
corrupt JSON, or unexpected shape). Tolerates the legacy bare-list format the same way
Python does. Mirrors `src/sync.py::load_progress` (which returns `{"uploaded": set}` —
here the bare `Set` since Julia callers only ever read that one field).
"""
function load_progress(researcher_name)
    path = progress_path(researcher_name)
    isfile(path) || return Set{String}()
    data = try
        JSON3.read(read(path, String))
    catch
        return Set{String}()
    end
    if data isa AbstractVector
        return Set{String}(String.(data))
    elseif data isa AbstractDict && haskey(data, "uploaded") && data["uploaded"] isa AbstractVector
        return Set{String}(String.(data["uploaded"]))
    end
    return Set{String}()
end

"""
    save_progress(researcher_name, uploaded::Set{String})

Writes `{"uploaded": sorted(uploaded)}` to a `.tmp` sibling then atomically renames over
the real path — the identical shape and write discipline as Python's `save_progress`, so a
Julia-written file resumes under Python and vice versa.
"""
function save_progress(researcher_name, uploaded)
    mkpath(config().sync_progress_dir)
    dest = progress_path(researcher_name)
    tmp = joinpath(config().sync_progress_dir, "$researcher_name.tmp")
    open(tmp, "w") do io
        JSON3.write(io, Dict("uploaded" => sort(collect(uploaded))))
    end
    mv(tmp, dest; force=true)
    return nothing
end

"""
    clear_progress(researcher_name)

Removes the progress file (no-op if absent). Mirrors `src/sync.py::clear_progress`.
"""
function clear_progress(researcher_name)
    path = progress_path(researcher_name)
    isfile(path) && rm(path)
    return nothing
end

end # module Sync
