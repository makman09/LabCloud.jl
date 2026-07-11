"""
Julia @testset unit suite — the native re-authoring of the 5 Python white-box files
(`tests/test_util.py`, `test_db.py`, `test_vendor_db.py`, `test_sync.py`, `test_provision.py`).
A unit test of a Julia function is Julia code; the shared, language-neutral behavioral coverage
lives in `tests_contract/` and runs against both CLIs.

Run:
    julia --project=LabCloud.jl --sysimage LabCloud.jl/lab.so LabCloud.jl/test/runtests.jl

The LocalStack-backed provision/S3 tests only run when `AWS_ENDPOINT_URL` is set (point it at
the contract-harness instance, :4576); otherwise they're skipped. Offline tests always run.
"""

using Test

# config() requires LAB_OPERATOR_ROLE_ARN; DB_PATH is overridden per-test by withdb().
get!(ENV, "LAB_OPERATOR_ROLE_ARN", "arn:aws:iam::000000000000:role/x")

include(joinpath(@__DIR__, "..", "LabAPI", "LabAPI.jl"))
using .LabAPI
using SQLite
using JSON3

# --- shared helpers ---------------------------------------------------------------------

"""True if `f()` throws (any exception). CHECK-constraint / UNIQUE violations surface as a
SQLite error; we assert *that* it fails, not the concrete exception type."""
threw(f) = try (f(); false) catch; true end

"""Run `f` with `DB_PATH` pointed at a fresh temp file, restoring/cleaning up after — the
analog of the Python autouse fixture that isolates `DB_PATH` into `tmp_path` per test."""
function withdb(f)
    path = tempname()
    old = get(ENV, "DB_PATH", nothing)
    ENV["DB_PATH"] = path
    try
        f()
    finally
        old === nothing ? delete!(ENV, "DB_PATH") : (ENV["DB_PATH"] = old)
        isfile(path) && rm(path; force=true)
    end
end

"""Run `f` with `SYNC_PROGRESS_DIR` pointed at a fresh temp dir — the analog of the Python
autouse fixture that isolates progress files into `tmp_path` per test."""
function withprogress(f)
    mktempdir() do d
        old = get(ENV, "SYNC_PROGRESS_DIR", nothing)
        ENV["SYNC_PROGRESS_DIR"] = d
        try
            f(d)
        finally
            old === nothing ? delete!(ENV, "SYNC_PROGRESS_DIR") : (ENV["SYNC_PROGRESS_DIR"] = old)
        end
    end
end

@testset "LabAPI unit suite" begin
    include("test_util.jl")
    include("test_db.jl")
    include("test_vendor_db.jl")
    include("test_sync_local.jl")
    if haskey(ENV, "AWS_ENDPOINT_URL")
        include("test_provision_aws.jl")
        include("test_upload_aws.jl")
        include("test_download_aws.jl")
    else
        @info "AWS_ENDPOINT_URL not set — skipping LocalStack-backed provision/S3/upload tests"
    end
end
