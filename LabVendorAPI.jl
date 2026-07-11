#!/usr/bin/env julia
"""
Lab Vendor API (Julia port of LabVendorAPI.py)

Manage the lifecycle of lab vendors — the inbound counterpart to LabCustomersAPI.jl.
Provision a `caucell-{vendor}-landing` S3 bucket with a scoped IAM user so a sequencing
vendor can upload raw seq data, pull that data down to the local NAS, rotate credentials,
and remove vendors (MFA-gated).
"""

include(joinpath(@__DIR__, "LabAPI", "LabAPI.jl"))
using .LabAPI
using SQLite

module VendorCLI

using Comonicon
using SQLite
using Dates
using ..LabAPI

function list_vendors()
    db = init_vendors_db()
    # NamedTuple(row), not collect(query) — SQLite.Row is a live proxy over the statement's
    # cursor, so collect()-ing the raw iterator yields rows that all read back "missing" once
    # the cursor advances past them. Materialize each row during iteration instead.
    rows = [NamedTuple(row) for row in SQLite.DBInterface.execute(db, "SELECT * FROM vendors ORDER BY vendor_name")]
    close(db)
    rows
end

function get_vendor(name)
    db = init_vendors_db()
    rows = [NamedTuple(row) for row in SQLite.DBInterface.execute(db, "SELECT * FROM vendors WHERE vendor_name = ?", (name,))]
    close(db)
    isempty(rows) && throw(AppError("Vendor '$name' not found"))
    rows[1]
end

"""
    create_vendor(name)

Provision a `caucell-{name}-landing` bucket + scoped IAM user for a new vendor and register
it. Mirrors `LabVendorAPI.py::create_vendor`.
"""
function create_vendor(name)
    validate_vendor_name(name)

    db = init_vendors_db()
    dup = [row for row in SQLite.DBInterface.execute(db, "SELECT 1 FROM vendors WHERE vendor_name = ?", (name,))]
    close(db)
    isempty(dup) || throw(AppError("Vendor '$name' already exists"))

    bucket_name = "caucell-$name-landing"
    cfg = assume_lab_operator()
    kms_key_arn = resolve_kms_key_arn(cfg)

    configure_bucket(cfg, bucket_name, kms_key_arn; purpose="vendor-landing")
    create_vendor_readme(cfg, bucket_name, kms_key_arn)

    account_id = LabAPI.AWSIdent.STS.get_caller_identity(; aws_config=cfg)["GetCallerIdentityResult"]["Account"]
    user_arn, access_key_id, secret_key = create_vendor_iam_user(cfg, name, bucket_name, account_id)

    now = Dates.now(Dates.UTC)
    db2 = init_vendors_db()
    insert_vendor(db2, name, user_arn, access_key_id, bucket_name,
        _iso(now), _iso(now + Dates.Day(ROTATION_DAYS)), "active")
    close(db2)

    print_secret(name, access_key_id, secret_key, bucket_name; label="Vendor")
end

"""
    rotate_vendor_credentials(name)

Mirrors `LabVendorAPI.py::rotate_vendor_credentials`.
"""
function rotate_vendor_credentials(name)
    v = get_vendor(name)
    rotate_key(vendor_spec(), name, v.bucket_name, username_from_arn(v.iam_user_arn))
end

"""
    migrate_vendor_policy_settings(name)

Re-apply bucket hardening and the vendor's scoped `s3-bucket-access` IAM policy to an existing
vendor, so policy changes (e.g. new `s3:DeleteObject` grant) reach vendors provisioned before
the change. Mirrors `LabCustomersAPI.jl::migrate_policy_settings`.
"""
function migrate_vendor_policy_settings(name)
    validate_vendor_name(name)
    # Guard on the DB registry (a local read) via get_vendor, which rc 1s for an unknown
    # vendor before any AWS work — same pattern as the customer migrate.
    v = get_vendor(name)
    bucket_name = v.bucket_name
    cfg = assume_lab_operator()
    kms_key_arn = resolve_kms_key_arn(cfg)
    configure_bucket(cfg, bucket_name, kms_key_arn; purpose="vendor-landing")
    put_vendor_s3_policy(cfg, username_from_arn(v.iam_user_arn), bucket_name)
    return bucket_name
end

"""
    migrate_all_vendor_policy_settings()

Run `migrate_vendor_policy_settings` across every registered vendor. Continue-and-report:
a failure on one vendor is caught and recorded, the sweep proceeds, and an `AppError` is
raised at the end if any failed (so the CLI exits non-zero). Every step is idempotent, so
re-running after a partial failure is safe.
"""
function migrate_all_vendor_policy_settings()
    vendors = list_vendors()
    isempty(vendors) && (println("No vendors found."); return)
    failures = String[]
    for v in vendors
        name = v.vendor_name
        try
            bucket_name = migrate_vendor_policy_settings(name)
            println("  ✓ ", rpad(name, 20), " ($bucket_name)")
        catch e
            msg = e isa AppError ? e.msg : sprint(showerror, e)
            push!(failures, name)
            println("  ✗ ", rpad(name, 20), " — $msg")
        end
    end
    n = length(vendors)
    println("\nMigrated $(n - length(failures))/$n vendors.")
    isempty(failures) || throw(AppError("Policy migration failed for: $(join(failures, ", "))"))
    return nothing
end

"""
    run_pull(vendor; dry_run=false, overwrite=false)

Mirror a vendor's landing bucket down to `<NAS_VENDORS_PATH>/<vendor>/`. Incremental by
default (download objects missing locally, size-changed, or newer in S3 — via
`compute_download_delta`); never deletes. With `overwrite`, also removes local files absent
from the bucket (`compute_local_orphans`) for an exact mirror. `dry_run` reports the planned
downloads and deletions without writing. The operator-facing inverse of the customer
`run_push`.
"""
function run_pull(vendor; dry_run=false, overwrite=false)
    v = get_vendor(vendor)  # raises if the vendor is unknown
    bucket_name = v.bucket_name
    base = config().nas_vendors_path
    # Guard on the mounted volume root, not the vendors dir (which pull may create): if the NAS
    # isn't mounted, mkpath would silently write to the boot disk. Mirrors Sync.jl's mount check.
    isdir(dirname(base)) || throw(AppError(
        "Vendors volume '$(dirname(base))' is not accessible. Is the NAS mounted?"))
    local_dir = joinpath(base, vendor)

    println("Pulling '$bucket_name' → $local_dir")
    cfg = assume_lab_operator()
    s3_manifest = build_s3_manifest(cfg, bucket_name, "")
    local_manifest = build_local_manifest(local_dir)
    to_download = compute_download_delta(s3_manifest, local_manifest)
    orphans = overwrite ? compute_local_orphans(s3_manifest, local_manifest) : String[]

    dl_bytes = sum(Int[s3_manifest[k].size for k in to_download]; init=0)

    # ----- single write guard: everything below the dry-run branch writes -----
    if dry_run
        println("    [dry-run] would download $(length(to_download)) file(s) ($(fmt_size(dl_bytes)))")
        for k in sort(to_download)
            println("      $k")
        end
        if overwrite && !isempty(orphans)
            println("    [dry-run] would remove $(length(orphans)) local file(s) not in bucket:")
            for k in sort(orphans)
                println("      $k")
            end
        end
        return (downloaded=0, failed=0, removed=0, skipped=length(s3_manifest) - length(to_download))
    end

    mkpath(local_dir)
    downloaded, failed = download_bucket_to_dir(
        bucket_name, local_dir, [(k, s3_manifest[k].size) for k in to_download])

    removed = 0
    if overwrite && !isempty(orphans)
        for k in orphans
            try
                rm(joinpath(local_dir, k))
                removed += 1
            catch e
                println("    FAILED to remove $(k): $(sprint(showerror, e))")
            end
        end
        println("    removed $removed local file(s) not in bucket")
    end

    skipped = length(s3_manifest) - length(to_download)
    return (downloaded=downloaded, failed=failed, removed=removed, skipped=skipped)
end

"""
    delete_vendor(name, mfa_code)

Mirrors `LabVendorAPI.py::delete_vendor`.
"""
function delete_vendor(name, mfa_code)
    v = get_vendor(name)
    mfa_delete(vendor_spec(), name, v.bucket_name, mfa_code, username_from_arn(v.iam_user_arn))
end

# `delete`'s interactive gates (`_require_mfa`/`_confirm_delete`) and the `AppError` exit
# wrapper (`run_cli`) live in `LabAPI.CLI`, shared with the customer CLI.

"""
List all lab vendors.
"""
@cast function list()
    vendors = list_vendors()
    if isempty(vendors)
        println("No vendors found.")
        return
    end
    header = rpad("Vendor", 20) * " " * rpad("Bucket", 32) * " " * rpad("Key ID", 22) * " " *
             rpad("Rotation Due", 14) * " " * "Status"
    println(header)
    println("-" ^ length(header))
    for v in vendors
        println(
            rpad(v.vendor_name, 20), " ", rpad(v.bucket_name, 32), " ",
            rpad(v.access_key_id, 22), " ", rpad(v.rotation_due[1:10], 14), " ", v.status,
        )
    end
end

"""
Create a new lab vendor with landing bucket and credentials.

# Args

- `name`: lowercase slug, e.g. genewiz, illumina-cloud.
"""
@cast function create(name)
    create_vendor(name)
    println("Vendor '$name' provisioned successfully.")
end

"""
Show details for a lab vendor.

# Args

- `name`: the vendor's slug name.
"""
@cast function get(name)
    print_record(get_vendor(name))
end

"""
Rotate credentials for a lab vendor.

# Args

- `name`: the vendor's slug name.
"""
@cast function rotate(name)
    rotate_vendor_credentials(name)
    println("Credentials rotated for '$name'.")
end

"""
Re-apply bucket hardening and the vendor's IAM policy to existing vendors.

Pass a vendor name to migrate one, or `--all` to sweep every registered vendor. Every step is
idempotent, so re-running (including after a partial `--all` failure) is safe.

# Args

- `name`: the vendor's slug name (omit when using `--all`).

# Flags

- `--all`: migrate every registered vendor; reports a per-vendor ✓/✗ summary and exits
  non-zero if any failed.
"""
@cast function migrate_policy_settings(name=""; all::Bool=false)
    if all
        isempty(name) || throw(AppError("Pass either a vendor name or --all, not both."))
        migrate_all_vendor_policy_settings()
    else
        isempty(name) && throw(AppError("Provide a vendor name, or pass --all to migrate every vendor."))
        bucket_name = migrate_vendor_policy_settings(name)
        println("Policy settings migrated for '$name' on bucket '$bucket_name'.")
    end
end

"""
Pull a vendor's landing bucket down to the local NAS vendor directory.

Mirrors everything from the root of `caucell-<vendor>-landing` into
`<NAS_VENDORS_PATH>/<vendor>/`. Incremental by default (only new, size-changed, or
S3-newer objects are downloaded; existing local files are left in place).

# Args

- `vendor`: the vendor's slug name.

# Flags

- `--dry-run`: show what would be downloaded/removed without writing anything.
- `--overwrite`: also delete local files that no longer exist in the bucket (exact mirror).
"""
@cast function pull(vendor; dry_run::Bool=false, overwrite::Bool=false)
    r = run_pull(vendor; dry_run=dry_run, overwrite=overwrite)
    dry_run && return
    println("Summary: $(r.downloaded) downloaded, $(r.skipped) up-to-date, " *
            "$(r.removed) removed, $(r.failed) failed")
end

"""
Delete a lab vendor, their IAM user, landing bucket, and orders. Requires MFA.

# Args

- `name`: the vendor's slug name.

# Options

- `--mfa=<code>`: TOTP code for the MFA-gated LabOperatorRole bypass-delete assumption.

# Flags

- `--yes`: skip the confirmation prompt (non-interactive use).
"""
@cast function delete(name; mfa::String="", yes::Bool=false)
    mfa = _require_mfa(mfa)
    _confirm_delete(yes; message="This will permanently delete the vendor, IAM user, bucket, and orders. Continue? [y/N]: ")
    result = delete_vendor(name, mfa)
    println("Deleted vendor '$(result.deleted)' and bucket '$(result.bucket)'.")
end

"""
Lab vendor landing-bucket provisioning tool.
"""
Comonicon.@main

end # module VendorCLI

# `run_cli` (LabAPI.CLI) converts an AppError into Click-style "Error: <msg>" output instead
# of a stacktrace dump — see LabCustomersAPI.jl / its docstring. Guarded on
# `PROGRAM_FILE == @__FILE__` (Julia's `if __name__ == "__main__"`) so `build_sysimage.jl`'s
# precompile step can `include` this file to warm the CLI dispatch without the run exiting
# the build. The bin wrappers invoke this file as the script, so the guard is true there.
if abspath(PROGRAM_FILE) == @__FILE__
    run_cli(VendorCLI.command_main)
end
