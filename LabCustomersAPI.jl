#!/usr/bin/env julia
"""
Lab Customers API (Julia port of LabCustomersAPI.py)

Manage the full lifecycle of lab customers: provision S3 research buckets with scoped IAM
credentials, rotate and revoke access keys, re-apply policy settings, delete customers and
their associated resources, and sync research data from NAS to S3 (plan/apply push with a
single write guard — `--dry-run` is apply minus writes).
"""

include(joinpath(@__DIR__, "src", "LabAPI", "LabAPI.jl"))
using .LabAPI
using SQLite

module CustomersCLI

using Comonicon
using SQLite
using Dates
using ..LabAPI

function list_customers()
    db = init_db()
    # NamedTuple(row), not collect(query) — SQLite.Row is a live proxy over the statement's
    # cursor, so collect()-ing the raw iterator yields rows that all read back "missing" once
    # the cursor advances past them. Materialize each row during iteration instead.
    rows = [NamedTuple(row) for row in SQLite.DBInterface.execute(db, "SELECT * FROM customers ORDER BY customer_name")]
    close(db)
    rows
end

function get_customer(name)
    db = init_db()
    rows = [NamedTuple(row) for row in SQLite.DBInterface.execute(db, "SELECT * FROM customers WHERE customer_name = ?", (name,))]
    close(db)
    isempty(rows) && throw(AppError("Customer '$name' not found"))
    rows[1]
end

"""
    create_customer(name)

Provision a research bucket + scoped IAM user for a new customer and register it. Mirrors
`LabCustomersAPI.py::create_customer`.
"""
function create_customer(name)
    validate_customer_name(name)

    db = init_db()
    dup = [row for row in SQLite.DBInterface.execute(db, "SELECT 1 FROM customers WHERE customer_name = ?", (name,))]
    close(db)
    isempty(dup) || throw(AppError("Customer '$name' already exists"))

    bucket_name = "research-$(lowercase(name))"
    cfg = assume_lab_operator()
    kms_key_arn = resolve_kms_key_arn(cfg)

    configure_bucket(cfg, bucket_name, kms_key_arn)
    create_prefix_structure(cfg, bucket_name, kms_key_arn)

    account_id = LabAPI.AWSIdent.STS.get_caller_identity(; aws_config=cfg)["GetCallerIdentityResult"]["Account"]
    user_arn, access_key_id, secret_key = create_lab_iam_user(cfg, name, bucket_name, account_id)

    now = Dates.now(Dates.UTC)
    db2 = init_db()
    insert_customer(db2, name, user_arn, access_key_id, bucket_name, "$bucket_name/",
        _iso(now), _iso(now + Dates.Day(ROTATION_DAYS)), "active")
    close(db2)

    print_secret(name, access_key_id, secret_key, bucket_name)
end

"""
    rotate_credentials(name)

Mirrors `LabCustomersAPI.py::rotate_credentials`.
"""
function rotate_credentials(name)
    c = get_customer(name)
    rotate_key(customer_spec(), name, c.bucket_name)
end

"""
    delete_customer(name, mfa_code)

Mirrors `LabCustomersAPI.py::delete_customer`.
"""
function delete_customer(name, mfa_code)
    c = get_customer(name)
    mfa_delete(customer_spec(), name, c.bucket_name, mfa_code)
end

# `delete`'s interactive gates (`_require_mfa`/`_confirm_delete`) and the `AppError` exit
# wrapper (`run_cli`) live in `LabAPI.CLI`, shared with the vendor CLI.

# ----------------------------------------------------------------------------------------
# `push` — forward NAS→S3, plan/apply with a single write guard. Ports LabCustomersAPI.py's
# _resolve_researchers/_plan_prefix/_plan_root_readme/_plan_push/push. `--dry-run` runs the
# identical plan (real S3 round-trip + size+mtime delta) and stops at the guard. Logic fn is
# `run_push` to avoid colliding with the `push` @cast command below.
# ----------------------------------------------------------------------------------------

function _resolve_researchers(nas_path, researcher_filter)
    researchers = discover_nas_researchers(nas_path)
    if !isempty(researcher_filter)
        validate_customer_name(researcher_filter)
        researcher_filter in researchers ||
            throw(AppError("Researcher '$researcher_filter' not found on NAS at $nas_path"))
        return [researcher_filter]
    end
    return researchers
end

_manifest_bytes(manifest) = sum(Int[v.size for v in values(manifest)])

"""Read-only sub-plan for one prefix (Data/, Result/, ...) of one researcher. `nothing` when
the prefix dir is absent or empty on NAS. Mirrors `LabCustomersAPI.py::_plan_prefix`."""
function _plan_prefix(bucket_name, root, prefix, needs_provision, s3)
    sub_dir = joinpath(root, rstrip(prefix, '/'))
    isdir(sub_dir) || return nothing

    local_manifest = build_local_manifest(sub_dir)
    isempty(local_manifest) && return nothing

    delta = if needs_provision
        # Bucket does not exist yet — everything would upload once provisioned.
        collect(keys(local_manifest))
    else
        s3_manifest = build_s3_manifest(s3, bucket_name, prefix)
        compute_sync_delta(local_manifest, s3_manifest, prefix)
    end

    return (
        prefix = prefix,
        label = prefix,
        data_dir = sub_dir,
        local_files = length(local_manifest),
        local_bytes = _manifest_bytes(local_manifest),
        delta = delta,
        delta_count = length(delta),
        delta_bytes = sum(Int[local_manifest[rel].size for rel in delta]),
    )
end

"""Read-only sub-plan for the researcher-root README.md → bucket-root `README.md` (empty
prefix). `nothing` when there is no README.md on NAS. Mirrors `_plan_root_readme`."""
function _plan_root_readme(bucket_name, root, needs_provision, s3)
    local_manifest = build_root_readme_local_manifest(root)
    isempty(local_manifest) && return nothing

    delta = if needs_provision
        collect(keys(local_manifest))
    else
        s3_manifest = build_s3_manifest(s3, bucket_name, README_NAME)
        compute_sync_delta(local_manifest, s3_manifest, "")
    end

    return (
        prefix = "",
        label = "README.md (root)",
        data_dir = root,
        local_files = length(local_manifest),
        local_bytes = _manifest_bytes(local_manifest),
        delta = delta,
        delta_count = length(delta),
        delta_bytes = sum(Int[local_manifest[rel].size for rel in delta]),
    )
end

"""Read-only: compute exactly what a push would upload for one researcher. Contacts S3 and
computes the real size+mtime delta for provisioned researchers. Persists nothing. Mirrors
`LabCustomersAPI.py::_plan_push`."""
function _plan_push(name, nas_path, conn)
    bucket_name = "research-$(lowercase(name))"
    needs_provision = isempty([row for row in SQLite.DBInterface.execute(
        conn, "SELECT 1 FROM customers WHERE customer_name = ?", (name,))])

    root = joinpath(nas_path, name)
    s3 = needs_provision ? nothing : assume_lab_operator()

    sub_plans = Any[_plan_prefix(bucket_name, root, prefix, needs_provision, s3) for prefix in PREFIXES]
    push!(sub_plans, _plan_root_readme(bucket_name, root, needs_provision, s3))
    prefixes = [sub for sub in sub_plans if sub !== nothing]

    return (
        bucket_name = bucket_name,
        needs_provision = needs_provision,
        prefixes = prefixes,
        skip_reason = isempty(prefixes) ?
            "no populated prefixes (Data/Result/Archive/Other) or root README.md" : nothing,
        local_files = sum(Int[sub.local_files for sub in prefixes]),
        local_bytes = sum(Int[sub.local_bytes for sub in prefixes]),
        delta_count = sum(Int[sub.delta_count for sub in prefixes]),
        delta_bytes = sum(Int[sub.delta_bytes for sub in prefixes]),
    )
end

function run_push(; dry_run=false, researcher_filter="", nas_path="")
    nas_path = isempty(nas_path) ? config().nas_research_path : nas_path
    researchers = _resolve_researchers(nas_path, researcher_filter)
    if isempty(researchers)
        println("No researchers found on NAS.")
        return
    end

    println("Found $(length(researchers)) researcher(s) on NAS.")
    println()

    conn = init_db()
    provisioned = String[]; synced = String[]; skipped = String[]; errors = Tuple{String,String}[]

    for name in researchers
        println("  $name")
        plan = try
            _plan_push(name, nas_path, conn)
        catch e
            msg = e isa AppError ? e.msg : sprint(showerror, e)
            println("    ERROR planning: $msg")
            push!(errors, (name, msg))
            continue
        end

        if plan.skip_reason !== nothing
            println("    $(plan.skip_reason) — skipped")
            push!(skipped, name)
            continue
        end

        prefixes_summary = join([p.label for p in plan.prefixes], ", ")
        println("    $(plan.local_files) file(s), $(fmt_size(plan.local_bytes)) total across $prefixes_summary")
        plan.needs_provision && println("    not in database — needs provisioning")

        if plan.delta_count == 0
            println("    already synced ($(plan.local_files) files)")
            push!(skipped, name)
            continue
        end

        # Only prefixes with a non-empty delta need uploading.
        to_upload = [p for p in plan.prefixes if p.delta_count > 0]

        # ----- single write guard: everything below this point writes -----
        if dry_run
            verb = plan.needs_provision ? "would provision, then upload" : "would upload"
            for p in to_upload
                println("    [dry-run] $verb $(p.delta_count) file(s) ($(fmt_size(p.delta_bytes))) to $(p.label)")
            end
            push!(synced, name)
            continue
        end

        try
            if plan.needs_provision
                println("    provisioning...")
                create_customer(name)
                push!(provisioned, name)
            end
            total_uploaded, total_failed = 0, 0
            for p in to_upload
                println("    $(p.label) — $(p.delta_count) file(s) ($(fmt_size(p.delta_bytes)))")
                count, fail_count = upload_data_to_s3(
                    plan.bucket_name, p.data_dir, p.delta, name; prefix=p.prefix)
                # `count` is the cumulative size of the shared resume set, so the last
                # prefix's return is the researcher-wide total — assign, don't sum.
                total_uploaded = count
                total_failed += fail_count
            end
            println("    done ($total_uploaded files uploaded)")
            total_failed == 0 && clear_progress(name)
            push!(synced, name)
        catch e
            msg = e isa AppError ? e.msg : sprint(showerror, e)
            println("    ERROR syncing: $msg")
            push!(errors, (name, msg))
        end
    end
    close(conn)

    println()
    println("Summary: $(length(provisioned)) provisioned, $(length(synced)) synced, " *
            "$(length(skipped)) skipped, $(length(errors)) errors")
    for (name, err) in errors
        println("  FAILED: $name — $err")
    end
end

"""
List all lab customers.
"""
@cast function list()
    customers = list_customers()
    if isempty(customers)
        println("No customers found.")
        return
    end
    header = rpad("Name", 20) * " " * rpad("Bucket", 30) * " " * rpad("Key ID", 22) * " " *
             rpad("Rotation Due", 28) * " " * "Status"
    println(header)
    println("-" ^ length(header))
    for c in customers
        println(
            rpad(c.customer_name, 20), " ", rpad(c.bucket_name, 30), " ",
            rpad(c.access_key_id, 22), " ", rpad(c.rotation_due[1:10], 28), " ", c.status,
        )
    end
end

"""
Create a new lab customer with bucket and credentials.

# Args

- `name`: TitleCase FirstnameLastname, e.g. JohnSmith.
"""
@cast function create(name)
    create_customer(name)
    println("Customer '$name' provisioned successfully.")
end

"""
Show details for a lab customer.

# Args

- `name`: the customer's TitleCase name.
"""
@cast function get(name)
    print_record(get_customer(name))
end

"""
Rotate credentials for a lab customer.

# Args

- `name`: the customer's TitleCase name.
"""
@cast function rotate(name)
    rotate_credentials(name)
    println("Credentials rotated for '$name'.")
end

"""
Re-apply bucket hardening and the researcher's IAM policy to an existing customer.

# Args

- `name`: the customer's TitleCase name.
"""
@cast function migrate_policy_settings(name)
    validate_customer_name(name)
    # Guard on the DB registry (a local read) rather than head_bucket — this targets
    # researchers we've provisioned, which is exactly what a customers row means;
    # get_customer raises if there isn't one, so a nonexistent customer rc 1s before any
    # AWS work. Mirrors LabCustomersAPI.py::migrate_policy_settings.
    c = get_customer(name)
    bucket_name = c.bucket_name
    cfg = assume_lab_operator()
    kms_key_arn = resolve_kms_key_arn(cfg)
    configure_bucket(cfg, bucket_name, kms_key_arn)
    put_lab_customer_s3_policy(cfg, "LabCustomer-$name", bucket_name)
    println("Policy settings migrated for '$name' on bucket '$bucket_name'.")
end

"""
Delete a lab customer, their IAM user, and bucket. Requires MFA.

# Args

- `name`: the customer's TitleCase name.

# Options

- `--mfa=<code>`: TOTP code for S3PhiBypassRole assumption.

# Flags

- `--yes`: skip the confirmation prompt (non-interactive use).
"""
@cast function delete(name; mfa::String="", yes::Bool=false)
    mfa = _require_mfa(mfa)
    _confirm_delete(yes; message="This will permanently delete the customer, IAM user, and bucket. Continue? [y/N]: ")
    result = delete_customer(name, mfa)
    println("Deleted customer '$(result.deleted)' and bucket '$(result.bucket)'.")
end

"""
Read-only reconcile of NAS vs DB vs AWS for each researcher.

# Options

- `--researcher=<name>`: reconcile only this researcher (TitleCase name).
- `--nas-path=<path>`: override NAS research path.
"""
@cast function status(; researcher::String="", nas_path::String="")
    render_status(status_report(; researcher_filter=researcher, nas_path=nas_path))
end

"""
Discover researchers on NAS, provision missing ones, and sync every populated prefix to S3.

# Options

- `--researcher=<name>`: push only this researcher (TitleCase name).
- `--nas-path=<path>`: override NAS research path.

# Flags

- `--dry-run`: run the identical plan (real S3 delta) but stop at the write guard.
"""
@cast function push(; dry_run::Bool=false, researcher::String="", nas_path::String="")
    run_push(; dry_run=dry_run, researcher_filter=researcher, nas_path=nas_path)
end

"""
Lab customer provisioning tool.
"""
Comonicon.@main

end # module CustomersCLI

# `run_cli` (LabAPI.CLI) wraps `command_main` so an `AppError` prints Click-style
# "Error: <msg>" instead of a stacktrace dump — see its docstring. Guarded on
# `PROGRAM_FILE == @__FILE__` (Julia's `if __name__ == "__main__"`) so `build_sysimage.jl`'s
# precompile step can `include` this file to warm the CLI dispatch without the run exiting
# the build. The bin wrappers invoke this file as the script, so the guard is true there.
if abspath(PROGRAM_FILE) == @__FILE__
    run_cli(CustomersCLI.command_main)
end
