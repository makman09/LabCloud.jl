#!/usr/bin/env julia
"""
Lab Vendor API (Julia port of LabVendorAPI.py)

Manage the lifecycle of lab vendors — the inbound counterpart to LabCustomersAPI.jl.
Provision a `caucell-{vendor}-landing` S3 bucket with a scoped IAM user so a sequencing
vendor can upload raw seq data, mint per-order `{uuid}/` prefixes, rotate credentials, and
remove vendors (MFA-gated).
"""

include(joinpath(@__DIR__, "LabAPI", "LabAPI.jl"))
using .LabAPI
using SQLite

module VendorCLI

using Comonicon
using SQLite
using Dates
using UUIDs
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

function list_orders_for(vendor)
    get_vendor(vendor)  # raises if the vendor is unknown
    db = init_vendors_db()
    rows = [NamedTuple(row) for row in SQLite.DBInterface.execute(
        db, "SELECT * FROM vendor_orders WHERE vendor_name = ? ORDER BY created", (vendor,))]
    close(db)
    rows
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
    rotate_key(vendor_spec(), name, v.bucket_name)
end

"""
    create_order(vendor; notes=missing)

Mint a `{uuid4}/` prefix under the vendor's landing bucket + a `vendor_orders` row. Mirrors
`LabVendorAPI.py::create_order`.
"""
function create_order(vendor; notes=missing)
    v = get_vendor(vendor)  # raises if the vendor is unknown
    bucket_name = v.bucket_name
    order_id = string(uuid4())
    s3_prefix = "$order_id/"

    cfg = assume_lab_operator()
    kms_key_arn = resolve_kms_key_arn(cfg)
    create_order_prefix(cfg, bucket_name, order_id, kms_key_arn)

    now = Dates.now(Dates.UTC)
    db = init_vendors_db()
    insert_vendor_order(db, order_id, vendor, s3_prefix, _iso(now), "open", notes)
    close(db)
    return (order_id=order_id, bucket=bucket_name, prefix=s3_prefix)
end

"""
    delete_vendor(name, mfa_code)

Mirrors `LabVendorAPI.py::delete_vendor`.
"""
function delete_vendor(name, mfa_code)
    v = get_vendor(name)
    mfa_delete(vendor_spec(), name, v.bucket_name, mfa_code)
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
Mint a new order: a {uuid}/ prefix under the vendor's landing bucket.

# Args

- `vendor`: the vendor's slug name.

# Options

- `--notes=<text>`: optional free-text notes for this order.
"""
@cast function new_order(vendor; notes::String="")
    result = create_order(vendor; notes = isempty(notes) ? missing : notes)
    println("Order '$(result.order_id)' created at $(result.bucket)/$(result.prefix)")
end

"""
List all orders for a lab vendor.

# Args

- `vendor`: the vendor's slug name.
"""
@cast function list_orders(vendor)
    orders = list_orders_for(vendor)
    if isempty(orders)
        println("No orders found for '$vendor'.")
        return
    end
    header = rpad("Order ID", 38) * " " * rpad("Created", 22) * " " * rpad("Status", 10) * " " * "Notes"
    println(header)
    println("-" ^ length(header))
    for o in orders
        println(
            rpad(o.order_id, 38), " ", rpad(o.created[1:19], 22), " ",
            rpad(o.status, 10), " ", coalesce(o.notes, ""),
        )
    end
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
