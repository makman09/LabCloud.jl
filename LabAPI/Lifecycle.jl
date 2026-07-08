"""
    Lifecycle

The shared IAM-user + registry-row lifecycle (`EntitySpec`, `rotate_key`, `mfa_delete`)
used by both the customer and vendor CLIs. Python inlined these bodies into
`LabCustomersAPI.py`/`LabVendorAPI.py` when it deleted `src/lifecycle.py`; the Julia port
deliberately keeps the parameterized form — the rotate/delete mechanics are still
near-identical between customers and vendors (username prefix, group, table/column names,
and the vendor's `vendor_orders` child purge are the only deltas), and the contract suite
asserts external behavior, not module structure.
"""
module Lifecycle

using Dates
using SQLite
using ..Config: config, ROTATION_DAYS
using ..DB: init_db, init_vendors_db
using ..AWSIdent: AWSIdent, _error_code
using ..Util: AppError, as_vector, ignore_not_found, print_secret

const IAM = AWSIdent.IAM
const S3 = AWSIdent.S3

export EntitySpec, customer_spec, vendor_spec, rotate_key, mfa_delete, _iso

"""
    EntitySpec

Parameterizes the shared rotate/delete mechanics over what differs between the customer and
vendor CLIs: the IAM username prefix, the IAM group to remove from on delete, the registry
table + name column, and (for vendors) extra child tables to purge first (FK order). Mirrors
`src/lifecycle.py::EntitySpec`.
"""
struct EntitySpec
    kind::String            # human label, e.g. "Customer" / "Vendor"
    user_prefix::String      # IAM username prefix, e.g. "LabCustomer-" / "LabVendor-"
    group::String            # IAM group to remove from on delete
    table::String            # registry table, e.g. "customers" / "vendors"
    name_col::String         # name column, e.g. "customer_name" / "vendor_name"
    init_db::Function        # returns an open SQLite.DB for this entity's DB
    child_tables::Tuple      # extra tables to purge on delete (FK children)
end

EntitySpec(kind, user_prefix, group, table, name_col, init_db) =
    EntitySpec(kind, user_prefix, group, table, name_col, init_db, ())

"""
    customer_spec() -> EntitySpec

Built fresh on every call, NOT a top-level `const` — `config()` re-reads `ENV` per call (see
`Config`'s module docstring on why: a `const` baked at `include()`/precompile time would
freeze whichever `LAB_CUSTOMERS_GROUP` happened to be set at sysimage-build time into every
later invocation, and would also make plain offline commands like `list`/`get` needlessly
require `LAB_OPERATOR_ROLE_ARN` just to load the module).
"""
customer_spec() = EntitySpec("Customer", "LabCustomer-", config().lab_group, "customers", "customer_name", init_db)

"""
    vendor_spec() -> EntitySpec

Vendor counterpart of `customer_spec()`. Built fresh per call for the same `config()`/`ENV`
reason. `vendor_orders` is a FK child of `vendors`, so it's purged first on delete. Mirrors
`LabVendorAPI.py::VENDOR_SPEC`.
"""
vendor_spec() = EntitySpec("Vendor", "LabVendor-", config().vendor_group, "vendors", "vendor_name",
                           init_vendors_db, ("vendor_orders",))

_iso_now() = Dates.format(Dates.now(Dates.UTC), dateformat"yyyy-mm-ddTHH:MM:SS.sss") * "+00:00"
_iso(dt) = Dates.format(dt, dateformat"yyyy-mm-ddTHH:MM:SS.sss") * "+00:00"

"""
    _access_key_metadata(list_access_keys_resp) -> Vector

Normalizes `iam:ListAccessKeys`' `AccessKeyMetadata` (XML-list-shaped: absent "member" key
means zero keys, a bare `Dict` means one, a `Vector` means two-plus — see `Util.as_vector`).
"""
function _access_key_metadata(resp)
    elem = resp["ListAccessKeysResult"]["AccessKeyMetadata"]
    return haskey(elem, "member") ? as_vector(elem["member"]) : []
end

"""Delete every existing access key for `username` (rotate and delete both start by wiping
the current key set). `cfg` is the operator session in both callers."""
function _delete_existing_keys(username, cfg)
    for key in _access_key_metadata(IAM.list_access_keys(Dict("UserName" => username); aws_config=cfg))
        IAM.delete_access_key(key["AccessKeyId"], Dict("UserName" => username); aws_config=cfg)
    end
end

"""
    rotate_key(spec, name, bucket_name) -> String

Deletes the entity's existing access key(s), mints a fresh one, and updates its registry row
(`access_key_id`, `key_created`, `rotation_due`). Returns the new access key ID. Uses the
lab-operator role. Mirrors the (now inlined) `rotate_credentials`/`rotate_vendor_credentials`
bodies in the Python CLIs.
"""
function rotate_key(spec::EntitySpec, name, bucket_name)
    username = "$(spec.user_prefix)$name"
    cfg = AWSIdent.assume_lab_operator()

    _delete_existing_keys(username, cfg)

    new_key = IAM.create_access_key(Dict("UserName" => username); aws_config=cfg)["CreateAccessKeyResult"]["AccessKey"]
    now = Dates.now(Dates.UTC)

    db = spec.init_db()
    SQLite.execute(db,
        "UPDATE $(spec.table) SET access_key_id = ?, key_created = ?, rotation_due = ? WHERE $(spec.name_col) = ?",
        (new_key["AccessKeyId"], _iso(now), _iso(now + Dates.Day(ROTATION_DAYS)), name))
    close(db)

    print_secret(name, new_key["AccessKeyId"], new_key["SecretAccessKey"], bucket_name; label=spec.kind)
    return new_key["AccessKeyId"]
end

function _purge_rows(spec::EntitySpec, name)
    db = spec.init_db()
    for table in spec.child_tables  # children first, then the parent row (FK order)
        SQLite.execute(db, "DELETE FROM $table WHERE $(spec.name_col) = ?", (name,))
    end
    SQLite.execute(db, "DELETE FROM $(spec.table) WHERE $(spec.name_col) = ?", (name,))
    close(db)
end

"""
    _delete_object_versions(bucket_name, bypass_cfg)

Paginates `s3:ListObjectVersions` and bypass-deletes every version and delete marker
(`x-amz-bypass-governance-retention`). AWS.jl's XML wire names for the list elements are
`Version`/`DeleteMarker` (singular — NOT boto3's `Versions`/`DeleteMarkers`).
"""
function _delete_object_versions(bucket_name, bypass_cfg)
    key_marker, version_id_marker = "", ""
    while true
        params = Dict{String,Any}()
        isempty(key_marker) || (params["key-marker"] = key_marker)
        isempty(version_id_marker) || (params["version-id-marker"] = version_id_marker)
        page = isempty(params) ? S3.list_object_versions(bucket_name; aws_config=bypass_cfg) :
                                  S3.list_object_versions(bucket_name, params; aws_config=bypass_cfg)

        versions = haskey(page, "Version") ? as_vector(page["Version"]) : []
        markers = haskey(page, "DeleteMarker") ? as_vector(page["DeleteMarker"]) : []
        for v in vcat(versions, markers)
            S3.delete_object(bucket_name, v["Key"],
                Dict("versionId" => v["VersionId"],
                     "headers" => Dict("x-amz-bypass-governance-retention" => "true"));
                aws_config=bypass_cfg)
        end

        get(page, "IsTruncated", "false") == "true" || break
        key_marker = get(page, "NextKeyMarker", "")
        version_id_marker = get(page, "NextVersionIdMarker", "")
    end
end

"""
    mfa_delete(spec, name, bucket_name, mfa_code) -> (deleted, bucket)

MFA-gated teardown: delete the IAM user, empty the versioned bucket under governance bypass,
delete the bucket, and purge the registry row(s). Idempotent against partially-gone state (a
missing IAM user or bucket is logged and skipped). IAM/bucket teardown runs as the lab
operator; ONLY the version wipe uses the MFA-gated bypass role. Mirrors the (now inlined)
`delete_customer`/`delete_vendor` bodies in the Python CLIs.
"""
function mfa_delete(spec::EntitySpec, name, bucket_name, mfa_code)
    username = "$(spec.user_prefix)$name"

    bypass = AWSIdent.assume_bypass_role(mfa_code)
    println("  MFA verified")

    operator = AWSIdent.assume_lab_operator()

    try
        _delete_existing_keys(username, operator)
        ignore_not_found(() -> IAM.delete_user_policy("s3-bucket-access", username; aws_config=operator))
        ignore_not_found(() -> IAM.remove_user_from_group(spec.group, username; aws_config=operator))
        IAM.delete_user(username; aws_config=operator)
        println("  Deleted IAM user '$username'")
    catch e
        _error_code(e) == "NoSuchEntity" || rethrow()
        println("  IAM user '$username' already gone, skipping")
    end

    try
        S3.head_bucket(bucket_name; aws_config=operator)
    catch e
        _error_code(e) in ("404", "NoSuchBucket") || rethrow()
        println("  Bucket '$bucket_name' already gone, skipping")
        _purge_rows(spec, name)
        return (deleted=name, bucket=bucket_name)
    end

    _delete_object_versions(bucket_name, bypass)

    try
        S3.delete_bucket_policy(bucket_name; aws_config=operator)
    catch
    end
    S3.delete_bucket(bucket_name; aws_config=operator)
    println("  Deleted bucket '$bucket_name'")

    _purge_rows(spec, name)
    return (deleted=name, bucket=bucket_name)
end

end # module Lifecycle
