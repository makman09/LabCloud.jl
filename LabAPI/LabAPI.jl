"""
    LabAPI

Julia port of the `research_buckets` Python CLIs (`LabCustomersAPI.py` / `LabVendorAPI.py`).
Submodule load order matters: later modules depend on earlier ones (`DB` on `Config`, etc).
"""
module LabAPI

# Util first: it has no internal deps, and Config needs its AppError for the friendly
# missing-required-variable message.
include("Util.jl")
using .Util

# CLI: Julia-only shared substrate for the two CLI entrypoints (needs only Util.AppError).
include("CLI.jl")
using .CLI

include("Config.jl")
using .Config

include("DB.jl")
using .DB

include("AWSIdent.jl")
using .AWSIdent

include("Provision.jl")
using .Provision

include("Lifecycle.jl")
using .Lifecycle

include("Sync.jl")
using .Sync

include("Upload.jl")
using .Upload

include("Status.jl")
using .Status

export AppConfig, config, PREFIXES, ROTATION_DAYS, EXCLUDED_NAS_DIRS, UPLOAD_BATCH_SIZE
export init_db, init_vendors_db, insert_customer, insert_vendor, insert_vendor_order
export AppError, NAME_PATTERN, VENDOR_NAME_PATTERN,
       validate_customer_name, validate_vendor_name,
       print_secret, fmt_size, ignore_not_found, as_vector, username_from_arn
export LabConfig, assume_lab_operator, assume_bypass_role, resolve_kms_key_arn
export configure_bucket, create_prefix_structure, put_lab_customer_s3_policy,
       create_lab_iam_user, create_vendor_readme, create_order_prefix, create_vendor_iam_user
export EntitySpec, customer_spec, vendor_spec, rotate_key, mfa_delete, _iso
export _prompt_line, _abort, _require_mfa, _confirm_delete, print_record, run_cli
export README_NAME, discover_nas_researchers, build_local_manifest,
       build_root_readme_local_manifest, build_s3_manifest, compute_sync_delta,
       progress_path, load_progress, save_progress, clear_progress,
       build_researcher_keyset, list_bucket_current_keys, compute_bucket_orphans
export upload_data_to_s3, delete_orphan_objects
export status_report, render_status

end # module LabAPI
