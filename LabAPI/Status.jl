"""
    Status

Julia port of `src/status.py` — read-only NAS<->DB<->AWS reconcile (`status_report`,
`render_status`). Never provisions, uploads, mutates the DB, or touches sync-progress
files. Both probes (bucket via `head_bucket`, IAM via `list_access_keys`) go through the
single `assume_lab_operator()` session. Drift is the same size+mtime `compute_sync_delta`
that `push` uses, so the NAS-ahead count matches exactly what a push would upload.
"""
module Status

using SQLite

using ..Config: config, PARTICIPANTS_SUBPATH, PARTICIPANTS_PREFIX
using ..DB: init_db
using ..Util: AppError, fmt_size, validate_customer_name, username_from_arn
using ..AWSIdent: AWSIdent, assume_lab_operator, _error_code
using ..Sync: Sync, README_NAME, discover_nas_researchers, discover_nas_participants,
              build_local_manifest, build_root_readme_local_manifest, build_s3_manifest,
              compute_sync_delta

const IAM = AWSIdent.IAM
const S3 = AWSIdent.S3

export status_report, render_status

# Per-researcher bucket roles. Each researcher has a single `research-{name}` bucket. A
# customer-facing delivery bucket is deliberately decoupled and not probed (see CLAUDE.md).
const BUCKET_ROLES = ("research",)

# role => (nas_ahead_label, s3_ahead_label, prefixes_to_scan). "" is the bucket root, scanned
# for README.md only (see reconcile_bucket).
const RECONCILE = Dict(
    "research" => ("archive push needed", "drift — investigate",
                   ("", "Data/", "Result/", "Archive/", "Other/")),
)

"""True if the bucket exists, false on 404/NoSuchBucket. Re-raises other errors."""
function probe_bucket_exists(s3, bucket_name)
    try
        S3.head_bucket(bucket_name; aws_config=s3)
        return true
    catch e
        (_error_code(e) in ("404", "NoSuchBucket", "NotFound") ||
         occursin("404", sprint(showerror, e)) || occursin("NoSuchBucket", sprint(showerror, e))) && return false
        rethrow()
    end
end

"""
True if the IAM user `username` exists. Uses `list_access_keys` (already granted to the
provisioner) rather than `get_user`, so no extra `iam:GetUser` grant is needed. The caller
resolves `username` from the registry ARN (legacy `LabCustomer-{name}` or new bare `{name}`).
"""
function probe_iam_user_exists(iam_prov, username)
    try
        IAM.list_access_keys(Dict("UserName" => username); aws_config=iam_prov)
        return true
    catch e
        occursin("NoSuchEntity", sprint(showerror, e)) && return false
        rethrow()
    end
end

"""Reconcile one bucket against NAS across the role's prefix set (read-only). In `participants`
mode the researcher-layout prefix set is replaced by a single unit: the participant's whole root
→ the `Data/` prefix (no per-prefix subdirs, no root README), so drift stays scoped to `Data/`."""
function reconcile_bucket(s3_phi, bucket_name, role, name, nas_root; participants=false)
    nas_ahead_label, s3_ahead_label, prefixes = RECONCILE[role]
    researcher_root = joinpath(nas_root, name)

    # Each unit is (prefix, local_dir, is_root). Researcher layout: root README + one per managed
    # prefix (`root/<Prefix>`). Participant layout: the single Data/ unit rooted at the whole dir.
    units = participants ?
        [(prefix=PARTICIPANTS_PREFIX, local_dir=researcher_root, is_root=false)] :
        [(prefix=p, local_dir=(p == "" ? researcher_root : joinpath(researcher_root, rstrip(p, '/'))),
          is_root=(p == "")) for p in prefixes]

    results = Any[]
    for u in units
        if u.is_root
            # Root: reconcile only README.md (researcher-root → bucket-root `README.md`).
            local_manifest = build_root_readme_local_manifest(researcher_root)
            s3_manifest = build_s3_manifest(s3_phi, bucket_name, README_NAME)
        else
            local_manifest = isdir(u.local_dir) ? build_local_manifest(u.local_dir) :
                             Dict{String,Sync.LocalEntry}()
            s3_manifest = build_s3_manifest(s3_phi, bucket_name, u.prefix)
        end

        # size+mtime delta — same rule `push` uses, so this count matches exactly what
        # a push would actually upload (missing, size differs, or locally newer).
        to_upload = compute_sync_delta(local_manifest, s3_manifest, u.prefix)

        local_keys = Set("$(u.prefix)$rel" for rel in keys(local_manifest))
        # At the root the provisioned README.md placeholder is managed state, not drift, so an
        # S3-only README is expected — don't report it as an orphan.
        orphans = u.is_root ? String[] : [k for k in keys(s3_manifest) if !(k in local_keys)]

        push!(results, (
            prefix = u.is_root ? README_NAME : u.prefix,
            local_files = length(local_manifest),
            s3_files = length(s3_manifest),
            local_bytes = sum(Int[v.size for v in values(local_manifest)]),
            nas_ahead = length(to_upload),
            orphans = length(orphans),
            nas_ahead_label = nas_ahead_label,
            s3_ahead_label = s3_ahead_label,
        ))
    end
    return results
end

"""Per-researcher block: IAM user + each per-researcher bucket's existence/reconcile. `arn`
is the registry `iam_user_arn` (or "" for NAS-only names with no DB row)."""
function reconcile_researcher(name, in_db, arn, nas_root, iam_prov, s3_phi; participants=false)
    buckets = Dict{String,Any}()
    for role in BUCKET_ROLES
        bucket_name = "$role-$(lowercase(name))"
        if !probe_bucket_exists(s3_phi, bucket_name)
            buckets[role] = (bucket=bucket_name, exists=false, prefixes=nothing)
        else
            buckets[role] = (bucket=bucket_name, exists=true,
                             prefixes=reconcile_bucket(s3_phi, bucket_name, role, name, nas_root;
                                                       participants=participants))
        end
    end
    # A name with no DB row hasn't been provisioned, so it has no IAM user to probe. Skip the
    # probe rather than guess a bare username: the operator policy scopes iam:ListAccessKeys to
    # the provisioned IAM path, so probing an off-path guessed username returns AccessDenied
    # (not NoSuchEntity) and would abort the whole reconcile — this is the common case in
    # `--participants` mode, where freshly-discovered participants are all un-provisioned.
    iam_username = isempty(arn) ? name : username_from_arn(arn)
    iam_user = isempty(arn) ? false : probe_iam_user_exists(iam_prov, iam_username)
    return (
        name = name,
        in_db = in_db,
        nas_present = isdir(joinpath(nas_root, name)),
        iam_username = iam_username,
        iam_user = iam_user,
        buckets = buckets,
    )
end

"""
    status_report(; researcher_filter="", nas_path="") -> NamedTuple

Reconcile NAS vs DB vs AWS for each researcher. Pure read-only. Empty `researcher_filter`
means whole-volume; empty `nas_path` falls back to `config().nas_research_path`. With
`participants=true`, discovery and reconcile target `<nas_path>/Caucell/Data` (each participant's
whole root vs the `Data/` bucket prefix) instead of top-level researchers. Mirrors
`src/status.py::status_report`.
"""
function status_report(; researcher_filter="", nas_path="", participants=false)
    nas_path = isempty(nas_path) ? config().nas_research_path : nas_path
    # `base` is where the discovered names live; participants are one level deeper. Passed as
    # `nas_root` to reconcile_researcher so `joinpath(base, name)` resolves correctly in both modes.
    base = participants ? joinpath(nas_path, PARTICIPANTS_SUBPATH) : nas_path

    conn = init_db()
    db_arns = Dict(row.customer_name => row.iam_user_arn for row in
                   SQLite.DBInterface.execute(conn, "SELECT customer_name, iam_user_arn FROM customers"))
    close(conn)
    db_names = Set(keys(db_arns))

    if !isempty(researcher_filter)
        validate_customer_name(researcher_filter)
        targets = [researcher_filter]
        on_nas = isdir(joinpath(base, researcher_filter))
        on_nas_not_in_db = (on_nas && !(researcher_filter in db_names)) ? [researcher_filter] : String[]
        in_db_not_on_nas = (researcher_filter in db_names && !on_nas) ? [researcher_filter] : String[]
    else
        nas_researchers = participants ? discover_nas_participants(nas_path) : discover_nas_researchers(nas_path)
        targets = nas_researchers
        nas_set = Set(nas_researchers)
        on_nas_not_in_db = sort(collect(setdiff(nas_set, db_names)))
        in_db_not_on_nas = sort(collect(setdiff(db_names, nas_set)))
    end

    researchers = Any[]
    if !isempty(targets)
        # One LabOperatorRole session serves both probes (Python: one session, two client
        # handles) — the `iam_prov`/`s3_phi` parameter names survive for line-by-line
        # mirroring of src/status.py.
        operator = assume_lab_operator()
        for name in targets
            push!(researchers, reconcile_researcher(name, name in db_names,
                                                    get(db_arns, name, ""), base, operator, operator;
                                                    participants=participants))
        end
    end

    return (
        nas_path = base,
        on_nas_not_in_db = on_nas_not_in_db,
        in_db_not_on_nas = in_db_not_on_nas,
        researchers = researchers,
    )
end

"""
    render_status(report)

Render a `status_report` NamedTuple to stdout. Line shapes mirror `src/status.py::render_status`
(a bare `click.echo()` is a blank line; column pads via `rpad`; em-dash label `drift — investigate`).
"""
function render_status(report)
    println("NAS: $(report.nas_path)")
    println()

    if !isempty(report.on_nas_not_in_db)
        println("On NAS, not in DB (needs provisioning): $(join(report.on_nas_not_in_db, ", "))")
    end
    if !isempty(report.in_db_not_on_nas)
        println("In DB, not on NAS (orphaned row / NAS unmounted): $(join(report.in_db_not_on_nas, ", "))")
    end
    if !isempty(report.on_nas_not_in_db) || !isempty(report.in_db_not_on_nas)
        println()
    end

    total_nas_ahead = 0
    total_orphans = 0
    needs_prov = 0

    for r in report.researchers
        r.in_db || (needs_prov += 1)
        db_tag = r.in_db ? "db: present" : "db: MISSING — needs provisioning"
        println("$(r.name)   [$db_tag]")
        if !r.nas_present
            println("  ⚠ researcher directory not found on NAS — orphan counts reflect S3-only inventory")
        end

        for role in BUCKET_ROLES
            b = r.buckets[role]
            if !b.exists
                println("  $(rpad(b.bucket, 34)) not provisioned")
                continue
            end
            println("  $(rpad(b.bucket, 34)) exists")
            for p in b.prefixes
                total_nas_ahead += p.nas_ahead
                total_orphans += p.orphans
                line = "      $(rpad(p.prefix, 10)) $(p.local_files) files, " *
                       "$(p.nas_ahead) push, $(p.orphans) orphans ($(fmt_size(p.local_bytes)))"
                if p.nas_ahead > 0 && !isempty(p.nas_ahead_label)
                    line *= "  [$(p.nas_ahead_label)]"
                end
                if p.orphans > 0 && !isempty(p.s3_ahead_label)
                    line *= "  [$(p.s3_ahead_label)]"
                end
                println(line)
            end
        end

        println("  iam $(rpad(r.iam_username, 34)) $(r.iam_user ? "present" : "MISSING")")
        println()
    end

    println("Summary: $(length(report.researchers)) researcher(s) | $needs_prov needs provisioning | " *
            "$total_nas_ahead NAS-ahead | $total_orphans orphans")
end

end # module Status
