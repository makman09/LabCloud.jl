"""
    Config

Mirrors `src/config.py`: environment-derived settings for the Lab Customers/Vendors CLIs.

Python reads `os.environ` once at import time (after `load_dotenv()`), which works there
because each CLI invocation is a fresh process. Julia's twist is the sysimage: `lab.so` is
built once and reused across invocations, so anything computed at precompile/`__init__` time
would freeze the FIRST subprocess's environment into every later run. Instead, `config()`
re-reads `ENV` on every call — the cost (a few dict lookups) is negligible next to an AWS call.

Like Python's `load_dotenv()`, the project-root `.env` (`LabCloud.jl/.env`, alongside the
CLI entrypoints and `.env.example`) is loaded on the first `config()` call of the process —
filling in ONLY variables absent from the environment (python-dotenv's `override=False`
semantics). That detail is load-bearing: the contract harness sets every config variable
explicitly in the subprocess env, and `.env` must never clobber those.
"""
module Config

using ..Util: AppError

export AppConfig, config, PREFIXES, ROTATION_DAYS, EXCLUDED_NAS_DIRS,
       PARTICIPANTS_SUBPATH, PARTICIPANTS_PREFIX,
       UPLOAD_BATCH_SIZE, MULTIPART_THRESHOLD, MULTIPART_CHUNKSIZE, MULTIPART_CONCURRENCY

# Non-env constants — same values for every process, safe as real `const`s.
const PREFIXES = ["Archive/", "Data/", "Other/", "Result/"]
const ROTATION_DAYS = 90
const EXCLUDED_NAS_DIRS = Set(["Caucell"])

# `--participants` mode: participants live one level deeper than researchers, under the fixed
# `Research/Caucell/Data` subpath, and each participant's whole root maps to the single `Data/`
# bucket prefix (not the four-prefix researcher layout). `Caucell` is in EXCLUDED_NAS_DIRS above,
# so these dirs stay invisible to normal researcher discovery.
const PARTICIPANTS_SUBPATH = joinpath("Caucell", "Data")
const PARTICIPANTS_PREFIX = "Data/"
const UPLOAD_BATCH_SIZE = 50

# Mirror of Python's TRANSFER_CONFIG (boto3 TransferConfig): files above the threshold go
# through hand-rolled multipart upload in Upload.jl; parts are chunksize bytes with at most
# `concurrency` parts in flight per file.
const MULTIPART_THRESHOLD = 64 * 1024 * 1024
const MULTIPART_CHUNKSIZE = 64 * 1024 * 1024
const MULTIPART_CONCURRENCY = 4

"""
    AppConfig

Snapshot of env-derived settings, read fresh on each `config()` call (see module docstring
for why this isn't frozen at load time).
"""
struct AppConfig
    role_arn::String
    region::String
    profile::String
    kms_alias::String
    lab_group::String
    vendor_group::String
    db_path::String
    multipart_abort_days::Int
    nas_research_path::String
    sync_progress_dir::String
    sync_workers::Int
end

const _dotenv_loaded = Ref(false)

# Project root (LabCloud.jl/) is a fixed one level up from this file's directory
# (LabAPI/ → LabCloud.jl/) — the `.env` / `.env.example` live there.
const _DOTENV_PATH = joinpath(dirname(@__DIR__), ".env")

"""
    _load_dotenv()

Once per process: read the project-root `.env` (`_DOTENV_PATH`, i.e. `LabCloud.jl/.env`) and
set each `KEY=VALUE` line into `ENV` — ONLY for keys not already present (`override=False`
semantics). Skips blank lines and `#` comments, tolerates an `export ` prefix and surrounding
quotes. No-op when the file doesn't exist.
"""
function _load_dotenv()
    _dotenv_loaded[] && return nothing
    _dotenv_loaded[] = true
    isfile(_DOTENV_PATH) || return nothing
    for line in eachline(_DOTENV_PATH)
        line = strip(line)
        (isempty(line) || startswith(line, "#")) && continue
        startswith(line, "export ") && (line = strip(line[8:end]))
        eq = findfirst('=', line)
        eq === nothing && continue
        key = strip(line[1:eq-1])
        value = strip(line[eq+1:end])
        if length(value) >= 2 && value[1] == value[end] && value[1] in ('"', '\'')
            value = value[2:end-1]
        end
        isempty(key) && continue
        haskey(ENV, key) || (ENV[key] = value)
    end
    return nothing
end

"""
    config() -> AppConfig

Read the current environment into an `AppConfig` (after backfilling from `.env` — see
`_load_dotenv`). Mirrors `src/config.py` line for line, including the hard requirement:
`LAB_OPERATOR_ROLE_ARN` must be set (env or `.env`) or this raises.

There is a single AWS CLI profile (`AWS_PROFILE`, default `caucellcloud-lab-operator`) for
everything: `LabOperatorRole` was consolidated (formerly `S3PhiBypassRole` was a separate
role; see terraform's `iam.tf`), and the MFA-gated bypass-delete path now re-assumes that same
`role_arn` from this SAME `lab-operator` identity — via a different trust statement
(`BypassDeleteRequiresMfa`) and a fresh MFA factor from lab-operator's own virtual MFA device
— rather than a separate human admin profile.
"""
function config()
    _load_dotenv()
    haskey(ENV, "LAB_OPERATOR_ROLE_ARN") || throw(AppError(
        "LAB_OPERATOR_ROLE_ARN is not set — export it or add it to LabCloud.jl/.env"))
    role_arn = ENV["LAB_OPERATOR_ROLE_ARN"]
    AppConfig(
        role_arn,
        get(ENV, "AWS_REGION", "us-east-1"),
        get(ENV, "AWS_PROFILE", "caucellcloud-lab-operator"),
        get(ENV, "PHI_KMS_KEY_ALIAS", "alias/phi-research-key"),
        get(ENV, "LAB_CUSTOMERS_GROUP", "LabCustomers"),
        get(ENV, "LAB_VENDORS_GROUP", "LabVendors"),
        get(ENV, "DB_PATH", "lab_customers.db"),
        parse(Int, get(ENV, "MULTIPART_ABORT_DAYS", "7")),
        get(ENV, "NAS_RESEARCH_PATH", "/Volumes/CaucellVolumeI/Research"),
        get(ENV, "SYNC_PROGRESS_DIR", joinpath(homedir(), ".caucell", "sync_progress")),
        parse(Int, get(ENV, "SYNC_WORKERS", "10")),
    )
end

end # module Config
