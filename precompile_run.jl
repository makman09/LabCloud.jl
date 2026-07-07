"""
Precompile execution script for `build_sysimage.jl`.

PackageCompiler traces whatever this script *runs* and bakes those specializations into
`lab.so`. A thin `using`-only warmup leaves the expensive path cold: Comonicon's argument
parser and command dispatch don't compile until the first real CLI invocation — which is the
"slow first run" the sysimage is supposed to kill. So here we `include` the actual
entrypoints and drive their offline-safe commands (`list`, `get`, `list-orders`) end to end,
plus the shared Util/DB helpers those commands lean on.

Only offline commands run: `create`/`rotate`/`delete`/`push`/`status`/`new-order` all reach
AWS or the NAS and can't execute during a build, so they stay JIT. `LabAPI` itself is
`include`-d source (not a baked package), so its own glue always JITs a little at runtime —
the durable win here is the *package* internals (Comonicon parse+dispatch, SQLite row
iteration, JSON3) getting specialized to how the CLIs actually use them.

Env + DB are pointed at throwaway values so the trace never touches real AWS or the real
`lab_customers.db`.
"""

using AWS
using SQLite
using Comonicon
using JSON3
using Dates

# config() hard-requires LAB_OPERATOR_ROLE_ARN and reads DB_PATH. Point both at throwaway
# values (get! only fills LAB_OPERATOR_ROLE_ARN if unset) so init_db()/list/get run against a
# temp SQLite file, never the real registry — and no AWS role is ever assumed by these paths.
get!(ENV, "LAB_OPERATOR_ROLE_ARN", "arn:aws:iam::000000000000:role/precompile-noop")
ENV["DB_PATH"] = joinpath(mktempdir(), "precompile.db")

# Include the real entrypoints. Their bottom-of-file `run_cli(...)` is guarded on
# `abspath(PROGRAM_FILE) == @__FILE__`, so including them here defines the CustomersCLI /
# VendorCLI modules WITHOUT executing (and exiting) the build. `using .LabAPI` (run inside
# each script, in Main) brings the exported helpers into scope here too.
# NOTE: kept at top level — `include`ing a file that defines a `module` fails inside a function.
include(joinpath(@__DIR__, "LabCustomersAPI.jl"))
include(joinpath(@__DIR__, "LabVendorAPI.jl"))

# Seed one valid row per table so `list`/`get`/`list-orders` exercise the row-materialization
# and formatting paths, not just the empty-result branch. Values satisfy the DDL CHECKs
# (see DB.jl). Helpers are qualified through `LabAPI` because including both entrypoints
# defines the module twice, which makes the re-exported names ambiguous unqualified in Main.
# Wrapped so a constraint hiccup can't abort the build.
try
    let db = LabAPI.init_db()
        LabAPI.insert_customer(db, "JohnSmith",
            "arn:aws:iam::000000000000:user/LabCustomer-JohnSmith",
            "AKIA0000000000000000", "research-johnsmith", "research-johnsmith/",
            "2026-01-01T00:00:00", "2026-04-01T00:00:00", "active")
        close(db)
    end
    let db = LabAPI.init_vendors_db()
        LabAPI.insert_vendor(db, "genewiz",
            "arn:aws:iam::000000000000:user/LabVendor-genewiz",
            "AKIA0000000000000000", "caucell-genewiz-landing",
            "2026-01-01T00:00:00", "2026-04-01T00:00:00", "active")
        LabAPI.insert_vendor_order(db, "00000000-0000-0000-0000-000000000000", "genewiz",
            "00000000-0000-0000-0000-000000000000/", "2026-01-01T00:00:00", "open", missing)
        close(db)
    end
catch
end

# Drive the real CLIs through Comonicon (arg parse + dispatch) on offline-safe commands.
# ARGS is the global the generated `command_main()` reads; stdout/stderr are silenced so the
# build log stays clean, and each call is wrapped so a stray throw can't abort tracing.
redirect_stdout(devnull) do
    redirect_stderr(devnull) do
        for (mod, argv) in (
            (Main.CustomersCLI, ["list"]),
            (Main.CustomersCLI, ["get", "JohnSmith"]),
            (Main.VendorCLI,    ["list"]),
            (Main.VendorCLI,    ["get", "genewiz"]),
            (Main.VendorCLI,    ["list-orders", "genewiz"]),
        )
            try
                empty!(ARGS); append!(ARGS, argv)
                mod.command_main()
            catch
            end
        end
    end
end

# Shared offline helpers the command bodies lean on — cheap to call and cover all branches
# (size tiers, both validators + their AppError path, the secret box, the record printer,
# the timestamp formatter).
redirect_stdout(devnull) do
    LabAPI.fmt_size(2 * 1024^3); LabAPI.fmt_size(5 * 1024^2)
    LabAPI.fmt_size(100 * 1024); LabAPI.fmt_size(0)
    LabAPI.validate_customer_name("JohnSmith"); LabAPI.validate_vendor_name("genewiz")
    try; LabAPI.validate_customer_name("bad name"); catch; end
    try; LabAPI.validate_vendor_name("Bad_Name"); catch; end
    LabAPI.print_secret("JohnSmith", "AKIA0000000000000000", "secret", "research-johnsmith")
    LabAPI.print_record((customer_name="JohnSmith", bucket_name="research-johnsmith", status="active"))
    LabAPI._iso(Dates.now(Dates.UTC))
end

# SQLite: exercise the DDL + a query, same shape as LabAPI.DB.
let db = SQLite.DB()
    SQLite.execute(db, "CREATE TABLE t (a TEXT, b INTEGER)")
    SQLite.execute(db, "INSERT INTO t (a, b) VALUES (?, ?)", ("x", 1))
    collect(SQLite.DBInterface.execute(db, "SELECT * FROM t"))
end

# JSON3: exercise read/write, since AWS.jl responses are JSON under the hood.
JSON3.write(Dict("a" => 1, "b" => "two"))
JSON3.read("""{"a": 1, "b": "two"}""")
