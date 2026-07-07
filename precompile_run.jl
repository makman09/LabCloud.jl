"""
Precompile execution script for `build_sysimage.jl`.

Exercises representative code paths from each dependency (AWS, SQLite, Comonicon, JSON3) so
PackageCompiler's tracing captures them into `lab.so`. Expand this as real command bodies land
in later steps — a thin sysimage that only warms up `using` doesn't buy much over the default.
"""

using AWS
using SQLite
using Comonicon
using JSON3

# SQLite: exercise the DDL + a query, same shape as LabAPI.DB.
let db = SQLite.DB()
    SQLite.execute(db, "CREATE TABLE t (a TEXT, b INTEGER)")
    SQLite.execute(db, "INSERT INTO t (a, b) VALUES (?, ?)", ("x", 1))
    collect(SQLite.DBInterface.execute(db, "SELECT * FROM t"))
end

# JSON3: exercise read/write, since AWS.jl responses are JSON under the hood.
JSON3.write(Dict("a" => 1, "b" => "two"))
JSON3.read("""{"a": 1, "b": "two"}""")

# TODO Step 6 (sysimage build): once LabAPI's AWSIdent/Provision/Lifecycle/Status/Sync/Upload
# are real, call representative offline-safe functions here (validate_customer_name,
# fmt_size, print_secret, init_db/init_vendors_db) so they precompile into lab.so too.
