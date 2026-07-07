"""
Builds `lab.so` — a PackageCompiler sysimage pre-loading AWS/SQLite/Comonicon/JSON3 so
`LabCustomersAPI.jl`/`LabVendorAPI.jl` start instantly instead of paying JIT/precompile cost
on every invocation. Not run automatically (slow, minutes) — invoke explicitly:

    julia --project=. build_sysimage.jl

then run the CLIs with `julia --project=. -J lab.so LabCustomersAPI.jl <command>`.
"""

using PackageCompiler

create_sysimage(
    [:AWS, :SQLite, :Comonicon, :JSON3];
    sysimage_path=joinpath(@__DIR__, "lab.so"),
    project=@__DIR__,
    precompile_execution_file=joinpath(@__DIR__, "precompile_run.jl"),
)
