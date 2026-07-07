"""
    CLI

Shared substrate for the two CLI entrypoints (`LabCustomersAPI.jl` / `LabVendorAPI.jl`).
Comonicon has no click-style `prompt=`/`confirmation_option` decorators or ClickException
printing, so the interactive `delete` gates, the `get`-command record printer, and the
`AppError`→"Error: <msg>" exit wrapper are hand-rolled once here and shared by both CLIs.
Julia-only glue (no Python mirror) — the customer/vendor CLIs previously carried byte-for-byte
copies of each of these.
"""
module CLI

using ..Util: AppError

export _prompt_line, _abort, _require_mfa, _confirm_delete, print_record, run_cli

# `delete`'s interactive gates — Comonicon has no click prompt/confirmation_option, so these
# match click's exact behavior: EOF (no input left) or a declined confirmation both abort with
# "Aborted!" on stderr and a nonzero exit, BEFORE any AWS/DB work — see the contract tests'
# `test_missing_mfa_aborts_without_destroying`/`test_declined_confirmation_aborts_without_destroying`.
function _prompt_line(promptstr)
    print(promptstr)
    flush(stdout)
    eof(stdin) && return nothing
    return readline(stdin)
end

_abort() = (println(stderr, "Aborted!"); exit(1))

function _require_mfa(mfa)
    isempty(mfa) || return mfa
    line = _prompt_line("MFA code: ")
    line === nothing && _abort()
    return line
end

"""Deletion confirmation gate. `message` is the entity-specific prompt string (the customer
and vendor CLIs differ only there)."""
function _confirm_delete(yes; message)
    yes && return nothing
    line = _prompt_line(message)
    (line !== nothing && lowercase(strip(line)) in ("y", "yes")) || _abort()
    return nothing
end

"""Print a registry record (a NamedTuple row) one field per line, skipping the surrogate
`:id`, `rpad`-ing the field name to width 16 — the `get` command's layout."""
function print_record(rec)
    for key in propertynames(rec)
        key === :id && continue
        println("  ", rpad(String(key), 16), " ", rec[key])
    end
end

"""Run a Comonicon `command_main` and convert an `AppError` (our `click.ClickException`
analog) into click-style `Error: <msg>` output + exit 1 instead of an uncaught-exception
dump. `@main`, run from each CLI's nested module rather than bare `Main`, defines
`command_main()` without auto-invoking it (Comonicon's "project" codegen), so we wrap it."""
function run_cli(main)
    try
        exit(main())
    catch e
        if e isa AppError
            println(stderr, "Error: ", e.msg)
            exit(1)
        end
        rethrow(e)
    end
end

end # module CLI
