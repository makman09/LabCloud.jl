"""
    Util

Mirrors `src/util.py`: name validation, the one-time-secret box, size formatting, and the
"swallow not-found" AWS error helper. `AppError` stands in for `click.ClickException` — the
exception type every CLI command raises for a user-facing, non-traceback error.
"""
module Util

using Printf
using Dates: DateTime

export AppError, NAME_PATTERN, VENDOR_NAME_PATTERN,
       validate_customer_name, validate_vendor_name,
       print_secret, fmt_size, ignore_not_found, as_vector, xml_children, xml_scalar,
       _parse_iso8601, username_from_arn

"""
    AppError <: Exception

The Julia analog of `click.ClickException`: a user-facing error whose `msg` is the whole
message (no traceback noise). CLI entrypoints should catch this and print `msg` plus exit
nonzero, same as click does.
"""
struct AppError <: Exception
    msg::String
end
Base.showerror(io::IO, e::AppError) = print(io, e.msg)

const NAME_PATTERN = r"^[A-Z][a-z]+[A-Z][a-z]+$"
# Vendor names are bucket-name-safe slugs: lowercase alphanumeric, hyphen-separated
# (e.g. genewiz, illumina-cloud). They embed into `caucell-{vendor}-landing`.
const VENDOR_NAME_PATTERN = r"^[a-z0-9]+(-[a-z0-9]+)*$"

function validate_customer_name(name)
    if match(NAME_PATTERN, name) === nothing
        throw(AppError(
            "Invalid name '$name'. Must be TitleCase FirstnameLastname " *
            "(e.g., JohnBob, JaneSmith). No spaces, digits, or special characters."
        ))
    end
end

function validate_vendor_name(name)
    if match(VENDOR_NAME_PATTERN, name) === nothing
        throw(AppError(
            "Invalid vendor name '$name'. Must be a lowercase slug " *
            "(e.g., genewiz, illumina-cloud). Lowercase alphanumerics separated by hyphens."
        ))
    end
end

"""
    fmt_size(b) -> String

GB/MB/KB tiers exactly matching `src/util.py`: `>= 1024^3` GB, `>= 1024^2` MB, else KB, all
`.1f`. Note `b == 0` falls through to the KB branch -> `"0.0 KB"`.
"""
function fmt_size(b)
    if b >= 1024^3
        return @sprintf("%.1f GB", b / 1024^3)
    end
    if b >= 1024^2
        return @sprintf("%.1f MB", b / 1024^2)
    end
    return @sprintf("%.1f KB", b / 1024)
end

"""
    print_secret(entity_name, access_key_id, secret_key, bucket_name; label="Customer")

Reproduces the one-time-secret box from `src/util.py::print_secret` verbatim, including the
em dash (—, U+2014) and the `label + ':'` left-padded to width 15.
"""
function print_secret(entity_name, access_key_id, secret_key, bucket_name; label="Customer")
    println()
    println("=" ^ 50)
    println("  ONE-TIME SECRET — COPY NOW")
    println("=" ^ 50)
    println("  ", rpad(label * ":", 15), " ", entity_name)
    println("  Access Key ID:  ", access_key_id)
    println("  Secret Key:     ", secret_key)
    println("  Bucket:         ", bucket_name)
    println("=" ^ 50)
    println("  THIS SECRET WILL NOT BE SHOWN AGAIN")
    println("=" ^ 50)
    println()
end

"""
    as_vector(x)

XML single-element collapse: AWS.jl's XML parser returns a bare `Dict` (not a one-element
`Vector`) when a repeated element occurs exactly once (e.g. one access key, one object
version) — while zero occurrences drop the key/element entirely rather than yielding an
empty `Vector`. Normalizes the present-and-nonempty case to a `Vector` so callers can always
iterate; callers still need a `haskey`/`get` check first for the zero case (see
`AWSIdent._first_mfa_serial` and `Lifecycle` for the pattern). Shared across `AWSIdent` (IAM
responses) and `Lifecycle` (IAM + S3 responses) — this is a generic AWS.jl quirk, not
specific to either.
"""
as_vector(x) = x isa AbstractVector ? x : [x]

"""
    xml_children(page, tag) -> Vector

Every child element named `tag` in an AWS.jl-parsed XML `page`, tolerant of BOTH shapes AWS.jl's
XMLDict parser produces. Usually siblings merge under the tag name (`page[tag]`, normalized via
`as_vector`). But some list responses (`ListVersionsResult`, `ListMultipartUploadsResult`) trigger
XMLDict's *ordered fallback*: the whole child list lands under a single `""` key as a `Vector` of
one-key dicts (`page[""] = [Dict("Name"=>…), Dict("Version"=>…), Dict("Version"=>…), …]`), so
`haskey(page,tag)` is false and a naive `page[tag]` read silently yields nothing. This recovers
`tag`'s children from whichever shape is present (empty `Vector` if absent). See `xml_scalar` for
the scalar-child companion.
"""
xml_children(page, tag) = haskey(page, tag) ? as_vector(page[tag]) :
    (haskey(page, "") ? Any[e[tag] for e in page[""] if e isa AbstractDict && haskey(e, tag)] : Any[])

"""
    xml_scalar(page, tag, default="")

A single scalar child (`IsTruncated`, `NextKeyMarker`, …) of an AWS.jl-parsed XML `page`, tolerant
of both the merged shape (`page[tag]`) and XMLDict's ordered-fallback shape (a matching one-key
dict inside `page[""]`). Returns `default` when absent. Companion to `xml_children`.
"""
function xml_scalar(page, tag, default="")
    haskey(page, tag) && return page[tag]
    if haskey(page, "")
        for e in page[""]
            e isa AbstractDict && haskey(e, tag) && return e[tag]
        end
    end
    return default
end

"""
    username_from_arn(arn) -> String

The IAM username is the last `/`-delimited segment of the user ARN — the single source of
truth for what every name-based IAM call (`list_access_keys`, `create_access_key`,
`delete_user`, …) needs. Deriving it from the stored ARN (rather than reconstructing it from
a fixed prefix) is what lets one code path serve every naming scheme at once:

- new customer `…:user/lab-customers/JohnSmith`  -> `JohnSmith` (bare; path is not part of the username)
- legacy customer `…:user/LabCustomer-JohnSmith` -> `LabCustomer-JohnSmith`
- vendor `…:user/LabVendor-genewiz`              -> `LabVendor-genewiz`
"""
username_from_arn(arn) = String(last(split(arn, '/')))

"""
    _parse_iso8601(s) -> DateTime

Parse an ISO8601 timestamp (STS `Expiration`, S3 `LastModified`) into an implicit-UTC
`DateTime`. Tolerates a `Z` or `+00:00` suffix and any fractional-second precision
(LocalStack emits microseconds; `Dates.DateTime` parses at most milliseconds, so extra
digits are truncated). Shared by `AWSIdent._parse_expiry` and `Sync._parse_last_modified`.
"""
function _parse_iso8601(s)
    str = rstrip(first(split(String(s), '+')), 'Z')
    m = match(r"^(.*?\.\d{1,3})\d*$", str)
    return DateTime(m === nothing ? str : m[1])
end

"""
    ignore_not_found(f)

Runs zero-arg `f`; if it throws and the exception's message contains "NoSuchEntity",
"NoSuchBucket", or "404", swallows it and returns `nothing`. Rethrows anything else. The
Julia-closure analog of `src/util.py::ignore_not_found` (AWS wiring — the boto-specific
`NoSuchEntityException` type check — lands with `AWSIdent` in a later step).
"""
function ignore_not_found(f)
    try
        return f()
    catch e
        msg = sprint(showerror, e)
        if occursin("NoSuchEntity", msg) || occursin("NoSuchBucket", msg) || occursin("404", msg)
            return nothing
        end
        rethrow()
    end
end

end # module Util
