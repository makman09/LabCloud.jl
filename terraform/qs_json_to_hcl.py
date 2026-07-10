#!/usr/bin/env python3
"""Convert a QuickSight API Definition JSON into Terraform HCL (snake_case).

Heuristic mapping (matches the aws_quicksight_analysis/_dashboard provider schema):
  dict              -> block:  key { ... }
  list-of-dict      -> repeated blocks: key { ... } key { ... }
  list-of-scalar    -> attribute: key = [ ... ]
  scalar            -> attribute: key = value
Empty dicts / empty lists are omitted. PascalCase keys -> snake_case with a few
known irregular overrides. terraform validate/plan is the oracle for the rest.
"""
import json, re, sys

# Irregular key names where naive snake_case != provider attribute name.
OVERRIDES = {
    "DataSetIdentifierDeclarations": "data_set_identifiers_declarations",
    "FieldBasedTooltip": "field_base_tooltip",
}

# Keys unsupported by the provider version — dropped entirely.
DROP_GLOBAL = {"Options", "QueryExecutionOptions"}
# Keys dropped only when nested directly under a given parent key.
DROP_UNDER = {
    "FilterListConfiguration": {"NullOption"},  # provider lacks null_option here
}

def snake(name):
    if name in OVERRIDES:
        return OVERRIDES[name]
    s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', name)
    s2 = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1)
    return s2.lower()

def esc(s):
    # HCL double-quoted string escaping, incl. interpolation sequences.
    s = s.replace('\\', '\\\\').replace('"', '\\"')
    s = s.replace('${', '$${').replace('%{', '%%{')
    return s

def emit_scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return json.dumps(v)
    return '"' + esc(str(v)) + '"'

def is_empty(v):
    return v is None or v == {} or v == []

def emit(key, val, out, indent):
    pad = "  " * indent
    sk = snake(key)
    if is_empty(val):
        return
    if isinstance(val, dict):
        out.append(f"{pad}{sk} {{")
        emit_body(val, out, indent + 1, parent=key)
        out.append(f"{pad}}}")
    elif isinstance(val, list):
        if all(isinstance(x, dict) for x in val):
            for item in val:
                if is_empty(item):
                    continue
                out.append(f"{pad}{sk} {{")
                emit_body(item, out, indent + 1, parent=key)
                out.append(f"{pad}}}")
        else:
            items = ", ".join(emit_scalar(x) for x in val)
            out.append(f"{pad}{sk} = [{items}]")
    else:
        out.append(f"{pad}{sk} = {emit_scalar(val)}")

def emit_body(d, out, indent, parent=None):
    drops = DROP_UNDER.get(parent, set())
    for k, v in d.items():
        if k in DROP_GLOBAL or k in drops:
            continue
        emit(k, v, out, indent)

def main():
    src = json.load(open(sys.argv[1]))
    defn = src["Definition"]
    out = []
    emit("definition", defn, out, 1)  # produces "  definition { ... }"
    print("\n".join(out))

if __name__ == "__main__":
    main()
