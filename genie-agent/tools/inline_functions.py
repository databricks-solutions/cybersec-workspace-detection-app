"""Inline the detection SQL functions into Genie example queries (build-time).

The Genie Agent's trusted assets can be *either* Unity Catalog SQL functions
*or* parameterized example queries whose exact SQL is embedded in the space.
The original installer created 33 UC functions with ~33 serial ``CREATE
FUNCTION`` statements on a warehouse (the "~20 minute" install). This module is
the alternative: it reads the SAME ``functions/*.sql`` files -- still the single
source of truth for the verified logic -- and rewrites each function body into
an embedded, parameterized example query, so the space needs **no DDL and no
warehouse at install time**.

The transform, per function, is deliberately parse-light so it can't silently
mangle a body:

1. A string/paren-aware scanner (NOT regex -- COMMENT text contains parens and
   semicolons) extracts the parameter names, the ``RETURNS TABLE`` column names,
   and the ``RETURN`` body.
2. Each parameter identifier in the body is replaced with the value the existing
   example wrapper passed: ``start_time``/``end_time`` become the named binds
   ``:start_time``/``:end_time``; tuning params become the literal the wrapper
   used (e.g. ``min_ips`` -> ``5``, ``admin_groups`` -> ``''``). A parameter is
   only substituted when it appears as a bare identifier, never as ``x.name``.
3. The body is wrapped as ``SELECT * FROM ( <body> ) AS results(col1, ..., colN)``
   using the RETURNS TABLE column names. This renames the output columns
   positionally -- so the embedded query returns exactly the columns the UC
   function did -- WITHOUT parsing or aliasing the inner SELECT. CTEs, window
   functions, and mixed aliasing in the body are therefore irrelevant.

Public API:
    parse_functions(functions_dir) -> {name: FunctionDef}
    parse_call(sql) -> (name, [arg, ...])
    inline(func, args) -> str          # the embedded SELECT
    build_example_sqls(functions_dir, examples) -> examples  # sql replaced in place

Stdlib only.
"""
from __future__ import annotations

import glob
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

__all__ = ["FunctionDef", "parse_functions", "parse_call", "inline",
           "build_example_sqls"]


@dataclass
class FunctionDef:
    name: str
    params: List[str]          # ordered input parameter names
    columns: List[str]         # ordered RETURNS TABLE column names
    body: str                  # everything after RETURN, ';' stripped


# --------------------------------------------------------------------------- #
#  String/paren-aware scanning primitives                                     #
# --------------------------------------------------------------------------- #
def _matching_paren(s: str, open_idx: int) -> int:
    """Index of the ')' matching the '(' at open_idx, ignoring quoted strings."""
    assert s[open_idx] == "(", "open_idx must point at '('"
    depth = 0
    in_str = False
    i = open_idx
    n = len(s)
    while i < n:
        c = s[i]
        if in_str:
            if c == "'":
                if i + 1 < n and s[i + 1] == "'":   # '' escape inside a literal
                    i += 2
                    continue
                in_str = False
        elif c == "'":
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced parentheses")


def _split_top_level(block: str, sep: str = ",", track_angle: bool = False) -> List[str]:
    """Split on `sep` only at depth 0 and outside single-quoted strings.

    `track_angle=True` also counts `<`/`>` toward depth, so a comma inside a
    complex type name (``MAP<STRING, STRING>``, ``STRUCT<a:INT, b:STRING>``,
    ``ARRAY<...>``) does not split the segment. Use it for type contexts
    (parameter lists, RETURNS TABLE column lists) -- NOT for value/expression
    lists, where `<`/`>` are comparison operators.
    """
    parts: List[str] = []
    depth = 0
    angle = 0
    in_str = False
    cur = ""
    i = 0
    n = len(block)
    while i < n:
        c = block[i]
        if in_str:
            cur += c
            if c == "'":
                if i + 1 < n and block[i + 1] == "'":
                    cur += block[i + 1]
                    i += 2
                    continue
                in_str = False
        elif c == "'":
            in_str = True
            cur += c
        elif c == "(":
            depth += 1
            cur += c
        elif c == ")":
            depth -= 1
            cur += c
        elif track_angle and c == "<":
            angle += 1
            cur += c
        elif track_angle and c == ">":
            angle = max(0, angle - 1)
            cur += c
        elif c == sep and depth == 0 and angle == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    if cur.strip():
        parts.append(cur)
    return parts


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i].isspace():
        i += 1
    return i


def _skip_string(s: str, i: int) -> int:
    """s[i] must be the opening quote; return index just past the closing quote."""
    assert s[i] == "'"
    i += 1
    n = len(s)
    while i < n:
        if s[i] == "'":
            if i + 1 < n and s[i + 1] == "'":
                i += 2
                continue
            return i + 1
        i += 1
    raise ValueError("unterminated string literal")


# --------------------------------------------------------------------------- #
#  Function-definition parser                                                 #
# --------------------------------------------------------------------------- #
_CREATE_RE = re.compile(
    r"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+[^(]*?(\w+)\s*\(", re.IGNORECASE)


def _first_token(segment: str) -> str:
    return segment.strip().split()[0]


def parse_function(chunk: str) -> FunctionDef:
    """Parse a single CREATE OR REPLACE FUNCTION block into a FunctionDef."""
    m = _CREATE_RE.search(chunk)
    if not m:
        raise ValueError("not a CREATE OR REPLACE FUNCTION block")
    name = m.group(1)

    # -- parameter list: the '(' the regex ended on --
    popen = m.end() - 1
    pclose = _matching_paren(chunk, popen)
    params = [_first_token(seg) for seg in
              _split_top_level(chunk[popen + 1:pclose], track_angle=True)
              if seg.strip()]

    # -- RETURNS TABLE ( ... ) --
    rt_kw = re.search(r"RETURNS\s+TABLE\s*\(", chunk[pclose:], re.IGNORECASE)
    if not rt_kw:
        raise ValueError(f"{name}: no RETURNS TABLE")
    rt_open = pclose + rt_kw.end() - 1
    rt_close = _matching_paren(chunk, rt_open)
    columns = [_first_token(seg) for seg in
               _split_top_level(chunk[rt_open + 1:rt_close], track_angle=True)
               if seg.strip()]

    # -- optional COMMENT 'string' then RETURN <body> --
    i = _skip_ws(chunk, rt_close + 1)
    if chunk[i:i + 7].upper() == "COMMENT":
        i = _skip_ws(chunk, i + 7)
        if i < len(chunk) and chunk[i] == "'":
            i = _skip_string(chunk, i)
        i = _skip_ws(chunk, i)
    if chunk[i:i + 6].upper() != "RETURN":
        raise ValueError(f"{name}: expected RETURN after signature, got "
                         f"{chunk[i:i + 20]!r}")
    body = chunk[i + 6:].strip().rstrip(";").strip()
    return FunctionDef(name=name, params=params, columns=columns, body=body)


def parse_functions(functions_dir: str | Path) -> Dict[str, FunctionDef]:
    """Parse every CREATE OR REPLACE FUNCTION across functions_dir/*.sql."""
    out: Dict[str, FunctionDef] = {}
    for path in sorted(glob.glob(str(Path(functions_dir) / "*.sql"))):
        text = Path(path).read_text(encoding="utf-8")
        # split on ';' at end-of-line (semicolons appear inside COMMENT text)
        for chunk in text.split(";\n"):
            if "CREATE OR REPLACE FUNCTION" not in chunk.upper():
                continue
            fn = parse_function(chunk[chunk.upper().index("CREATE"):])
            out[fn.name] = fn
    return out


# --------------------------------------------------------------------------- #
#  Example-call parser + inliner                                              #
# --------------------------------------------------------------------------- #
# Find the detection table-function call in an example wrapper, whether it is
# fully qualified (`${catalog}.${schema}.detect_x(`), partially qualified
# (`schema.detect_x(`), or BARE (`detect_x(`). The templates historically carry a
# `${catalog}.${schema}.` prefix, but the embedded / no-DDL install no longer needs
# it -- so this MUST NOT depend on that leading dot. If someone "tidies away" those
# now-vestigial placeholders, a dot-anchored pattern would match nothing and every
# install would break silently. The optional `(?:\w+\.)*` qualifier makes removing
# them safe; anchoring on the `detect_` naming convention (every function in
# functions/*.sql starts with it) keeps `.search` from latching onto an incidental
# earlier call such as `to_timestamp(`. If a detection is ever named without the
# `detect_` prefix, widen this pattern in lockstep.
_CALL_RE = re.compile(r"(?:\w+\.)*(detect_\w+)\s*\(", re.IGNORECASE)


def parse_call(sql: str) -> Tuple[str, List[str]]:
    """From `SELECT * FROM cat.sch.detect_x(:a, :b, 5)` -> ('detect_x', [':a',':b','5'])."""
    m = _CALL_RE.search(sql)
    if not m:
        raise ValueError(f"no function call found in: {sql[:80]!r}")
    open_idx = m.end() - 1
    close_idx = _matching_paren(sql, open_idx)
    arg_block = sql[open_idx + 1:close_idx]
    args = [a.strip() for a in _split_top_level(arg_block) if a.strip()]
    return m.group(1), args


def _substitute_params(body: str, mapping: Dict[str, str]) -> str:
    """Replace each bare param identifier with its value (never `x.param`)."""
    for pname, value in mapping.items():
        # not preceded by '.' (a column ref) or a word char; word boundary after
        pattern = re.compile(r"(?<![\w.])" + re.escape(pname) + r"\b")
        body = pattern.sub(lambda _m, v=value: v, body)
    return body


def inline(func: FunctionDef, args: List[str]) -> str:
    """Produce the embedded, parameterized SELECT for one function call."""
    if len(args) != len(func.params):
        raise ValueError(
            f"{func.name}: wrapper passes {len(args)} args "
            f"but function declares {len(func.params)} params "
            f"({func.params} vs {args})")
    mapping = dict(zip(func.params, args))
    body = _substitute_params(func.body, mapping)
    cols = ", ".join(func.columns)
    # indent the body one level for readability inside the wrapper
    indented = "\n".join("  " + ln if ln.strip() else ln
                         for ln in body.splitlines())
    return f"SELECT *\nFROM (\n{indented}\n) AS results({cols})"


def build_example_sqls(functions_dir: str | Path, examples: List[dict]) -> List[dict]:
    """Replace each example's `sql` (a detect_x() wrapper) with its inlined form.

    Mutates and returns `examples`. The question + usage_guidance on each entry
    are left untouched -- functions/*.sql owns the SQL, the space owns the
    natural-language matching text.
    """
    funcs = parse_functions(functions_dir)
    for ex in examples:
        sql = "".join(ex["sql"]) if isinstance(ex["sql"], list) else ex["sql"]
        name, args = parse_call(sql)
        if name not in funcs:
            raise ValueError(f"example calls unknown function {name!r}; "
                             f"have {sorted(funcs)}")
        inlined = inline(funcs[name], args)
        # store as a list of line-strings, matching the template's shape
        ex["sql"] = [ln + "\n" for ln in inlined.splitlines()]
    return examples


# --------------------------------------------------------------------------- #
#  Self-check: parse everything, assert arg/param parity, show one sample     #
# --------------------------------------------------------------------------- #
def _selfcheck() -> int:
    import json
    here = Path(__file__).resolve().parent
    fdir = here.parent / "functions"
    template = here.parent / "agent" / "serialized_space.template.json"

    funcs = parse_functions(fdir)
    print(f"parsed {len(funcs)} functions")
    for name, f in funcs.items():
        print(f"  {name}: params={f.params} cols={len(f.columns)}")

    sp = json.loads(template.read_text())
    examples = sp["instructions"]["example_question_sqls"]
    print(f"\n{len(examples)} example wrappers")
    ok = True
    for ex in examples:
        sql = "".join(ex["sql"]) if isinstance(ex["sql"], list) else ex["sql"]
        name, args = parse_call(sql)
        if name not in funcs:
            print(f"  ✗ example -> unknown function {name}")
            ok = False
            continue
        f = funcs[name]
        flag = "" if len(args) == len(f.params) else "  ✗ ARG/PARAM MISMATCH"
        if flag:
            ok = False
        print(f"  {name}: {len(args)} args, {len(f.params)} params{flag}")

    # show one full inlined example
    demo = "detect_session_multi_ip_logins"
    if demo in funcs:
        sql = next(("".join(e["sql"]) for e in examples
                    if parse_call("".join(e["sql"]) if isinstance(e["sql"], list)
                                  else e["sql"])[0] == demo), None)
        if sql:
            _, args = parse_call(sql)
            print(f"\n----- inlined {demo} -----\n{inline(funcs[demo], args)}")
    print("\nSELF-CHECK:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selfcheck())
