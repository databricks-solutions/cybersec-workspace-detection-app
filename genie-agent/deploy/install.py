"""One-command installer for the Security Detections Genie Agent.

Creates the schema, installs every SQL function, and creates (or updates) the
Genie Agent with all 32 functions registered as example queries.

    python genie-agent/deploy/install.py \
        --profile <cli-profile> \
        --catalog main \
        --warehouse-id <sql-warehouse-id>

Re-runnable: functions are CREATE OR REPLACE, and passing --space-id updates an
existing agent instead of creating a second one.

WHY A SCRIPT AND NOT A DAB BUNDLE. Databricks Asset Bundles do support a
``genie_spaces`` resource, and that is the right long-term home. It is not used
here for one concrete reason: the agent's whole configuration is a single opaque
``serialized_space`` JSON string, and the substitutions this install needs
(catalog and schema, in 32 places, INSIDE that string) are not something bundle
variable interpolation reaches -- it substitutes in YAML, not within an embedded
JSON payload. Doing it in a bundle would mean committing a pre-rendered
serialized_space per customer, which is worse than rendering it here. Revisit if
bundles gain templating inside resource payloads.

Stdlib only, and it shells out to the Databricks CLI rather than importing the
SDK, so there is nothing to pip install first -- the CLI is already a
prerequisite for anyone deploying this.

TWO THINGS LEARNED THE HARD WAY, both encoded below:

1. Function names are FULLY QUALIFIED in the DDL. Relying on ``USE CATALOG``
   fails when the session defaults to ``hive_metastore``: a function created
   there cannot reference the Unity Catalog table ``system.access.audit``, and the
   error (``UC_COMMAND_NOT_SUPPORTED``) does not mention the session catalog at
   all.
2. ``example_question_sqls`` MUST be sorted by ``id`` or the API rejects the
   whole payload with ``Invalid export proto``. Every entry also needs a 32-char
   hex id, which this script mints.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent
GENIE_DIR = HERE.parent
FUNCTIONS_DIR = GENIE_DIR / "functions"
TEMPLATE = GENIE_DIR / "agent" / "serialized_space.template.json"
INSTRUCTIONS = GENIE_DIR / "agent" / "instructions.md"

#: The API rejects an unsorted example list; ids must be 32-char lowercase hex.
_HEX32 = re.compile(r"^[0-9a-f]{32}$")


def _cli(profile: str, *args: str, body: Optional[dict] = None) -> dict:
    """Run a Databricks CLI command, optionally with a JSON body, return parsed JSON."""
    argv = ["databricks", "--profile", profile, *args]
    tmp = None
    if body is not None:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(body, tmp)
        tmp.close()
        argv += ["--json", "@" + tmp.name]
    proc = subprocess.run(argv, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"CLI failed: {' '.join(argv[:6])}…\n{proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        return {"_raw": proc.stdout}


def _sql(profile: str, warehouse_id: str, statement: str) -> None:
    """Execute one SQL statement, raising with the server's message on failure."""
    res = _cli(
        profile,
        "api",
        "post",
        "/api/2.0/sql/statements",
        body={"warehouse_id": warehouse_id, "statement": statement, "wait_timeout": "50s"},
    )
    state = res.get("status", {}).get("state")
    if state != "SUCCEEDED":
        msg = res.get("status", {}).get("error", {}).get("message", json.dumps(res)[:300])
        raise SystemExit(f"SQL failed ({state}): {msg}\n--- statement ---\n{statement[:400]}")


def _split_statements(sql_text: str) -> List[str]:
    """Split a function file into individual CREATE FUNCTION statements.

    Splits on ``;`` at end-of-line rather than every ``;`` -- semicolons appear
    inside COMMENT text, and splitting on those would cut a statement in half.
    """
    out: List[str] = []
    for chunk in sql_text.split(";\n"):
        if "CREATE OR REPLACE FUNCTION" not in chunk:
            continue
        out.append(chunk[chunk.index("CREATE OR REPLACE FUNCTION") :].strip())
    return out


def install_functions(profile: str, warehouse_id: str, catalog: str, schema: str) -> int:
    """Create the schema then install every function. Returns the count."""
    print(f"→ creating schema {catalog}.{schema}")
    _sql(
        profile,
        warehouse_id,
        f"CREATE SCHEMA IF NOT EXISTS {catalog}.{schema} "
        f"COMMENT 'Security detection functions for the Genie Agent'",
    )

    total = 0
    for path in sorted(FUNCTIONS_DIR.glob("*.sql")):
        text = path.read_text(encoding="utf-8")
        text = text.replace("${CATALOG}", catalog).replace("${SCHEMA}", schema)
        stmts = _split_statements(text)
        print(f"→ {path.name}: {len(stmts)} function(s)")
        for stmt in stmts:
            name = re.match(r"CREATE OR REPLACE FUNCTION ([\w.]+)\(", stmt)
            # Belt and braces: qualify anything the placeholder pass missed, so a
            # hand-edited file cannot land a function in hive_metastore.
            if name and "." not in name.group(1):
                stmt = stmt.replace(
                    f"CREATE OR REPLACE FUNCTION {name.group(1)}(",
                    f"CREATE OR REPLACE FUNCTION {catalog}.{schema}.{name.group(1)}(",
                    1,
                )
            _sql(profile, warehouse_id, stmt)
            total += 1
    print(f"✓ installed {total} functions")
    return total


def build_serialized_space(catalog: str, schema: str) -> str:
    """Render the space template, refresh instructions, and satisfy the API's rules."""
    space = json.loads(TEMPLATE.read_text(encoding="utf-8").replace(
        "${catalog}.${schema}", f"{catalog}.{schema}"
    ))

    # Instructions are maintained as markdown; keep the deployed copy in step.
    if INSTRUCTIONS.exists():
        lines = INSTRUCTIONS.read_text(encoding="utf-8").splitlines(keepends=True)
        space["instructions"]["text_instructions"] = [
            {"id": uuid.uuid4().hex, "content": lines}
        ]

    examples = space["instructions"].get("example_question_sqls", [])
    for ex in examples:
        if not _HEX32.match(str(ex.get("id", ""))):
            ex["id"] = uuid.uuid4().hex
    # Load-bearing: the API rejects an unsorted list outright.
    examples.sort(key=lambda e: e["id"])
    space["instructions"]["example_question_sqls"] = examples

    return json.dumps(space, indent=2)


def deploy_agent(
    profile: str,
    warehouse_id: str,
    catalog: str,
    schema: str,
    title: str,
    space_id: Optional[str],
) -> str:
    """Create a new agent, or update *space_id* in place. Returns the space id."""
    serialized = build_serialized_space(catalog, schema)
    n_examples = len(json.loads(serialized)["instructions"]["example_question_sqls"])

    if space_id:
        print(f"→ updating existing agent {space_id} ({n_examples} examples)")
        current = _cli(
            profile, "api", "get",
            f"/api/2.0/genie/spaces/{space_id}?include_serialized_space=true",
        )
        etag = current.get("etag")
        if not etag:
            raise SystemExit(
                f"could not read etag for space {space_id}. "
                "include_serialized_space needs CAN EDIT on the space -- without it "
                "the field is omitted silently rather than erroring."
            )
        res = _cli(
            profile, "api", "patch", f"/api/2.0/genie/spaces/{space_id}",
            body={"serialized_space": serialized, "etag": etag},
        )
    else:
        print(f"→ creating agent '{title}' ({n_examples} examples)")
        res = _cli(
            profile, "api", "post", "/api/2.0/genie/spaces",
            body={
                "warehouse_id": warehouse_id,
                "serialized_space": serialized,
                "title": title,
            },
        )

    new_id = res.get("space_id", space_id)
    print(f"✓ agent ready: {new_id}")
    return new_id


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", required=True, help="Databricks CLI profile")
    ap.add_argument("--catalog", required=True, help="Unity Catalog catalog to install into")
    ap.add_argument("--schema", default="security_detections")
    ap.add_argument("--warehouse-id", required=True, help="SQL warehouse for DDL and the agent")
    ap.add_argument("--title", default="Databricks Security Audit Investigator")
    ap.add_argument("--space-id", help="Update this existing agent instead of creating one")
    ap.add_argument("--functions-only", action="store_true", help="Skip the agent step")
    args = ap.parse_args()

    if not TEMPLATE.exists():
        raise SystemExit(f"missing {TEMPLATE}")

    install_functions(args.profile, args.warehouse_id, args.catalog, args.schema)

    if args.functions_only:
        print("\nfunctions installed; skipping agent (--functions-only)")
        return 0

    space_id = deploy_agent(
        args.profile, args.warehouse_id, args.catalog, args.schema,
        args.title, args.space_id,
    )

    print("\nNext: open Genie, find the agent, and ask")
    print('  "Who changed the IP allow list in the last 30 days?"')
    print("\nIf a function returns no rows, that action may simply not occur in this")
    print("account -- check with the discovery query in agent/example_questions.md")
    print("before concluding nothing happened.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
