"""One-command installer for the Security Detections Genie Agent.

Builds the Genie Agent with all detections embedded as parameterized example
queries and creates (or updates) the space. There is **no DDL** — the detection
SQL is inlined into the space from ``functions/*.sql`` at build time, so nothing
is created in Unity Catalog and no warehouse is needed to install.

    python genie-agent/deploy/install.py --profile <cli-profile>
    python genie-agent/deploy/install.py --profile <cli-profile> --warehouse-id <id>
    python genie-agent/deploy/install.py --profile <cli-profile> --space-id <id>   # update

Re-runnable: passing ``--space-id`` updates an existing agent in place instead of
creating a second one.

WHY EMBEDDED QUERIES AND NOT UC FUNCTIONS. An earlier version created one SQL
function per detection (~30 serial ``CREATE FUNCTION`` statements on a warehouse —
a multi-minute install that also required ``CREATE FUNCTION`` / ``USE SCHEMA``
privileges and a caller-chosen catalog/schema). A Genie Agent's trusted assets
can equally be *parameterized example queries* whose SQL is embedded in the space,
so ``tools/inline_functions.py`` rewrites each function body into an example query
at build time. The install becomes a single space create — seconds, no DDL, no
privileges beyond creating a Genie space. ``functions/*.sql`` stays the single
source of truth for the verified logic; the batch/scheduled notebooks under
``base/`` are unaffected.

WHY A SCRIPT AND NOT A DAB BUNDLE. The agent's whole configuration is a single
opaque ``serialized_space`` JSON string, and the substitutions this install needs
happen INSIDE that string — not something bundle variable interpolation reaches
(it substitutes in YAML, not within an embedded JSON payload). Revisit if bundles
gain templating inside resource payloads.

Stdlib only, and it shells out to the Databricks CLI rather than importing the
SDK, so there is nothing to pip install first — the CLI is already a prerequisite
for anyone deploying this.

ONE THING LEARNED THE HARD WAY, encoded below: ``example_question_sqls`` MUST be
sorted by ``id`` or the API rejects the whole payload with ``Invalid export
proto``. Every entry also needs a 32-char hex id, which this script mints.
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
from typing import Optional

HERE = Path(__file__).resolve().parent
GENIE_DIR = HERE.parent
FUNCTIONS_DIR = GENIE_DIR / "functions"
TEMPLATE = GENIE_DIR / "agent" / "serialized_space.template.json"
INSTRUCTIONS = GENIE_DIR / "agent" / "instructions.md"

# The inliner lives next to this script's package, under genie-agent/tools/.
sys.path.insert(0, str(GENIE_DIR / "tools"))
from inline_functions import build_example_sqls  # noqa: E402

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


def resolve_warehouse(profile: str, warehouse_id: Optional[str]) -> str:
    """Return an explicit warehouse id, or auto-pick a sensible default.

    A Genie space is created against a SQL warehouse (the space runs its queries
    there), so a create needs one — but the caller shouldn't have to hunt for an
    id. Preference order: a RUNNING serverless warehouse, then any RUNNING one,
    then any warehouse at all.
    """
    if warehouse_id:
        return warehouse_id
    res = _cli(profile, "api", "get", "/api/2.0/sql/warehouses")
    warehouses = res.get("warehouses", []) if isinstance(res, dict) else []
    if not warehouses:
        raise SystemExit(
            "no SQL warehouse found to attach the agent to. Create one, or pass "
            "--warehouse-id explicitly."
        )

    def score(w: dict) -> tuple:
        running = w.get("state") == "RUNNING"
        serverless = w.get("enable_serverless_compute", False)
        return (running, serverless)

    best = max(warehouses, key=score)
    print(f"→ using warehouse {best.get('id')} ({best.get('name')}, "
          f"state={best.get('state')}) — pass --warehouse-id to override")
    return best["id"]


def build_serialized_space() -> str:
    """Render the space: inline the detections, refresh instructions, satisfy the API."""
    space = json.loads(TEMPLATE.read_text(encoding="utf-8"))

    # Instructions are maintained as markdown; keep the deployed copy in step.
    if INSTRUCTIONS.exists():
        lines = INSTRUCTIONS.read_text(encoding="utf-8").splitlines(keepends=True)
        space["instructions"]["text_instructions"] = [
            {"id": uuid.uuid4().hex, "content": lines}
        ]

    examples = space["instructions"].get("example_question_sqls", [])
    # Replace each detect_x() wrapper with the detection's inlined, parameterized
    # SQL — the source of truth is functions/*.sql, rendered at build time.
    build_example_sqls(FUNCTIONS_DIR, examples)
    for ex in examples:
        if not _HEX32.match(str(ex.get("id", ""))):
            ex["id"] = uuid.uuid4().hex
    # Load-bearing: the API rejects an unsorted list outright.
    examples.sort(key=lambda e: e["id"])
    space["instructions"]["example_question_sqls"] = examples

    return json.dumps(space, indent=2)


def deploy_agent(profile: str, warehouse_id: Optional[str], title: str,
                 space_id: Optional[str]) -> str:
    """Create a new agent, or update *space_id* in place. Returns the space id."""
    serialized = build_serialized_space()
    n_examples = len(json.loads(serialized)["instructions"]["example_question_sqls"])

    if space_id:
        print(f"→ updating existing agent {space_id} ({n_examples} embedded queries)")
        current = _cli(
            profile, "api", "get",
            f"/api/2.0/genie/spaces/{space_id}?include_serialized_space=true",
        )
        etag = current.get("etag")
        if not etag:
            raise SystemExit(
                f"could not read etag for space {space_id}. "
                "include_serialized_space needs CAN EDIT on the space — without it "
                "the field is omitted silently rather than erroring."
            )
        _cli(
            profile, "api", "patch", f"/api/2.0/genie/spaces/{space_id}",
            body={"serialized_space": serialized, "etag": etag},
        )
        print(f"✓ agent updated: {space_id}")
        return space_id

    wid = resolve_warehouse(profile, warehouse_id)
    print(f"→ creating agent '{title}' ({n_examples} embedded queries)")
    res = _cli(
        profile, "api", "post", "/api/2.0/genie/spaces",
        body={"warehouse_id": wid, "serialized_space": serialized, "title": title},
    )
    new_id = res.get("space_id")
    print(f"✓ agent ready: {new_id}")
    return new_id


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", required=True, help="Databricks CLI profile")
    ap.add_argument("--warehouse-id",
                    help="SQL warehouse the agent runs on (optional; a default is "
                         "auto-selected for a create). Not needed with --space-id.")
    ap.add_argument("--title", default="Databricks Security Audit Investigator")
    ap.add_argument("--space-id", help="Update this existing agent instead of creating one")
    args = ap.parse_args()

    if not TEMPLATE.exists():
        raise SystemExit(f"missing {TEMPLATE}")

    space_id = deploy_agent(args.profile, args.warehouse_id, args.title, args.space_id)

    print("\nNext: open Genie, find the agent, and ask")
    print('  "Who changed the IP allow list in the last 30 days?"')
    print("\nIf a query returns no rows, that action may simply not occur in this")
    print("account — check with the discovery query in agent/example_questions.md")
    print("before concluding nothing happened.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
