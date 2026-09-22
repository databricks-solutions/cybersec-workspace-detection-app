# Databricks notebook source
# MAGIC %md
# MAGIC # Install the Security Detections Genie Agent
# MAGIC
# MAGIC Run this notebook from a Git folder in your own workspace. It creates the
# MAGIC Genie Agent with every detection embedded as a parameterized example query —
# MAGIC **no Unity Catalog functions, no schema, no DDL**.
# MAGIC
# MAGIC **No local setup.** No Databricks CLI, no Python environment, no cloning to
# MAGIC your laptop — the notebook reads the SQL from the Git folder it is running in
# MAGIC and builds the agent with the notebook's own credentials.
# MAGIC
# MAGIC ## Before you start
# MAGIC
# MAGIC 1. **Add this repo as a Git folder**
# MAGIC    Workspace → Create → Git folder →
# MAGIC    `https://github.com/databricks-solutions/cybersec-workspace-detection-app`
# MAGIC    Leave *Sparse checkout* unchecked — this notebook reads sibling files from
# MAGIC    `genie-agent/functions/`, `genie-agent/agent/`, and `genie-agent/tools/`.
# MAGIC 2. **Open this notebook from inside that Git folder.** Attach compute —
# MAGIC    **Serverless works** and is the simplest choice.
# MAGIC 3. **Fill in the widgets** at the top: a SQL warehouse id is optional (blank =
# MAGIC    auto-select one for the agent to run on).
# MAGIC
# MAGIC ## What you need permission to do
# MAGIC
# MAGIC | Step | Permission |
# MAGIC |---|---|
# MAGIC | Read audit data (preflight) | `SELECT` on `system.access.audit` |
# MAGIC | Create the agent | Genie enabled; `CAN USE` on a SQL warehouse |
# MAGIC
# MAGIC No `CREATE SCHEMA` or `CREATE FUNCTION` is needed — the agent embeds the
# MAGIC detection SQL, it does not create catalog objects. If `system.access.audit` is
# MAGIC not readable, an **account admin** must run
# MAGIC `ALTER METASTORE ENABLE SCHEMA system.access;` once per metastore — the single
# MAGIC most common blocker.
# MAGIC
# MAGIC ## Two things this does NOT do
# MAGIC
# MAGIC * **It does not replace the scheduled notebooks.** Those run unattended and
# MAGIC   produce alerts; this agent answers questions while you investigate. Keep
# MAGIC   both — installing this and switching those off would leave nothing watching
# MAGIC   your account.
# MAGIC * **It writes nothing to your audit data.** Every embedded query is read-only.

# COMMAND ----------

dbutils.widgets.text("warehouse_id", "", "1. SQL warehouse id (blank = auto-select)")
dbutils.widgets.text("space_id", "", "2. Existing agent id (blank = create new)")
dbutils.widgets.dropdown("create_agent", "yes", ["yes", "no"], "3. Create the Genie Agent?")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1 — Locate the repo files
# MAGIC
# MAGIC The notebook derives the Git folder root from its own path, so nothing is
# MAGIC hardcoded and the same notebook works wherever the customer put the folder.

# COMMAND ----------

import json
import re
import sys
import uuid
from pathlib import Path

WAREHOUSE_ID = dbutils.widgets.get("warehouse_id").strip()
SPACE_ID = dbutils.widgets.get("space_id").strip()
CREATE_AGENT = dbutils.widgets.get("create_agent") == "yes"

# Same self-location idiom lib/common.py and lib/notebook_generator_base.py use.
_nb_path = (
    dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
)
# .../<git-folder>/genie-agent/deploy/install_notebook -> the repo root is 3 up.
REPO_ROOT = Path("/Workspace" + _nb_path).parent.parent.parent
GENIE_DIR = REPO_ROOT / "genie-agent"
FUNCTIONS_DIR = GENIE_DIR / "functions"
AGENT_DIR = GENIE_DIR / "agent"
TOOLS_DIR = GENIE_DIR / "tools"

print(f"notebook   : {_nb_path}")
print(f"repo root  : {REPO_ROOT}")
print(f"functions  : {FUNCTIONS_DIR}")

if not FUNCTIONS_DIR.is_dir() or not TOOLS_DIR.is_dir():
    raise FileNotFoundError(
        f"{FUNCTIONS_DIR} not found.\n\n"
        "This notebook must run from inside a Git folder cloned from "
        "databricks-solutions/cybersec-workspace-detection-app. If you imported "
        "just this one notebook, the SQL and tools files are not there -- add the "
        "repo as a Git folder instead (Workspace -> Create -> Git folder)."
    )

# The inliner that turns functions/*.sql into embedded example queries.
sys.path.insert(0, str(TOOLS_DIR))
from inline_functions import build_example_sqls  # noqa: E402

sql_files = sorted(FUNCTIONS_DIR.glob("*.sql"))
print(f"\nfound {len(sql_files)} SQL file(s): {[f.name for f in sql_files]}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2 — Check what you can see
# MAGIC
# MAGIC Do this before installing: it decides how much you can trust every answer
# MAGIC afterwards. If verbose audit logging was ever off, events in that period were
# MAGIC never recorded and **no tool can recover them**.

# COMMAND ----------

try:
    _range = spark.sql(
        "SELECT min(event_time) AS earliest, max(event_time) AS latest, "
        "count(*) AS events FROM system.access.audit"
    ).collect()[0]
    print(f"audit data: {_range['events']:,} events")
    print(f"  from {_range['earliest']}")
    print(f"  to   {_range['latest']}")
except Exception as exc:  # noqa: BLE001 - surface the real cause, do not mask it
    raise SystemExit(
        f"Cannot read system.access.audit: {exc}\n\n"
        "An account admin must run, once per metastore:\n"
        "    ALTER METASTORE ENABLE SCHEMA system.access;\n"
        "You also need SELECT on system.access.audit."
    )

_gaps = spark.sql(
    """
    SELECT event_time, user_identity.email AS who,
           request_params['workspaceConfValues'] AS set_to
    FROM system.access.audit
    WHERE action_name = 'workspaceConfEdit'
      AND request_params['workspaceConfKeys'] = 'enableVerboseAuditLogs'
    ORDER BY event_time DESC LIMIT 20
    """
)
_off = [r for r in _gaps.collect() if str(r["set_to"]).lower() == "false"]
if _off:
    print("\n*** VISIBILITY GAP ***")
    for r in _off:
        print(f"  verbose audit logging set to false at {r['event_time']} by {r['who']}")
    print("  Events in that period may never have been recorded. Note the dates:")
    print("  they bound what any investigation can conclude. Re-enable it.")
else:
    print("\nno verbose-audit-logging disable events found in the recent history")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3 — Build the agent's embedded queries
# MAGIC
# MAGIC Each detection in `functions/*.sql` is inlined into the space as a
# MAGIC parameterized example query (`:start_time` / `:end_time`, plus any threshold).
# MAGIC Nothing is created in Unity Catalog. `functions/*.sql` stays the single source
# MAGIC of truth; the same inliner backs the CLI installer.

# COMMAND ----------

template = AGENT_DIR / "serialized_space.template.json"
if not template.exists():
    raise FileNotFoundError(f"{template} not found in the Git folder")

space = json.loads(template.read_text(encoding="utf-8"))

instructions = AGENT_DIR / "instructions.md"
if instructions.exists():
    space["instructions"]["text_instructions"] = [
        {"id": uuid.uuid4().hex,
         "content": instructions.read_text(encoding="utf-8").splitlines(keepends=True)}
    ]

examples = space["instructions"].get("example_question_sqls", [])
build_example_sqls(FUNCTIONS_DIR, examples)  # detect_x() wrappers -> inlined SQL
for ex in examples:
    if not re.match(r"^[0-9a-f]{32}$", str(ex.get("id", ""))):
        ex["id"] = uuid.uuid4().hex
examples.sort(key=lambda e: e["id"])  # load-bearing: the API rejects an unsorted list
space["instructions"]["example_question_sqls"] = examples

serialized = json.dumps(space, indent=2)
print(f"built space payload: {len(examples)} embedded queries, {len(serialized):,} bytes")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4 — Smoke-test the embedded queries
# MAGIC
# MAGIC Run each embedded query for the last 90 days. A query returning zero rows
# MAGIC because of a wrong filter looks identical to one returning zero because nothing
# MAGIC happened — so expect **some** empties: on one reference workspace ~20 of 33
# MAGIC returned data and the rest were empty because those events do not occur there.
# MAGIC That is an empty environment, not a broken build.

# COMMAND ----------

# Named parameters (:start_time / :end_time) bind through spark.sql(args=...).
_args = {
    "start_time": "2000-01-01T00:00:00Z",  # placeholders overwritten below
    "end_time": "2000-01-01T00:00:00Z",
}
_win = spark.sql(
    "SELECT current_timestamp() - INTERVAL 90 DAYS AS s, current_timestamp() AS e"
).collect()[0]
_args = {"start_time": _win["s"], "end_time": _win["e"]}

results = []
for ex in examples:
    q = "".join(ex["sql"]) if isinstance(ex["sql"], list) else ex["sql"]
    label = ("".join(ex["question"]) if isinstance(ex["question"], list)
             else ex["question"])
    try:
        n = spark.sql(q, args=_args).count()
        results.append((label, n, None))
    except Exception as exc:  # noqa: BLE001 - report, do not abort the sweep
        results.append((label, None, str(exc)[:160]))

_with_data = [r for r in results if r[1]]
_empty = [r for r in results if r[1] == 0]
_errored = [r for r in results if r[1] is None]

print(f"executed with data : {len(_with_data)}")
print(f"executed, empty    : {len(_empty)}  (expected -- see the note above)")
print(f"errored            : {len(_errored)}")
for label, _, err in _errored:
    print(f"  ! {label}: {err}")
if _errored:
    # Do NOT abort the install. The usual cause is a missing OPTIONAL grant --
    # detect_data_movement_sql_queries reads system.query.history, a separate
    # prerequisite (see DEPLOY.md) you may not have granted. Those detections
    # simply return nothing until the grant is in place; every other detection,
    # and agent creation in Step 5, is unaffected.
    print("\n! Some embedded queries errored above -- this does NOT block agent")
    print("  creation. Most often it is a missing SELECT on system.query.history")
    print("  (an optional, separate prerequisite). Grant it if you want those")
    print("  detections to return results; otherwise continue.")
print("\ntop results:")
for label, n, _ in sorted(_with_data, key=lambda r: -r[1])[:10]:
    print(f"  {n:>9,}  {label}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5 — Create the Genie Agent
# MAGIC
# MAGIC Optional. Set `create_agent` to `no` if someone else owns agent creation.
# MAGIC A SQL warehouse is auto-selected if the widget is blank (the space runs its
# MAGIC queries there). Reading an existing space to update it needs
# MAGIC `include_serialized_space=true` **with CAN EDIT** — without it the field is
# MAGIC omitted *silently* rather than erroring.

# COMMAND ----------

if not CREATE_AGENT:
    print("skipping agent creation (create_agent = no)")
else:
    from databricks.sdk import WorkspaceClient

    w = WorkspaceClient()

    warehouse_id = WAREHOUSE_ID
    if not warehouse_id:
        # Auto-pick: prefer a RUNNING serverless warehouse, then any RUNNING, then any.
        whs = list(w.warehouses.list())
        if not whs:
            raise SystemExit(
                "no SQL warehouse found. Create one, or set the warehouse_id widget."
            )
        def _score(wh):
            running = getattr(wh, "state", None) and str(wh.state).endswith("RUNNING")
            serverless = getattr(wh, "enable_serverless_compute", False)
            return (bool(running), bool(serverless))
        best = max(whs, key=_score)
        warehouse_id = best.id
        print(f"auto-selected warehouse {warehouse_id} ({best.name}, state={best.state})")

    if SPACE_ID:
        current = w.api_client.do(
            "GET", f"/api/2.0/genie/spaces/{SPACE_ID}?include_serialized_space=true"
        )
        etag = current.get("etag")
        if not etag:
            raise SystemExit(
                f"No etag returned for space {SPACE_ID}. include_serialized_space "
                "requires CAN EDIT on the space; without it the field is omitted "
                "silently rather than erroring."
            )
        w.api_client.do(
            "PATCH",
            f"/api/2.0/genie/spaces/{SPACE_ID}",
            body={"serialized_space": serialized, "etag": etag},
        )
        space_id = SPACE_ID
        print(f"updated existing agent {space_id}")
    else:
        res = w.api_client.do(
            "POST",
            "/api/2.0/genie/spaces",
            body={
                "warehouse_id": warehouse_id,
                "serialized_space": serialized,
                "title": "Databricks Security Audit Investigator",
            },
        )
        space_id = res.get("space_id")
        print(f"created agent {space_id}")

    host = spark.conf.get("spark.databricks.workspaceUrl", "<your-workspace>")
    print(f"\nOpen it: https://{host}/genie/rooms/{space_id}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Done — try these
# MAGIC
# MAGIC * *Who changed the IP allow list in the last 30 days?*
# MAGIC * *Who created personal access tokens, and how long do they live?*
# MAGIC * *Was there any bulk notebook export?*
# MAGIC * *Did anyone disable audit logging?*
# MAGIC
# MAGIC **Read "no results" carefully.** It can mean the event did not happen, the
# MAGIC window missed it, verbose audit logging was off, or the action is named
# MAGIC differently in your account. The agent is instructed to say *"no matching
# MAGIC events found"* rather than *"this did not happen"* — hold it to that, and
# MAGIC hold yourself to it when reporting to someone else.
# MAGIC
# MAGIC **One limit worth knowing up front:** ask for the before/after IP values on an
# MAGIC allow-list change and the agent will tell you the CIDRs are **not in the audit
# MAGIC log** and point you at `GET /api/2.0/ip-access-lists`. That is correct —
# MAGIC `request_params` carries only the list id and the user id. Historical values
# MAGIC are not recoverable from audit data at all.
# MAGIC
# MAGIC Full limits: `genie-agent/README.md` section 7.
