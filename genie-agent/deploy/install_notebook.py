# Databricks notebook source
# MAGIC %md
# MAGIC # Install the Security Detections Genie Agent
# MAGIC
# MAGIC Run this notebook from a Git folder in your own workspace. It installs
# MAGIC every detection as a Unity Catalog SQL function and creates the Genie Agent
# MAGIC that queries them.
# MAGIC
# MAGIC **No local setup.** No Databricks CLI, no Python environment, no cloning to
# MAGIC your laptop — the notebook reads the SQL from the Git folder it is running in
# MAGIC and executes it with the notebook's own credentials.
# MAGIC
# MAGIC ## Before you start
# MAGIC
# MAGIC 1. **Add this repo as a Git folder**
# MAGIC    Workspace → Create → Git folder →
# MAGIC    `https://github.com/databricks-solutions/cybersec-workspace-detection-app`
# MAGIC 2. **Open this notebook from inside that Git folder** and attach any cluster
# MAGIC    (serverless is fine).
# MAGIC 3. **Fill in the widgets** at the top: catalog, schema, and — only if you
# MAGIC    want the agent created for you — a SQL warehouse id.
# MAGIC
# MAGIC ## What you need permission to do
# MAGIC
# MAGIC | Step | Permission |
# MAGIC |---|---|
# MAGIC | Create the schema | `CREATE SCHEMA` on the catalog |
# MAGIC | Install the functions | `CREATE FUNCTION` + `USE SCHEMA` |
# MAGIC | Read audit data | `SELECT` on `system.access.audit` |
# MAGIC | Create the agent (optional) | Genie enabled; `CAN USE` on a SQL warehouse |
# MAGIC
# MAGIC If `system.access.audit` is not readable, an **account admin** must run
# MAGIC `ALTER METASTORE ENABLE SCHEMA system.access;` once per metastore. That is the
# MAGIC single most common blocker.
# MAGIC
# MAGIC ## Two things this does NOT do
# MAGIC
# MAGIC * **It does not replace the scheduled notebooks.** Those run unattended and
# MAGIC   produce alerts; this agent answers questions while you investigate. Keep
# MAGIC   both — installing this and switching those off would leave nothing watching
# MAGIC   your account.
# MAGIC * **It writes nothing to your audit data.** Every function is read-only.

# COMMAND ----------

dbutils.widgets.text("catalog", "", "1. Catalog (required)")
dbutils.widgets.text("schema", "security_detections", "2. Schema")
dbutils.widgets.text("warehouse_id", "", "3. SQL warehouse id (blank = skip agent)")
dbutils.widgets.text("space_id", "", "4. Existing agent id (blank = create new)")
dbutils.widgets.dropdown("create_agent", "yes", ["yes", "no"], "5. Create the Genie Agent?")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1 — Locate the repo files
# MAGIC
# MAGIC The notebook derives the Git folder root from its own path, so nothing is
# MAGIC hardcoded and the same notebook works wherever the customer put the folder.

# COMMAND ----------

import json
import os
import re
import uuid
from pathlib import Path

CATALOG = dbutils.widgets.get("catalog").strip()
SCHEMA = dbutils.widgets.get("schema").strip() or "security_detections"
WAREHOUSE_ID = dbutils.widgets.get("warehouse_id").strip()
SPACE_ID = dbutils.widgets.get("space_id").strip()
CREATE_AGENT = dbutils.widgets.get("create_agent") == "yes"

if not CATALOG:
    raise ValueError(
        "Set the 'catalog' widget. Use a catalog your security team owns -- anyone "
        "granted EXECUTE on these functions can read audit data through them."
    )

# Same self-location idiom lib/common.py and lib/notebook_generator_base.py use.
_nb_path = (
    dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
)
# .../<git-folder>/genie-agent/deploy/install_notebook -> the repo root is 3 up.
REPO_ROOT = Path("/Workspace" + _nb_path).parent.parent.parent
FUNCTIONS_DIR = REPO_ROOT / "genie-agent" / "functions"
AGENT_DIR = REPO_ROOT / "genie-agent" / "agent"

print(f"notebook   : {_nb_path}")
print(f"repo root  : {REPO_ROOT}")
print(f"functions  : {FUNCTIONS_DIR}")

if not FUNCTIONS_DIR.is_dir():
    raise FileNotFoundError(
        f"{FUNCTIONS_DIR} not found.\n\n"
        "This notebook must run from inside a Git folder cloned from "
        "databricks-solutions/cybersec-workspace-detection-app. If you imported "
        "just this one notebook, the SQL files are not there -- add the repo as a "
        "Git folder instead (Workspace -> Create -> Git folder)."
    )

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
# MAGIC ## Step 3 — Install the functions
# MAGIC
# MAGIC Function names are **fully qualified** from the widgets. That is deliberate: a
# MAGIC bare `CREATE FUNCTION` lands in whatever catalog the session defaults to —
# MAGIC often `hive_metastore` — and a function there cannot reference the Unity
# MAGIC Catalog table `system.access.audit`. It fails with
# MAGIC `UC_COMMAND_NOT_SUPPORTED`, an error that never mentions the session catalog.

# COMMAND ----------

spark.sql(
    f"CREATE SCHEMA IF NOT EXISTS `{CATALOG}`.`{SCHEMA}` "
    f"COMMENT 'Security detection functions for the Genie Agent'"
)
print(f"schema ready: {CATALOG}.{SCHEMA}")


def _split_statements(sql_text: str) -> list:
    """Split a function file into individual CREATE FUNCTION statements.

    Splits on ``;`` at end-of-line rather than every ``;`` -- semicolons appear
    inside COMMENT text, and splitting on those cuts a statement in half.
    """
    out = []
    for chunk in sql_text.split(";\n"):
        if "CREATE OR REPLACE FUNCTION" not in chunk:
            continue
        out.append(chunk[chunk.index("CREATE OR REPLACE FUNCTION") :].strip())
    return out


installed, failed = [], []
for path in sql_files:
    text = path.read_text(encoding="utf-8")
    text = text.replace("${CATALOG}", CATALOG).replace("${SCHEMA}", SCHEMA)
    stmts = _split_statements(text)
    print(f"\n{path.name}: {len(stmts)} function(s)")
    for stmt in stmts:
        m = re.match(r"CREATE OR REPLACE FUNCTION ([\w.`]+)\(", stmt)
        name = m.group(1).split(".")[-1].strip("`") if m else "?"
        # Belt and braces: qualify anything the placeholder pass missed, so a
        # hand-edited file cannot land a function in hive_metastore.
        if m and "." not in m.group(1):
            stmt = stmt.replace(
                f"CREATE OR REPLACE FUNCTION {m.group(1)}(",
                f"CREATE OR REPLACE FUNCTION {CATALOG}.{SCHEMA}.{m.group(1)}(",
                1,
            )
        try:
            spark.sql(stmt)
            installed.append(name)
            print(f"  OK   {name}")
        except Exception as exc:  # noqa: BLE001 - report and continue
            failed.append((name, str(exc)[:200]))
            print(f"  FAIL {name}: {str(exc)[:160]}")

print(f"\ninstalled {len(installed)}, failed {len(failed)}")
if failed:
    for n, e in failed:
        print(f"  ! {n}: {e}")
    raise SystemExit("some functions failed to install -- fix the errors above before continuing")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4 — Smoke-test
# MAGIC
# MAGIC A function returning zero rows because of a wrong filter looks identical to
# MAGIC one returning zero rows because nothing happened. Expect **some** functions to
# MAGIC be empty: on one reference workspace 19 of 33 returned data and 14 were empty
# MAGIC because those events do not occur there. That is an empty environment, not a
# MAGIC broken install.

# COMMAND ----------

# Functions with extra tuning parameters (thresholds, admin group lists) cannot be
# called with only the two timestamps. Their defaults are read from each
# function's own signature so the smoke test exercises every one, rather than
# skipping the interesting ones.
_DEFAULTS = {"STRING": "''", "INT": "5", "DOUBLE": "5.0"}


def _extra_args(fn_name: str) -> str:
    """Literal args beyond start_time/end_time, from the function's signature."""
    rows = spark.sql(
        f"DESCRIBE FUNCTION EXTENDED {CATALOG}.{SCHEMA}.{fn_name}"
    ).collect()
    body = "\n".join(str(r[0]) for r in rows)
    sig = re.search(r"\((.*?)\)\s*RETURNS", body, re.S)
    if not sig:
        return ""
    params = re.findall(r"(\w+)\s+(TIMESTAMP|STRING|INT|DOUBLE)", sig.group(1))
    extra = [p for p in params if p[0] not in ("start_time", "end_time")]
    return "".join(", " + _DEFAULTS[t] for _, t in extra)


_results = []
for fn in sorted(installed):
    try:
        args = _extra_args(fn)
        n = spark.sql(
            f"SELECT count(*) AS n FROM {CATALOG}.{SCHEMA}.{fn}("
            f"current_timestamp() - INTERVAL 90 DAYS, current_timestamp(){args})"
        ).collect()[0]["n"]
        _results.append((fn, n, None))
    except Exception as exc:  # noqa: BLE001 - report, do not abort the sweep
        _results.append((fn, None, str(exc)[:120]))

_with_data = [r for r in _results if r[1]]
_empty = [r for r in _results if r[1] == 0]
_errored = [r for r in _results if r[1] is None]

print(f"executed with data : {len(_with_data)}")
print(f"executed, empty    : {len(_empty)}  (expected -- see the note above)")
print(f"errored            : {len(_errored)}")
for fn, _, err in _errored:
    print(f"  ! {fn}: {err}")
print("\ntop results:")
for fn, n, _ in sorted(_with_data, key=lambda r: -r[1])[:10]:
    print(f"  {n:>9,}  {fn}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5 — Create the Genie Agent
# MAGIC
# MAGIC Optional. Needs a SQL warehouse id. Set `create_agent` to `no` if you only
# MAGIC want the functions, or if someone else owns agent creation.
# MAGIC
# MAGIC Two API rules are handled here because both fail obscurely:
# MAGIC `example_question_sqls` must be **sorted by a 32-char hex id** (otherwise
# MAGIC `Invalid export proto`), and reading an existing space needs
# MAGIC `include_serialized_space=true` **with CAN EDIT** — without it the field is
# MAGIC omitted *silently* rather than erroring.

# COMMAND ----------

if not CREATE_AGENT:
    print("skipping agent creation (create_agent = no)")
elif not WAREHOUSE_ID:
    print("skipping agent creation: no warehouse_id set")
    print("Functions are installed. Add them to a Genie Agent under")
    print("Configure -> Examples, or re-run this notebook with a warehouse id.")
else:
    from databricks.sdk import WorkspaceClient

    w = WorkspaceClient()
    template = AGENT_DIR / "serialized_space.template.json"
    if not template.exists():
        raise FileNotFoundError(f"{template} not found in the Git folder")

    space = json.loads(
        template.read_text(encoding="utf-8").replace(
            "${catalog}.${schema}", f"{CATALOG}.{SCHEMA}"
        )
    )

    instructions = AGENT_DIR / "instructions.md"
    if instructions.exists():
        space["instructions"]["text_instructions"] = [
            {
                "id": uuid.uuid4().hex,
                "content": instructions.read_text(encoding="utf-8").splitlines(keepends=True),
            }
        ]

    examples = space["instructions"].get("example_question_sqls", [])
    for ex in examples:
        if not re.match(r"^[0-9a-f]{32}$", str(ex.get("id", ""))):
            ex["id"] = uuid.uuid4().hex
    examples.sort(key=lambda e: e["id"])  # load-bearing: unsorted is rejected
    space["instructions"]["example_question_sqls"] = examples

    serialized = json.dumps(space, indent=2)
    print(f"space payload: {len(examples)} examples, {len(serialized):,} bytes")

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
        res = w.api_client.do(
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
                "warehouse_id": WAREHOUSE_ID,
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
