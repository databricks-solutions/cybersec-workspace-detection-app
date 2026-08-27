# Deploy runbook — Security Detections Genie Agent

Self-service install. ~20 minutes.

**Two paths.** The **install notebook** (`genie-agent/deploy/install_notebook`, run
from a Git folder) is recommended -- no CLI, no local Python. The steps below are
the manual/CLI equivalent, for workspaces that cannot reach GitHub or where you
want to see each step. Both are re-runnable and produce the same result.

## Prerequisites

| Requirement | Why | Check |
|---|---|---|
| Unity Catalog enabled | Genie Agents work on "data registered to Unity Catalog"; SQL functions are UC objects | `SELECT current_metastore()` |
| A SQL warehouse | The agent executes queries through it | Serverless is fine |
| `SELECT` on `system.access.audit` | Every detection reads it | query below |
| `SELECT` on `system.query.history` | One detection reads it | query below |
| `CREATE FUNCTION` + `USE SCHEMA` on a target schema | To install the functions | — |

Verify audit access before anything else — this is the most common blocker:

```sql
SELECT count(*) FROM system.access.audit
WHERE event_time >= current_timestamp() - INTERVAL 1 DAY;
```

If that errors, an account admin must enable the system schema:

```sql
-- account admin, once per metastore
ALTER METASTORE ENABLE SCHEMA system.access;
```

## Step 1 — Check your audit visibility

Do this **before** installing, because it determines what the agent can tell you.

```sql
-- Is verbose audit logging on? Without it, workspaceConfEdit and
-- notebook-level actions may never be recorded at all.
SELECT event_time, user_identity.email AS actor,
       request_params['workspaceConfKeys']   AS setting,
       request_params['workspaceConfValues'] AS value
FROM system.access.audit
WHERE action_name = 'workspaceConfEdit'
  AND request_params['workspaceConfKeys'] = 'enableVerboseAuditLogs'
ORDER BY event_time DESC LIMIT 20;
```

A `false` value means there is a visibility gap from that timestamp onward. Note
the date — it bounds what any investigation can conclude. Enable verbose audit
logging before relying on this agent for coverage.

Then see how far back your data goes:

```sql
SELECT min(event_time) AS earliest, max(event_time) AS latest, count(*) AS events
FROM system.access.audit;
```

## Step 2 — Create the schema

```sql
CREATE SCHEMA IF NOT EXISTS <your_catalog>.security_detections
  COMMENT 'Security detection functions for the Genie Agent. Source: cybersec-workspace-detection-app';
```

Use a catalog your security team owns. The functions read `system.access.audit`
and write nothing, but **anyone granted `EXECUTE` can read audit data through
them** — so scope grants to your security team, not to `account users`.

## Step 3 — Install the functions

```sql
USE CATALOG <your_catalog>;
USE SCHEMA security_detections;
```

Run each file in [`../functions/`](../functions/) in filename order. Then confirm:

```sql
SHOW USER FUNCTIONS IN <your_catalog>.security_detections;
```

## Step 4 — Smoke-test before wiring up the agent

A function that returns zero rows because of a wrong filter looks identical to
one that returns zero rows because nothing happened. Test with a window you know
contains activity:

```sql
SELECT * FROM detect_config_changes_high_priority(
  current_timestamp() - INTERVAL 90 DAYS, current_timestamp())
ORDER BY event_time DESC LIMIT 20;
```

If empty, run the discovery query from
[`../agent/example_questions.md`](../agent/example_questions.md) to see which
action names exist in your environment. Absence of rows is not evidence of
absence of events.

Cross-check one function against its source notebook on the same window and
confirm the row counts match. That is the real acceptance test for the port.

## Step 5 — Create the Genie Agent

In the Databricks UI:

1. **Genie** → create a new agent, named e.g. *Databricks Security Detections*
2. **Data** — add `system.access.audit` and `system.query.history`
3. **Trusted Assets** — add every function from
   `<your_catalog>.security_detections`
4. **Instructions** — paste [`../agent/instructions.md`](../agent/instructions.md)
   verbatim. It encodes the traps that otherwise produce confidently wrong,
   empty answers
5. **Example SQL Queries** — add from
   [`../agent/example_questions.md`](../agent/example_questions.md), replacing
   `<catalog>`
6. **Benchmarks** — seed with the three cases at the end of that file: the
   questions where a wrong query returns zero rows rather than an error

## Step 6 — Validate

Ask the agent, in plain language:

- *"Who changed the IP allow list in the last 30 days?"* → must call
  `detect_ip_access_list_changes`, not hand-write a query filtering
  `audit_level='ACCOUNT_LEVEL'`
- *"Show me the before and after IP values"* → must say the CIDRs are **not in
  the audit log** and point at the REST API, NOT invent an empty diff
- *"Did anyone disable audit logging?"* → must surface the `CRITICAL` severity row

If it hand-writes SQL instead of calling a function, the function's `Use for:`
phrasings do not match how you ask. Extend them — that is expected tuning, not a
defect.

## Keep the notebooks running

This agent is for **investigation**. It does not run on a schedule, does not
write to an alerts table, and cannot page anyone. Continue running the
`base/detections/` notebooks as Workflows for continuous detection — the agent
is how you investigate what those alerts surface.

## Access model

- The functions **read** audit data and write nothing.
- `EXECUTE` on a function lets the grantee read whatever that function selects —
  treat it as granting audit-log read access.
- Genie queries run as the **asking user**, so grant `EXECUTE` only to
  identities entitled to see audit data.
- Audit data contains user emails, source IPs and user agents — personal data
  under most privacy regimes. Apply your existing retention and access policy.
