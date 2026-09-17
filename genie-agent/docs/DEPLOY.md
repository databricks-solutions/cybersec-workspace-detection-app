# Deploy runbook — Security Detections Genie Agent

Self-service install. **~2 minutes** — one Genie space create, no Unity Catalog
DDL.

The agent embeds every detection as a **parameterized example query** (the SQL is
inlined into the space from [`../functions/`](../functions/) at build time), so
there is nothing to create in Unity Catalog and no `CREATE FUNCTION` /
`CREATE SCHEMA` privilege to arrange. `functions/*.sql` stays the single source of
truth for the verified logic; the batch/scheduled notebooks under `base/` are
unaffected.

**Two paths, same result:**
- **Install notebook** (`genie-agent/deploy/install_notebook`, run from a Git
  folder) — no CLI, no local Python. Recommended.
- **CLI** — `python genie-agent/deploy/install.py --profile <cli-profile>`. Needs
  the Databricks CLI and this repo checked out locally.

Both are re-runnable; pass an existing space id to update in place.

## Prerequisites

| Requirement | Why | Check |
|---|---|---|
| Unity Catalog enabled | Genie Agents work on data registered to Unity Catalog | `SELECT current_metastore()` |
| A SQL warehouse | The agent runs its queries through it (a default is auto-selected) | Serverless is fine |
| `SELECT` on `system.access.audit` | Every detection reads it | query below |
| `SELECT` on `system.query.history` | One detection reads it | query below |
| Genie enabled + `CAN USE` on a warehouse | To create and run the agent | — |

No `CREATE FUNCTION`, `CREATE SCHEMA`, or `USE SCHEMA` is needed — the agent
embeds the SQL rather than creating catalog objects.

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

## Step 2 — Create the agent

**Notebook path.** Add this repo as a Git folder, open
`genie-agent/deploy/install_notebook` from inside it, attach serverless compute,
and Run All. Leave the warehouse widget blank to auto-select one; set
`create_agent = no` if someone else owns agent creation.

**CLI path.**

```bash
python genie-agent/deploy/install.py --profile <cli-profile>
# optional: --warehouse-id <id>   (else a default is auto-selected)
# update in place:  --space-id <existing-space-id>
```

Both build the space from the template, inline every detection from
`functions/*.sql` as an embedded example query, refresh the instructions from
`agent/instructions.md`, and create (or update) the Genie space. The installer
prints the space id.

## Step 3 — Validate

Ask the agent, in plain language:

- *"Who changed the IP allow list in the last 30 days?"* → must use the trusted
  `detect_ip_access_list_changes` example query, not hand-write a query filtering
  `audit_level='ACCOUNT_LEVEL'`
- *"Show me the before and after IP values"* → must say the CIDRs are **not in the
  audit log** and point at the REST API, NOT invent an empty diff
- *"Did anyone disable audit logging?"* → must surface the `CRITICAL` severity row

If it hand-writes SQL instead of using a trusted example query, that query's
`Use for:` phrasings do not match how you ask. Extend them — expected tuning, not
a defect. See [`PORTING.md`](PORTING.md) for how the embedded queries are built.

## Keep the notebooks running

This agent is for **investigation**. It does not run on a schedule, does not write
to an alerts table, and cannot page anyone. Continue running the
`base/detections/` notebooks as Workflows for continuous detection — the agent is
how you investigate what those alerts surface.

## Access model

- The embedded queries **read** audit data and write nothing.
- Genie queries run as the **asking user**, so a user only sees what their own
  grants on `system.access.audit` allow. Grant access to the Genie space, and
  audit-log read access, only to identities entitled to see audit data.
- Audit data contains user emails, source IPs and user agents — personal data
  under most privacy regimes. Apply your existing retention and access policy.
