# Genie Agent — Databricks Workspace Security Detections

Natural-language investigation over the same audit-log logic the notebooks in
[`../base/detections/`](../base/detections/) run in batch. Ask *"who changed the
IP allow list last week?"* instead of editing widget parameters.

> **This is additive. It does not replace the notebooks.**
> The notebooks are the scheduled detection surface — run them as Workflows,
> write to an alerts table, page someone. This agent is the *interactive*
> surface for investigating what those alerts point at. Deploying the agent and
> deleting the Workflows would leave you with no continuous detection at all.

---

## Why this isn't just "point Genie at the audit table"

A Genie Agent chooses between **Trusted Assets** — per the
[docs](https://docs.databricks.com/aws/en/genie-agents/concepts), "parameterized
example queries and SQL functions whose exact logic has been verified." It cannot
call a PySpark `@detect` function, so the detections are re-expressed as UC SQL
functions here.

That re-expression is where the value is. Pointed at the raw table with no
functions, Genie will write queries that are *syntactically fine and
semantically wrong* — and during an investigation a wrong query returns **zero
rows, which reads as "nothing happened."** Two examples, both real:

- Filtering `audit_level = 'ACCOUNT_LEVEL'` for IP access list changes returns
  nothing. Verified against a live account: IP ACL mutations are emitted with
  `service_name='accounts'` and `audit_level='WORKSPACE_LEVEL'`, even though IP
  ACLs exist at account scope too.
- Asking for a "change diff" produces the submitted value only. There is **no
  previous-value column** in `system.access.audit`; a diff has to be
  reconstructed with `LAG(...)`.

The functions and the [instructions](agent/instructions.md) encode those traps so
the agent can't fall into them.

---

## Layout

```
genie-agent/
├── functions/            UC SQL functions — the Trusted Assets
│   └── 01_ip_access_and_config.sql
├── views/                semantic layer for free-form questions
├── agent/
│   ├── instructions.md        paste into the agent's Instructions field
│   ├── example_questions.md   seed the Example SQL Queries
│   └── detection_catalog.json GENERATED — do not hand-edit
├── tools/
│   └── extract_detection_metadata.py   regenerates the catalog
└── docs/
    ├── DEPLOY.md         customer install runbook
    └── PORTING.md        how to port a detection, and what can't be ported
```

## Install

Requires: Unity Catalog, a SQL warehouse, and `SELECT` on `system.access.audit`
(plus `system.query.history` for one detection). See
[docs/DEPLOY.md](docs/DEPLOY.md) for the full runbook.

```sql
CREATE SCHEMA IF NOT EXISTS <your_catalog>.security_detections;
USE CATALOG <your_catalog>;
USE SCHEMA security_detections;
-- then run each file in functions/ in order
```

Then create a Genie Agent in the UI, add the functions as Trusted Assets, and
paste [`agent/instructions.md`](agent/instructions.md) into Instructions.

**Packaging caveat, stated plainly:** the Genie Agents documentation covers
sharing *within* a Databricks account and does not document exporting an agent
for external distribution. So the agent itself is created through the UI (or the
API) against the SQL objects this folder deploys — the SQL is fully
reproducible, the agent configuration is a documented manual step. If an
export/import path ships later, `agent/` holds everything needed to automate it.

## Regenerating the catalog

`agent/detection_catalog.json` is derived from the `dscc` YAML blocks already
embedded in every detection notebook — name, objective, MITRE taxonomy,
severity, fidelity, false positives, source tables. Re-run after any notebook
metadata change:

```bash
python genie-agent/tools/extract_detection_metadata.py --repo-root . \
  --out genie-agent/agent/detection_catalog.json
```

Exits non-zero if any notebook fails to parse, so CI catches silent
under-coverage.

## Coverage

34 detections in `base/detections/` (18 behavioral, 16 event-based; 10 high /
3 medium / 21 low severity). This branch ports the **incident-response set
first** — IP access lists, security configuration changes, audit-logging
evasion, denied logins — because those are what an active investigation needs.
[docs/PORTING.md](docs/PORTING.md) tracks the rest.

One genuinely new detection came out of the port:
**`detect_ip_acl_validation_failures`** (`accountIpAclsValidationFailed`), which
no notebook covers. On the live account that surfaced it, it was the highest-volume
IP-related action — 106 events against 39 successful updates.

## What can't be ported

- **GeoIP enrichment.** `lib/common.py` provides MaxMind lookups via pandas
  UDFs, needing an `.mmdb` file on the cluster. No current detection uses it, so
  nothing is lost today — but a future GeoIP detection would need a
  pre-materialized enriched table rather than a function.
- **Batch alerting semantics.** Scheduled runs, an alerts table, and
  "avoid duplicate events on subsequent runs" are Workflow properties. Keep the
  notebooks for that.
