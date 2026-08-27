# Ask your Databricks audit logs questions in plain English

This folder turns the security detections in this repo into a **Genie Agent** —
so you can type

> *"Who changed our IP allow list last week?"*

instead of writing SQL or editing notebook parameters.

Built for security analysts and incident responders. **No Databricks expertise
required** — if you can create a schema and run a SQL file, you can install this.
Everything you need is below, in order.

---

## Contents

1. [Is this for me?](#1-is-this-for-me)
2. [What you need before you start](#2-what-you-need-before-you-start)
3. [Install (about 20 minutes)](#3-install-about-20-minutes)
4. [Create the agent](#4-create-the-agent)
5. [Check it works](#5-check-it-works)
6. [Questions you can ask](#6-questions-you-can-ask)
7. [**Limits you must know before trusting an answer**](#7-limits-you-must-know-before-trusting-an-answer)
8. [Troubleshooting](#8-troubleshooting)
9. [Who can see what](#9-who-can-see-what)
10. [For maintainers](#10-for-maintainers)

---

## 1. Is this for me?

**Yes, if** you investigate security questions about your Databricks account —
who changed a setting, who was blocked, what happened during an incident — and
you would rather ask a question than write SQL.

**This does not replace the notebooks in [`../base/detections/`](../base/detections/).**
Those run on a schedule and produce alerts. This agent answers questions when you
are investigating. You want both:

| | Notebooks (`../base/detections/`) | This agent |
|---|---|---|
| Runs | On a schedule, unattended | When you ask |
| Output | Rows in an alerts table | An answer in a chat window |
| Good for | *Noticing* something happened | *Investigating* what happened |
| Can page you | Yes | No |

If you install the agent and switch the scheduled notebooks off, **nothing will
be watching your account.** Keep them running.

---

## 2. What you need before you start

| # | Requirement | How to check |
|---|---|---|
| 1 | Unity Catalog enabled | Run `SELECT current_metastore()` — an error means it is not |
| 2 | A SQL warehouse | Any size. Serverless is easiest |
| 3 | Access to audit logs | Query below |
| 4 | Permission to create a schema | Ask your Databricks admin for `CREATE SCHEMA` on a catalog |
| 5 | A Git folder, **or** the Databricks CLI | Git folder is easiest; CLI is the fallback if your workspace cannot reach GitHub |

**Check #3 now** — it blocks more installs than anything else. In a SQL editor:

```sql
SELECT count(*) AS events_last_24h
FROM system.access.audit
WHERE event_time >= current_timestamp() - INTERVAL 1 DAY;
```

- **A number** → you are good.
- **An error like `Table or view not found`** → your account admin must enable
  the system schema, once per metastore:
  ```sql
  ALTER METASTORE ENABLE SCHEMA system.access;
  ```
- **`0`** → the schema is enabled but empty. Audit data can take up to a few
  hours to appear after enablement.

---

## 3. Install (about 20 minutes)

### Step 3.1 — Find out what you can actually see

Do this **first**. It tells you whether your audit trail has gaps, which changes
how much you can trust every answer afterwards.

```sql
-- How far back does your audit data go?
SELECT min(event_time) AS earliest, max(event_time) AS latest, count(*) AS events
FROM system.access.audit;
```

```sql
-- Has anyone turned OFF verbose audit logging?
-- If so, some events after that moment were never recorded at all.
SELECT event_time,
       user_identity.email                   AS who,
       request_params['workspaceConfValues'] AS set_to
FROM system.access.audit
WHERE action_name = 'workspaceConfEdit'
  AND request_params['workspaceConfKeys'] = 'enableVerboseAuditLogs'
ORDER BY event_time DESC
LIMIT 20;
```

If `set_to` is `false` anywhere, **write down that date.** From then until it was
re-enabled, your logs are incomplete — and no tool can recover what was never
written. Turn verbose audit logging back on before relying on this agent.

### Step 3.2 — Install everything

**Recommended: run the install notebook from a Git folder.** No Databricks CLI, no
local Python, nothing cloned to your laptop.

1. **Workspace → Create → Git folder** →
   `https://github.com/databricks-solutions/cybersec-workspace-detection-app`
2. Open **`genie-agent/deploy/install_notebook`** from inside that Git folder
3. Attach any cluster (serverless is fine) and fill in the widgets:
   - **catalog** — a catalog your security team owns *(required)*
   - **schema** — defaults to `security_detections`
   - **warehouse_id** — only if you want the agent created for you; leave blank to
     install functions only
4. **Run all**

The notebook finds the SQL files from its own path, so nothing is hardcoded and it
works wherever you put the Git folder. It also checks your audit visibility
*before* installing and tells you if verbose audit logging was ever disabled.

**Alternative: the CLI installer.** Use this if your workspace cannot reach GitHub
(egress restrictions, no Git folder support, air-gapped):

```bash
python genie-agent/deploy/install.py \
  --profile <your-cli-profile> \
  --catalog main \
  --warehouse-id <your-sql-warehouse-id>
```

Requires the Databricks CLI configured locally, and a clone of this repo. Same
result — it just runs from your machine instead of the workspace.

Both are re-runnable: functions are `CREATE OR REPLACE`, and `--space-id` (CLI) or
the `space_id` widget (notebook) updates an existing agent rather than creating a
second one. Re-run either after a `git pull`.

Use a catalog your security team owns. The functions only read audit data, but
**anyone granted `EXECUTE` can read audit data through them**, so scope grants to
your security team rather than `account users`.

**If you install by hand instead**, run each file in [`functions/`](functions/)
after find-and-replacing `${CATALOG}` and `${SCHEMA}`. **Replace the placeholders —
do not substitute a leading `USE CATALOG`.** A bare `CREATE FUNCTION` lands in
whatever catalog the session defaults to, often `hive_metastore`, and a function
there cannot reference the Unity Catalog table `system.access.audit`. It fails with
`UC_COMMAND_NOT_SUPPORTED`, an error that never mentions the session catalog.

### Step 3.3 — Confirm and smoke-test

The notebook does this for you (step 4 of the notebook). Manually:

```sql
SHOW USER FUNCTIONS IN main.security_detections;   -- expect 33

SELECT * FROM main.security_detections.detect_config_changes_high_priority(
  current_timestamp() - INTERVAL 90 DAYS, current_timestamp())
ORDER BY event_time DESC LIMIT 20;
```

Rows → working. No rows → not necessarily broken; see
[Troubleshooting](#8-troubleshooting).

## 4. Create the agent

`install.py` does this for you. This section is for doing it by hand, or for
understanding what the script created.

In the Databricks UI:

1. **Genie** → create a new agent, e.g. *Databricks Security Audit Investigator*
2. **Sources** → add `system.access.audit` (and `system.query.history` if you want
   `detect_data_movement_sql_queries`). Note the Sources picker lists **tables and
   views only** — your functions will not appear here, and that is expected.
3. **Configure → Instructions** → paste
   [`agent/instructions.md`](agent/instructions.md) in full
4. **Configure → Examples** → this is where the SQL functions go. There is no
   one-click "add function": each one is a saved parameterised query. Per
   function you supply a name, a `SELECT * FROM <catalog>.<schema>.<fn>(:start_time,
   :end_time)` body, both parameters as **Date and Time**, and Usage Guidance
   text. Budget a couple of minutes each — which is the main reason `install.py`
   exists.
5. Save, and share with your security team

The docs call these **Trusted Assets**; the UI label is **Examples**. Same thing.

## 5. Check it works

Ask the agent these three, in order:

| Ask | You should get |
|---|---|
| *"Who changed the IP allow list in the last 30 days?"* | A table of changes, or a clear "no matching events found" |
| *"Did anyone disable audit logging?"* | Either a `CRITICAL` row, or a clear "no" |
| *"Show me blocked login attempts this month"* | Identities and IPs that were denied |

If the agent writes its own SQL instead of using a `detect_*` function, its
description didn't match your phrasing. That's normal tuning — add your wording
to the function's `Use for:` list, or add an Example SQL Query.

---

## 6. Questions you can ask

**33 functions covering all 35 detections in this repo.** By theme:

**IP access & network** — who changed the IP allow list; who deleted a list;
failed attempts to change IP rules; who was blocked and what they were reaching
for.

**Identity & privilege** — who was made account, workspace or metastore admin;
new user accounts; deleted accounts; account attribute and role changes; password
changes; MFA keys added or removed; group creation, deletion and membership.

**Credentials** — who created a personal access token and how long it lives;
revoked tokens; tokens presenting from many IPs (leaked-token signal); credential
scanners like TruffleHog.

**Authentication** — logins that bypassed SSO; Databricks employee (support)
access; SSO/IdP configuration changes.

**Data movement** — new storage credentials, mounts and external connections;
`COPY INTO` with inline credentials; download and export volume per user; bulk
notebook export scored against each principal's own history (source-code
exfiltration).

**Secrets** — identities that enumerate secret scopes *and* read many distinct
secrets (the discovery pattern, not just normal reads).

**Sessions** — one identity from many IPs; one session used from multiple
devices (the strongest hijacking signal); many sessions from one IP.

**Evasion** — was verbose audit logging disabled, and when did it come back on.

**Configuration** — the security-relevant subset, the complete workspace
changelog, and account-level settings with their new values.

**Pivots** — what else did this user do that day; what else came from this IP;
which changes came from automation rather than the console (`user_agent`
distinguishes Terraform/CLI/SDK from a person clicking).

More in [`agent/example_questions.md`](agent/example_questions.md).

**Expect some functions to return nothing**, and read that carefully. In one
reference account 19 of 33 returned data and 14 were empty — because those events
simply do not occur there, not because the function is broken. See
[Limits](#7-limits-you-must-know-before-trusting-an-answer).

## 7. Limits you must know before trusting an answer

Read this section. These are not edge cases — they change what you can honestly
tell your leadership or your customer.

### "No results" does not mean "it didn't happen"

An empty answer can mean any of: it didn't happen, your time window missed it,
verbose audit logging was off, or the event isn't recorded under the name
expected. The agent is instructed to say *"no matching events found"* rather than
*"this did not happen"* — hold it to that, and hold yourself to it when
reporting.

### Audit logs do not contain your IP allow list values

**This surprises people, so it is worth being blunt.** When someone changes an IP
access list, Databricks records *that the list changed, who changed it, when, and
from where* — but **not the IP addresses themselves.**

Verified against a live account across all 54 IP access list changes in a 90-day
window: the event carries exactly two fields, the list's id and the user's id.
No IP ranges, no before value, no after value.

So you **can** answer:
- ✅ Who changed an IP access list, when, from what IP, using what client
- ✅ Which list (by id) was created, modified or deleted
- ✅ Whether it succeeded

You **cannot** answer from audit logs alone:
- ❌ Which IP ranges were added or removed
- ❌ What the list contained before the change

To get current IP ranges, call the IP Access Lists REST API
(`GET /api/2.0/ip-access-lists`) and match on the list id from the changelog.
**Historical values are not recoverable** — if you need them, start capturing
list contents on a schedule now.

*If someone asks you for a "config diff" of IP allow lists: you can give them a
complete changelog of who-and-when, plus the list contents as they are today. You
cannot give them the before/after IP values for a past change. Say so early.*

### There is no "previous value" for most changes

Audit logs record what was *submitted*, not a before/after pair. Account-level
settings are the exception — those carry `settingValueForAudit`, the new value.

### Severity is a hint, not a verdict

`HIGH` means "look at this first," not "this was an attack." Administrators
legitimately change IP access lists and settings all the time. Every detection
has expected false positives.

### Timestamps are UTC

All of them. Convert before comparing against anything local.

---

## 8. Troubleshooting

**"Table or view not found: system.access.audit"**
The system schema isn't enabled. An account admin runs
`ALTER METASTORE ENABLE SCHEMA system.access;`

**"PERMISSION_DENIED on system.access.audit"**
You need `SELECT` on it. Ask your metastore admin.

**A function returns no rows, and you expected some**
Don't assume it's broken. Check what exists in your environment:

```sql
SELECT audit_level, service_name, action_name, count(*) AS events
FROM system.access.audit
WHERE event_time >= current_timestamp() - INTERVAL 30 DAYS
GROUP BY 1, 2, 3
ORDER BY events DESC;
```

If the action you expected isn't listed, it didn't happen in that window — or
wasn't logged (see verbose audit logging, above).

**The agent answers with its own SQL instead of a function**
Its phrasing match failed. Add your wording to the function's `Use for:` list in
the SQL, re-run the file, and refresh the agent's Trusted Assets.

**The agent gives a confident but wrong-looking answer**
Ask it to show the SQL it ran. If it wrote its own instead of calling a
`detect_*` function, that's the cause — see above. Verify the Instructions were
pasted in full.

---

## 9. Who can see what

- The functions **only read** audit data. They change nothing.
- Granting `EXECUTE` on a function grants the ability to read audit data through
  it. Grant it to your security team, **not** to `account users`.
- Genie runs queries **as the person asking**, so they also need `SELECT` on
  `system.access.audit`.
- Audit logs contain user emails, IP addresses and user agents — personal data
  under most privacy regimes. Apply your existing access and retention policy.

---

## 10. For maintainers

Layout:

```
genie-agent/
├── functions/     33 UC SQL functions (4 themed files)
├── agent/         instructions, example questions, serialized_space template
├── deploy/        install_notebook (recommended) + install.py (CLI fallback)
├── tools/         metadata extractor
└── docs/          DEPLOY.md (terse runbook), PORTING.md (what was ported + traps)
```

**Why SQL functions and not the notebooks.** A Genie Agent selects between
Trusted Assets — "parameterized example queries and SQL functions whose exact
logic has been verified" — and cannot call a PySpark `@detect` function. So the
detections are re-expressed as UC SQL. Confirmed while surveying the set: no
detection uses `lib/common.py`'s GeoIP/pandas-UDF helpers, so all 34 are
SQL-portable.

**Regenerate the detection catalog** after editing any notebook's metadata:

```bash
python genie-agent/tools/extract_detection_metadata.py --repo-root . \
  --out genie-agent/agent/detection_catalog.json
```

Exits non-zero if a notebook fails to parse, so CI catches silent under-coverage.

**Verification status.** All 33 functions were installed and executed against a
live workspace (SFE, 90-day window, 2026-08-26): 33/33 created, 33/33 executed
without error, 19 returning data and 14 legitimately empty. Every
`request_params` key is verified against live data rather than the REST API docs —
they differ, and a wrong key returns NULL rather than erroring. Keys are listed at
the top of each SQL file.

**Coverage: 35/35 detections in 33 functions.** Fewer functions than detections
because four near-identical notebooks were merged into two: `mfa_key_added` +
`mfa_key_deleted` → `detect_mfa_key_changes`, and the four group notebooks →
`detect_group_changes`. Genie selects better from one well-described function than
from several near-duplicates, and both directions of a change answer the same
investigative question.

**Two deliberate deviations from the notebooks**, both documented inline:
`detect_admin_sql_activity_spike` reports a threshold count rather than the
notebook's normalised *rate* (a stateless function has no baseline window to
normalise against, and faking one would be dishonest), and
`detect_token_scanning_activity` drops the MaxMind geo enrichment (it needs an
`.mmdb` file on the cluster; the IP-spread signal is intact).

**One new detection came out of this port:**
`detect_ip_acl_validation_failures` (`accountIpAclsValidationFailed`), which no
notebook covers. On the account that surfaced it, it was the highest-volume
IP-related event by roughly 8× — 447 events against 54 successful changes.

**Packaging caveat.** The Genie Agents documentation covers sharing within an
account and does not document exporting an agent for external distribution. The
SQL here is fully reproducible; creating the agent is a documented manual step
(section 4). If an export path ships later, `agent/` holds what's needed to
automate it.
