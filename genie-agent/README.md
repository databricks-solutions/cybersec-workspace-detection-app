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

### Step 3.2 — Create a schema to hold the functions

Replace `main` with a catalog your security team owns.

```sql
CREATE SCHEMA IF NOT EXISTS main.security_detections
  COMMENT 'Security detection functions for the Genie Agent';
```

### Step 3.3 — Install the functions

```sql
USE CATALOG main;
USE SCHEMA security_detections;
```

Now open each file in [`functions/`](functions/) and run it. There is currently
one: [`01_ip_access_and_config.sql`](functions/01_ip_access_and_config.sql).

Confirm they installed:

```sql
SHOW USER FUNCTIONS IN main.security_detections;
```

You should see five names beginning `detect_`.

### Step 3.4 — Test one before going further

```sql
SELECT * FROM main.security_detections.detect_config_changes_high_priority(
  current_timestamp() - INTERVAL 90 DAYS,
  current_timestamp()
) ORDER BY event_time DESC LIMIT 20;
```

Rows → working. No rows → not necessarily broken; see
[Troubleshooting](#8-troubleshooting).

---

## 4. Create the agent

In the Databricks UI:

1. Open **Genie** and create a new agent. Name it something obvious, e.g.
   *Security Audit Investigator*.
2. **Data** — add `system.access.audit`.
3. **Trusted Assets** — add all five `detect_*` functions from
   `main.security_detections`. *This is the important step.* These are verified
   queries; without them the agent invents its own SQL and can get it subtly
   wrong.
4. **Instructions** — open [`agent/instructions.md`](agent/instructions.md),
   copy the whole thing, paste it in. It teaches the agent the traps in audit
   data. Do not skip or shorten it.
5. **Example SQL Queries** — add a few from
   [`agent/example_questions.md`](agent/example_questions.md), replacing
   `<catalog>` with your catalog name.
6. Save, and give your security team access.

---

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

Five functions are installed today, covering incident-response basics.

**IP allow lists**
- Who changed the IP allow list, and when?
- Who deleted an IP access list?
- Were there failed attempts to change IP access rules?

**Security settings**
- What security settings changed in the last two weeks?
- Did anyone disable audit logging?
- What changed at the account level?

**Blocked access**
- Who was blocked by our IP allow list?
- Which IP addresses were denied, and what were they trying to reach?

**Follow-ups**
- What else did this user do that day?
- What else came from this IP address?
- Which changes came from automation rather than a person? *(the `user_agent`
  column distinguishes Terraform/CLI/SDK from someone clicking in the console)*

More in [`agent/example_questions.md`](agent/example_questions.md). The other 29
detections in this repo aren't ported yet — see
[`docs/PORTING.md`](docs/PORTING.md).

---

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
├── functions/     UC SQL functions (the Trusted Assets)
├── agent/         instructions, example questions, generated catalog
├── tools/         metadata extractor
└── docs/          DEPLOY.md (terse runbook), PORTING.md (port the other 29)
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

**Verification status.** All five functions were executed against a live account
(SFE workspace, 90-day window, 2026-08-26) and return real rows. Every
`request_params` key is verified against live data rather than the REST API docs —
they differ, and a wrong key returns NULL rather than an error. The key names are
listed at the top of the SQL file.

**One new detection came out of this port:**
`detect_ip_acl_validation_failures` (`accountIpAclsValidationFailed`), which no
notebook covers. On the account that surfaced it, it was the highest-volume
IP-related event by roughly 8× — 447 events against 54 successful changes.

**Packaging caveat.** The Genie Agents documentation covers sharing within an
account and does not document exporting an agent for external distribution. The
SQL here is fully reproducible; creating the agent is a documented manual step
(section 4). If an export path ships later, `agent/` holds what's needed to
automate it.
