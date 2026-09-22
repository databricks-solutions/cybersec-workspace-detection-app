# Authoring detections as Genie Agent trusted assets

How the detections in [`../../base/detections/`](../../base/detections/) are
authored as SQL in [`../functions/`](../functions/), how they become the agent's
**embedded example queries**, the deliberate deviations, and the traps found along
the way.

## Two forms, one source of truth

Each detection is authored as a `CREATE OR REPLACE FUNCTION` in `functions/*.sql`
— a parameterized table function over one system table, with a `RETURNS TABLE`
signature and a `COMMENT`. That file is the single source of truth for the
verified logic.

The installer does **not** create those functions in Unity Catalog. Instead
[`../tools/inline_functions.py`](../tools/inline_functions.py) rewrites each
function into an **embedded, parameterized example query** in the Genie space at
build time (see "From function to embedded query" below). So the agent ships with
no UC objects and no DDL at install; the `CREATE FUNCTION` form is the authoring
format, not a deployed artifact.

## Why it's a hand port, not a transpiler

Every detection is a filter-and-project over one table, so the *shape* translates
mechanically. But the SQL `COMMENT` is what Genie matches a natural-language
question against, and that text needs a human deciding how analysts actually
phrase the question. A generated comment like *"Detects high-priority
configuration changes"* will not match *"did anyone turn off audit logging?"*.

So: the SQL logic translates from the notebook mechanically; the `Use for:`
phrasings are written by hand.

## Verified about the source set

```
source detections   behavioral + event-based
source tables        system.access.audit (most), system.query.history (1)
lib/common.py helpers used by a detection   NONE
```

That last line is the important one. `lib/common.py` carries pandas UDFs and
MaxMind GeoIP enrichment that SQL cannot express — but **no current detection
calls them**, so all are SQL-portable today.

## Coverage

| File | Functions | Detections covered |
|---|---|---|
| `00_investigation_triage.sql` | 1 | *not a detection* — the investigation-mode entry point (see below) |
| `01_ip_access_and_config.sql` | 5 | IP access lists, high-priority + account-level config, denied logons |
| `02_identity_and_access.sql` | 15 | tokens, admin grants (account/workspace/metastore), user lifecycle, roles, passwords, MFA, groups, non-SSO + employee logon, SSO config |
| `03_data_movement_and_secrets.sql` | 9 | storage credentials, COPY INTO, downloads, bulk notebook export, secrets discovery, credential scanners, token scanning, admin SQL spike, encoded command execution |
| `04_sessions_and_config.sql` | 5 | session hijacking ×3, verbose-audit-logging evasion, workspace config |

### The investigation-triage asset (not a detection)

`00_investigation_triage.sql` (`detect_investigation_triage`) is the entry point
for **investigation mode**, not a ported detection. A Genie space answers one query
per turn, so an open-ended investigation must play out across turns; the load-bearing
first step is picking the lead. Ad-hoc, the model tends to either UNION every family
into one query (which truncates to a sample and buries the signal) or rank by raw
event volume (which floats a busy service principal to the top). This asset makes
that step deterministic: it ranks actors and their source IPs by the count of
**distinct** security-sensitive action types they touched — breadth across families
first, then failed attempts, then volume — because an incident's signature is one
identity touching several *rare, high-severity* action types (an IP-ACL burst is
low-volume but high-signal). Its sensitive-action set is the union of the action
names the detections already treat as security-relevant; routine authentication
(`login`/`tokenLogin`/`samlLogin`/`jwtLogin`/`mfaLogin`/`certLogin`) is deliberately
excluded because it is high-volume and would dominate the ranking (the non-SSO /
employee-logon detections cover authentication specifically).

**Its blind spot, by construction:** because it ranks *per actor*, a campaign
distributed across many identities that each touch only a little — credential
stuffing, mass token replay, distributed export from a shared IP pool — will not
top it, since no single identity has the breadth. A single high-breadth *benign*
actor (e.g. an admin running an IP-ACL migration across several controls) can even
outrank it. That distributed shape surfaces in IP/token concentration, not
per-actor breadth, which is why the pivot step ranks on the shared IP/token for
that case. Triage is one lens, not the whole investigation. See
`agent/instructions.md` for the loop it anchors.

Some near-identical notebooks were merged deliberately: `mfa_key_added` +
`mfa_key_deleted` → `detect_mfa_key_changes`, and the four group notebooks →
`detect_group_changes`. Genie selects better from one well-described query than
from several near-duplicates, and both directions of a change answer the same
investigative question ("did group membership change for this principal?").

## From function to embedded query

`tools/inline_functions.py` performs a deliberately parse-light transform so it
cannot silently mangle a body:

1. A string/paren/angle-aware scanner (not regex — `COMMENT` text contains parens
   and semicolons, and `RETURNS TABLE` columns contain `MAP<STRING, STRING>` whose
   comma must not split the column list) extracts the parameter names, the
   `RETURNS TABLE` column names, and the `RETURN` body.
2. Each parameter is replaced with the value the example wrapper passed:
   `start_time` / `end_time` become the named binds `:start_time` / `:end_time`;
   tuning params become the literal the wrapper used (e.g. `min_ips` → `5`,
   `admin_groups` → `''`). A parameter is substituted only as a bare identifier,
   never as `x.name`.
3. The body is wrapped as `SELECT * FROM ( <body> ) AS results(col1, …, colN)`
   using the `RETURNS TABLE` column names. This renames the output columns
   positionally — so the embedded query returns exactly what the function did —
   WITHOUT parsing or aliasing the inner `SELECT`. CTEs, window functions, and
   mixed aliasing in the body are therefore irrelevant.

Run `python3 genie-agent/tools/inline_functions.py` for a self-check: it parses
every function, asserts each example wrapper's argument count matches the
function's parameter count, and prints one fully inlined example. The transform
was additionally validated against the installed functions on a live workspace
(inlined query vs. function output over the same window — identical row sets,
aside from columns built with order-nondeterministic `COLLECT_SET`, which differ
run-to-run in the function itself too).

### Deliberate deviations from the source notebooks

**`detect_admin_sql_activity_spike`** reports a per-actor-per-day COUNT above a
threshold, not the notebook's normalised RATE. A stateless function has no
baseline window to normalise against, and inventing one would misrepresent the
result. The investigative question — "who suddenly started issuing account DDL?" —
is answered either way.

**`detect_token_scanning_activity`** drops the notebook's optional MaxMind geo
enrichment, which needs an `.mmdb` file on the cluster and cannot be expressed in
SQL. The load-bearing signal (one token presenting from many distinct IPs) is
intact; only the city/country columns are gone.

**`detect_data_movement_downloads`** aggregates per actor/action/day rather than
returning one row per event. Discovered by running it: the un-aggregated form
returned hundreds of thousands of rows in a 90-day window, which would truncate in
any agent answer and tell an analyst nothing. Aggregated it returns the same total
in a few hundred rows.

**Environment-specific allowlists are NOT baked in.** A source notebook may
exclude one account's known job by user agent and source IP. Shipping that would
silently hide real activity in every other account, so the columns are returned
and the caller filters. The session detections' RFC1918 and
Databricks-service-agent exclusions ARE kept, because those are structural rather
than account-specific.

## How to author one

1. Read the notebook's `dscc` YAML for name, objective, MITRE taxonomy, severity
   and documented false positives.
2. Translate the `.filter(...)` to a `WHERE` clause.
   `col("request_params").getItem("k")` becomes `request_params['k']`.
3. Translate `.select(...)` to the `RETURNS TABLE` column list, keeping the
   notebook's aliases so notebook and query output line up.
4. Write the `COMMENT`: one sentence of what it detects, the MITRE tag, then
   `Use for:` with 5-8 real analyst phrasings.
5. Keep `start_time` / `end_time` as the first two parameters, matching the
   notebook's `earliest` / `latest`. Any tuning parameter comes after, and the
   example query in the space template passes its default literal.
6. Verify against the notebook on the same window — **same row count, same rows**.
   A port that returns *fewer* rows is worse than no port, because during an
   investigation a short answer reads as a clean one. Then run the inliner
   self-check.

## Traps found while authoring

**Filter on `service_name`, not `audit_level`.** Verified against a live account:
every IP-ACL mutation is `service_name='accounts'` with
`audit_level='WORKSPACE_LEVEL'`, despite IP ACLs existing at account scope.
`audit_level='ACCOUNT_LEVEL'` returns zero rows. Treat `audit_level` as a
reporting column. `setSetting` is the real exception and genuinely is
account-scoped.

**`request_params` keys do NOT match the REST API field names.** Verify every key
against live data before shipping — a wrong key returns NULL, not an error, so the
detection looks like it works while silently answering nothing. Verified keys (a
live workspace, 90-day window):

| action | keys |
|---|---|
| create/update/deleteIpAccessList | `ipAccessListId`, `userId` — **that is all** |
| accountIpAclsValidationFailed | `sourceIpAddress`, `user` |
| IpAccessDenied | `path`, `userId`, `user` |
| workspaceConfEdit | `workspaceConfKeys`, `workspaceConfValues` |
| setSetting | `settingName`, `settingTypeName`, `settingKeyName`, `settingValueForAudit`, `settingKeyTypeName` |

Enumerate before assuming:
`SELECT action_name, map_keys(request_params) FROM system.access.audit WHERE action_name='…' LIMIT 5`

**IP access list events contain NO IP values.** The most important finding.
Across all IP-ACL mutations in a live 90-day window, `request_params` held exactly
two keys (above) and `response.result` was NULL on every row. A before/after CIDR
diff is therefore **impossible** from audit data. An earlier draft did
`LAG(request_params['ip_addresses'])` and would have returned NULL for every value
— looking functional while answering nothing. Resolve `ipAccessListId` against
`GET /api/2.0/ip-access-lists` for current contents; historical values are
unrecoverable.

**But some events DO carry values** — do not over-generalise the rule above.
`setSetting` has `settingValueForAudit`; `workspaceConfEdit` has
`workspaceConfValues`. Note `settingName` is frequently EMPTY while
`settingTypeName` holds the meaningful identifier (e.g. `abac_grants`).

**A SQL UDF body cannot begin with a top-level `WITH`.** The CTE has to sit inside
a subquery — `RETURN SELECT * FROM ( WITH … )`. Without the wrap, `CREATE FUNCTION`
fails with `The request failed due to an unexpected condition`: no parse error, no
line number, nothing pointing at the CTE. The identical query runs fine
standalone, which makes it look like a permissions or transport problem rather
than a syntax one. Cost real time on `detect_bulk_notebook_export`; the wrap is
commented in place so nobody "tidies" it away. (The inliner then wraps that body
once more for column renaming — a valid nested subquery.)

**A PySpark `r"\b"` regex SILENTLY breaks when ported into a Spark SQL string
literal.** The `encoded_command_execution` port (PR #10) matches `base64 -d|bash`
with `rlike(r"(--decode|-d)\b")` and pipe-to-shell with `r"\|\s*(ba)?sh\b"`. In
PySpark the `r"..."` preserves the backslash, so Java regex sees a word boundary.
Dropped verbatim into a SQL `RLIKE '...'` it breaks: the SQL string-literal parser
consumes `\b` as a backspace character *before* the regex engine ever sees it, so
the word boundary is gone and `base64 -d|bash` stops matching — the same
"looks-fine, matches-nothing" failure as a wrong `request_params` key. Verified
live (2026-09-03):

```
'base64 -d|bash' RLIKE '(--decode|-d)\b'   -> false   (backspace)
'base64 -d|bash' RLIKE '(--decode|-d)\\b'  -> true    (word boundary)
```

Double every backslash (`\\b`, `\\|`, `\\s`) in a ported regex, and prove it
fires against a known payload rather than trusting a clean install — a regex that
matches nothing installs without error.

**The port attributes SQL to `executed_by`, not `executed_as` — and the #10
notebook still does the opposite.** `system.query.history` carries two identities:
`executed_by` (who submitted the statement) and `executed_as` (the run-as identity
the statement executes under, which on a scheduled or owned query is the owner or a
service principal — masking the human who submitted it). For incident attribution
you want the submitter, so `detect_encoded_command_execution` reports `executed_by`.
The scheduled-notebook counterpart (PR #10,
`base/detections/behavioral/encoded_command_execution.py`) still reports
`executed_as`, so the interactive and scheduled surfaces can name *different* actors
for the same SQL-warehouse statement. Everything else is already in parity: the
base64 word-boundary match, the narrowed printf branch (`[0-9a-fA-F]{20,}` + a
pipe-to-shell or `xxd`), and the `runCommand`/`submitCommand` × `notebook`/`jobs`
audit source all match #10 as of its review-fix commit `795795c`. Attribution is
the one place they still differ. **Follow-up:** backport `executed_by` to the #10
notebook so both surfaces attribute to the submitter — tracked separately because
that notebook is not on this branch.

**A correlated `IN (SELECT explode(...))` creates on a SQL warehouse but FAILS in a
UDF body on DBR.** The three admin-grant functions used
`IN (SELECT trim(g) FROM (SELECT explode(split(admin_groups, ',')) AS g))` to match
a comma-separated parameter. That created fine via the SQL Statement API (DBSQL)
and silently failed via `spark.sql` in a notebook (DBR). Use
`array_contains(transform(split(param, ','), x -> trim(x)), value)` instead: no
subquery, works on both. Found only by running the notebook installer end to end,
not by reading it — **test every install path you ship, they are not
interchangeable.**

**Enumerate before concluding absence.** Action names differ across environments
and feature enablement. Before deciding a detection has no coverage, run the
discovery query in
[`../agent/example_questions.md`](../agent/example_questions.md).
