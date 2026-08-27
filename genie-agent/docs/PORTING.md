# Porting detections to Genie Agent trusted functions

How all 34 detections in [`../../base/detections/`](../../base/detections/) were
ported to Unity Catalog SQL functions, the deliberate deviations, and the traps
found along the way.

## Why it's a hand port, not a transpiler

Every detection is a filter-and-project over one table, so the *shape* translates
mechanically. The **metadata** is auto-extracted
(`tools/extract_detection_metadata.py` — all 34 parse cleanly). But the SQL
`COMMENT` is what Genie matches a natural-language question against, and that
text needs a human deciding how analysts actually phrase the question. A
generated comment like *"Detects high-priority configuration changes"* will not
match *"did anyone turn off audit logging?"*.

So: metadata generated, `Use for:` phrasings written by hand.

## Verified about the source set

```
35 detections   19 behavioral / 16 event-based
severity        11 high / 3 medium / 21 low
source tables   system.access.audit (33), system.query.history (1)
lib/common.py helpers used by a detection   NONE
```

That last line is the important one. `lib/common.py` (586 LOC) carries pandas
UDFs and MaxMind GeoIP enrichment that SQL cannot express — but **no current
detection calls them**, so all 34 are SQL-portable today.

## Ported: all 35

| File | Functions | Detections covered |
|---|---|---|
| `01_ip_access_and_config.sql` | 5 | IP access lists, high-priority + account-level config, denied logons |
| `02_identity_and_access.sql` | 15 | tokens, admin grants (account/workspace/metastore), user lifecycle, roles, passwords, MFA, groups, non-SSO + employee logon, SSO config |
| `03_data_movement_and_secrets.sql` | 8 | storage credentials, COPY INTO, downloads, bulk notebook export, secrets discovery, credential scanners, token scanning, admin SQL spike |
| `04_sessions_and_config.sql` | 5 | session hijacking ×3, verbose-audit-logging evasion, workspace config |

**33 functions for 35 detections.** Four near-identical notebooks were merged into
two, deliberately: `mfa_key_added` + `mfa_key_deleted` → `detect_mfa_key_changes`,
and `group_created` + `group_deleted` + `principal_added_to_group` +
`principal_removed_from_group` → `detect_group_changes`. Genie selects better from
one well-described function than from several near-duplicates, and both directions
of a change answer the same investigative question ("did group membership change
for this principal?").

Verified on a live workspace: 33/33 installed, 33/33 executed without error, 19
returning data and 14 legitimately empty because those events do not occur in
that account.

### Deliberate deviations from the source notebooks

**`detect_admin_sql_activity_spike`** reports a per-actor-per-day COUNT above a
threshold, not the notebook's normalised RATE. A stateless SQL function has no
baseline window to normalise against, and inventing one would misrepresent the
result. The investigative question — "who suddenly started issuing account DDL?" —
is answered either way.

**`detect_token_scanning_activity`** drops the notebook's optional MaxMind geo
enrichment, which needs an `.mmdb` file on the cluster and cannot be expressed in
SQL. The load-bearing signal (one token presenting from many distinct IPs) is
intact; only the city/country columns are gone.

**`detect_data_movement_downloads`** aggregates per actor/action/day rather than
returning one row per event. Discovered by running it: the un-aggregated form
returned **242,738 rows from 6 actors** in a 90-day window, which would truncate
in any agent answer and tell an analyst nothing. Aggregated it returns 199 rows
with the same total.

**Environment-specific allowlists are NOT baked in.** `access_token_created` in
the notebook excludes one account's known job (`user_agent ~ 'linux auth'`, source
IP `52.9.53.2`). Shipping that would silently hide real tokens in every other
account, so the columns are returned and the caller filters. The session
detections' RFC1918 and Databricks-service-agent exclusions ARE kept, because
those are structural rather than account-specific.

## How to port one

1. Read the notebook's `dscc` YAML for name, objective, MITRE taxonomy, severity
   and documented false positives.
2. Translate the `.filter(...)` to a `WHERE` clause. `col("request_params").getItem("k")`
   becomes `request_params['k']`.
3. Translate `.select(...)` to the `RETURNS TABLE` column list, keeping the
   notebook's aliases so notebook and function output line up.
4. Write the `COMMENT`: one sentence of what it detects, the MITRE tag, then
   `Use for:` with 5-8 real analyst phrasings.
5. Keep `start_time` / `end_time` as the first two parameters, matching the
   notebook's `earliest` / `latest`.
6. Verify against the notebook on the same window — **same row count, same rows**.
   A port that returns *fewer* rows is worse than no port, because during an
   investigation a short answer reads as a clean one.

## Traps found while porting

**Filter on `service_name`, not `audit_level`.** Verified against a live account
(2026-08-26): every IP-ACL mutation is `service_name='accounts'` with
`audit_level='WORKSPACE_LEVEL'`, despite IP ACLs existing at account scope.
`audit_level='ACCOUNT_LEVEL'` returns zero rows. Treat `audit_level` as a
reporting column. `setSetting` is the real exception and genuinely is
account-scoped.

**`request_params` keys do NOT match the REST API field names.** Verify every key
against live data before shipping a function — a wrong key returns NULL, not an
error, so the function looks like it works while silently answering nothing.
Verified keys (SFE workspace, 90-day window, 2026-08-26):

| action | keys |
|---|---|
| create/update/deleteIpAccessList | `ipAccessListId`, `userId` — **that is all** |
| accountIpAclsValidationFailed | `sourceIpAddress`, `user` |
| IpAccessDenied | `path`, `userId`, `user` |
| workspaceConfEdit | `workspaceConfKeys`, `workspaceConfValues` |
| setSetting | `settingName`, `settingTypeName`, `settingKeyName`, `settingValueForAudit`, `settingKeyTypeName` |

Enumerate before assuming:
`SELECT action_name, map_keys(request_params) FROM system.access.audit WHERE action_name='…' LIMIT 5`

**IP access list events contain NO IP values.** The most important finding of this
port. Across all 54 IP-ACL mutations in a live 90-day window, `request_params`
held exactly two keys (above) and `response.result` was NULL on every row. A
before/after CIDR diff is therefore **impossible** from audit data. An earlier
draft of the ported function did `LAG(request_params['ip_addresses'])` and would
have returned NULL for every value — looking functional while answering nothing.
Resolve `ipAccessListId` against `GET /api/2.0/ip-access-lists` for current
contents; historical values are unrecoverable.

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
commented in place so nobody "tidies" it away.

**Enumerate before concluding absence.** Action names differ across
environments and feature enablement. Before deciding a detection has no
coverage, run the discovery query in
[`../agent/example_questions.md`](../agent/example_questions.md).
