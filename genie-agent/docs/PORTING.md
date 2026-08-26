# Porting detections to Genie Agent trusted functions

Status of the 34 detections in [`../../base/detections/`](../../base/detections/),
and how to port the rest.

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
34 detections   18 behavioral / 16 event-based
severity        10 high / 3 medium / 21 low
source tables   system.access.audit (33), system.query.history (1)
lib/common.py helpers used by a detection   NONE
```

That last line is the important one. `lib/common.py` (586 LOC) carries pandas
UDFs and MaxMind GeoIP enrichment that SQL cannot express — but **no current
detection calls them**, so all 34 are SQL-portable today.

## Ported

| Detection | Function | Source |
|---|---|---|
| Configuration Changes (High Priority) | `detect_config_changes_high_priority` | `event-based/configuration_changes_high_priority.py` |
| Configuration Changes (Account Level) | `detect_config_changes_account_level` | `event-based/configuration_changes_account_level.py` |
| Attempted Logon from Denied IP | `detect_denied_ip_logon_attempts` | `event-based/attempted_logon_from_denied_ip.py` |
| IP access list changes **+ diff** | `detect_ip_access_list_changes` | extracted from high-priority, extended |
| IP ACL validation failures | `detect_ip_acl_validation_failures` | **new — no notebook covers this** |

The IR set first, because that is what an active investigation needs.

## Not yet ported

The remaining 29, grouped by porting difficulty:

**Straightforward** — single filter + project, same pattern as the ported ones.
Most event-based detections: `sso_config_changed`, `verbose_audit_logging_disabled`,
`user_admin_account_change`, `trufflehog_scan_detected`,
`configuration_changes_workspace_level`, the privileged-role-assignment pair,
`databricks_employee_logon`.

**Needs care** — uses window functions or aggregation, which SQL supports but
where semantics must be checked against the PySpark original rather than
translated line by line:

- `behavioral/spike_in_table_admin_activity.py`
- `behavioral/session_hijacking_multi_device.py`
- `behavioral/session_hijacking_frequent_logins.py`
- `behavioral/session_hijacking_session_count.py`
- `behavioral/token_scanning_activity.py`
- `behavioral/secret_scanning_activity.py`

**Check for cross-run state first.** Any detection that assumes "compared to the
previous run" is a Workflow property, not a function property. A function is
stateless per call, so such logic needs either a materialized table or an
explicit baseline window as a parameter. Audit before porting — do not assume a
window function is self-contained.

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

**`request_params` key names are not guaranteed.** They mirror API payloads and
vary by action and API version. The ported IP-ACL function uses
`COALESCE(request_params['ip_addresses'], request_params['ipAddresses'])` for
exactly this reason. Confirm keys against live data —
`SELECT request_params FROM system.access.audit WHERE action_name='…' LIMIT 5` —
rather than trusting the API docs.

**There is no previous-value column.** A "diff" must be reconstructed with
`LAG(...) OVER (PARTITION BY <entity> ORDER BY event_time)`. The first event for
any entity necessarily has a NULL previous value.

**Enumerate before concluding absence.** Action names differ across
environments and feature enablement. Before deciding a detection has no
coverage, run the discovery query in
[`../agent/example_questions.md`](../agent/example_questions.md).
