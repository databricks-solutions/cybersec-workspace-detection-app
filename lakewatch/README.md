# Lakewatch detections for Databricks audit logs

This folder runs this repository's detections as [Lakewatch](https://docs.databricks.com/aws/en/lakewatch/introduction-to-lakewatch/)
detection rules on your `system.access.audit` table. There is nothing to ingest: Lakewatch rules read the system
table directly.

| Path | What it is |
|------|------------|
| [`SETUP.md`](SETUP.md) | From a workspace with no Lakewatch to running rules: enablement, a locked-down environment, the run-as service principal, the Content library rules, this folder's rules, and investigation with Genie. Start here. |
| `rules/` | 48 rule files: 21 generated from this repository's detections (`cwda_*`) and 27 attack-family rules (`cwdf_*`) |
| `templates/` | A rule that needs data outside system tables (cloud storage access logs); copy it into `rules/` once that data is ingested |
| `deploy.py` | Validates and deploys the rules (idempotent; leaves rules edited in the UI alone unless `--force`; creates the allow-list table; `--dry-run`, `--prune` disables orphans, `--prune-delete`, `--run-as`) |
| `tools/build_rules.py` | Regenerates `rules/` from `genie-agent/functions/` and the notebooks' metadata |
| `tests/` | Rule checks (up to date with the detections, `IN_TIMERANGE` window, placeholders, MITRE, context keys) and `fixtures/`: synthetic audit rows with planted attacks and near misses for every family rule |
| `tools/try_fixtures.py`, `tools/backtest.py` | Run a rule on its fixture (true positives), or over its last N runs on your real audit table (noise), read-only |
| [`demo/`](demo/README.md) | A self-contained demo on a synthetic audit table with a planted credential attack: stage and correlation rules, hunts, a dashboard and a Genie Agent (by Alex Ott) |

## Quick start

Follow [`SETUP.md`](SETUP.md). With Lakewatch set up, the rules deploy in two commands:

```bash
uv run lakewatch/deploy.py --profile <ws-profile> --catalog <lakewatch_catalog> --schema detection \
  --warehouse-id <warehouse-id> --run-as <sp-application-id> --dry-run
uv run lakewatch/deploy.py --profile <ws-profile> --catalog <lakewatch_catalog> --schema detection \
  --warehouse-id <warehouse-id> --run-as <sp-application-id>
```

Rules are created disabled. Back-test them on your audit table with `uv run lakewatch/tools/backtest.py` (read-only;
SETUP.md step 9), then enable the ones you want.

## How the rules relate to the rest of the repository

Each rule is the repository's Genie Agent function for that detection (`genie-agent/functions/`), with the
function's time window turned into the Lakewatch run window (`IN_TIMERANGE`) and the metadata of the detection
notebook (`base/detections/`). The three versions (notebook, Genie Agent, Lakewatch rule) stay one detection:
change the function or the notebook, run `uv run lakewatch/tools/build_rules.py`, and the test fails until the
rule file matches.

The rules complement the Lakewatch Content library's *Databricks Audit Intelligence* pack. Fifteen cover detections
the pack does not have; four replace pack rules that share a bug fixed here (SETUP.md step 9 lists which pack rules
to turn off); two add thresholds.

| Rule | Severity | Runs every | MITRE | Source detection |
|------|----------|-----------|-------|------------------|
| `cwda_access_token_deleted` | Low | 1h | — | `base/detections/behavioral/access_token_deleted.py` |
| `cwda_account_admin_privileged_role_assignment` | High | 1h | T1098 | `base/detections/event-based/account_admin_privileged_role_assignment.py` |
| `cwda_bulk_notebook_export` | High | 24h | T1567 | `base/detections/behavioral/bulk_notebook_export.py` |
| `cwda_configuration_changes_account_level` | Low | 1h | T1484 | `base/detections/event-based/configuration_changes_account_level.py` |
| `cwda_configuration_changes_high_priority` | Medium | 1h | T1484 | `base/detections/event-based/configuration_changes_high_priority.py` |
| `cwda_encoded_command_execution` | High | 1h | T1027, T1059 | `base/detections/behavioral/encoded_command_execution.py` |
| `cwda_group_created_or_member_added` | Low | 1h | — | `base/detections/behavioral/principal_added_to_group.py` |
| `cwda_non_sso_login_detected` | Low | 1h | — | `base/detections/behavioral/non_sso_login_detected.py` |
| `cwda_potential_data_movement_explicit_creds` | High | 1h | T1537 | `base/detections/behavioral/potential_data_movement_explicit_creds.py` |
| `cwda_potential_data_movement_sql_queries` | High | 1h | T1537 | `base/detections/behavioral/potential_data_movement_sql_queries.py` |
| `cwda_potential_data_movement_workspace_downloads` | Medium | 24h | T1567 | `base/detections/behavioral/potential_data_movement_workspace_downloads.py` |
| `cwda_secret_scanning_activity` | High | 24h | T1526 | `base/detections/behavioral/secret_scanning_activity.py` |
| `cwda_session_hijacking_frequent_logins` | Low | 24h | — | `base/detections/behavioral/session_hijacking_frequent_logins.py` |
| `cwda_session_hijacking_multi_device` | Low | 24h | — | `base/detections/behavioral/session_hijacking_multi_device.py` |
| `cwda_session_hijacking_session_count` | Low | 24h | — | `base/detections/behavioral/session_hijacking_session_count.py` |
| `cwda_spike_in_table_admin_activity` | Low | 24h | — | `base/detections/behavioral/spike_in_table_admin_activity.py` |
| `cwda_token_scanning_activity` | Low | 24h | — | `base/detections/behavioral/token_scanning_activity.py` |
| `cwda_user_account_created` | High | 1h | T1078, T1098 | `base/detections/behavioral/user_account_created.py` |
| `cwda_user_password_changed` | Low | 1h | — | `base/detections/behavioral/user_password_changed.py` |
| `cwda_verbose_audit_logging_disabled` | Low | 1h | — | `base/detections/event-based/verbose_audit_logging_disabled.py` |
| `cwda_workspace_admin_privileged_role_assignment` | High | 1h | T1098 | `base/detections/event-based/workspace_admin_privileged_role_assignment.py` |

## Attack-family rules (`cwdf_*`)

These 27 rules describe how credential-driven attacks on Databricks look in the audit log: each family is a
behaviour that separates an attacker from normal activity (a credential used from a new network and client, one new
IP signing in as many principals, secret harvesting, export sweeps, remote command execution, staged code, token
rotation across networks, and so on). They are written directly as Lakewatch rules, mostly against each
principal's or credential's own 30-day history rather than fixed thresholds. Each has a fixture in
`tests/fixtures/` with planted attacks and near misses; run `uv run lakewatch/tools/try_fixtures.py` to check them,
and `uv run lakewatch/tools/backtest.py` to see what they would return on your data before you enable them.

| Rule | Severity | Runs every | MITRE | Detects |
|------|----------|-----------|-------|---------|
| `cwdf_anomalous_credential_minting` | High | 1h | T1098, T1550 | A credential is minted anomalously. |
| `cwdf_api_cluster_privileged_or_ephemeral` | High | 1h | T1078, T1578 | A cluster created or edited over the API with privilege-bearing configuration. |
| `cwdf_audit_log_self_read` | Low | 24h | T1518 | A principal with no read of the audit log in the 90 days before starts reading system.access.audit. |
| `cwdf_command_execution_api_public_ip` | High | 1h | T1059, T1651 | Remote command execution through the Command Execution API (1.2) from a public IP by a principal and IP with no such history. |
| `cwdf_compute_serving_resource_abuse` | Medium | 24h | T1496 | Compute or model-serving resource abuse. |
| `cwdf_credential_new_network_and_client` | High | 1h | T1078, T1550 | An external credential (personal access token or service principal OAuth secret) is used from a network and a client family that this credential has never used. |
| `cwdf_credential_pivot_same_source` | High | 1h | T1550, T1552 | A credential is first used from the IP that just harvested secrets or credential files, or the IP that used a revoked token switches to another credential (or the revoked token still works). |
| `cwdf_denied_privileged_action_burst` | Medium | 1h | T1069, T1098 | A burst of refused privileged or data actions by one principal. |
| `cwdf_discovery_breadth_or_novel_actions` | Medium | 1h | T1526, T1619 | One principal suddenly surveys many surfaces. |
| `cwdf_dormant_credential_reactivation` | Medium | 24h | T1078 | A PAT idle for at least 30 days, or a service principal idle for at least 90 days, authenticates again from a public IP. |
| `cwdf_foreign_catalog_federation_abuse` | High | 1h | T1021, T1087 | Lakehouse Federation abuse. |
| `cwdf_identity_provisioning_anomaly` | High | 1h | T1098, T1136 | An identity is provisioned or elevated outside the normal path. |
| `cwdf_offensive_code_in_commands` | High | 1h | T1059, T1552 | A submitted command or Python UDF definition steals cloud instance-metadata credentials, spawns a shell or socket, or encodes secrets to get past output redaction. |
| `cwdf_one_new_ip_many_principals` | High | 1h | T1078, T1110 | One public IP with no sign-in history in the account presents the credentials of several principals, or reaches several workspaces, within one run. |
| `cwdf_refused_auth_spray` | High | 1h | T1078, T1110 | Refused token logins or IP access list denials across workspaces from one source, with any later success from the same source. |
| `cwdf_run_output_and_query_history_harvest` | Medium | 1h | T1213, T1552 | Bulk harvest of other principals' SQL query history or job run output by one principal from a public IP. |
| `cwdf_secret_bulk_read_burst` | High | 1h | T1552, T1555 | A principal reads far more distinct secrets in one run than its own busiest hour of the last 30 days, after enumerating scopes, or from outside Databricks compute. |
| `cwdf_secret_scope_enumeration` | Medium | 1h | T1526, T1555 | Secret scope enumeration. |
| `cwdf_sql_burst_new_client_or_volume` | High | 1h | T1213, T1567 | SQL statements from a client application new to the principal, statement or row volume far above its own baseline, or a bulk-dump shape (hash-sharded reads). |
| `cwdf_sql_credential_hunting` | Medium | 1h | T1083, T1552 | SQL that hunts for credentials. |
| `cwdf_staged_code_one_time_run` | High | 1h | T1070, T1651 | Code staged and run once from a new source. |
| `cwdf_suspicious_client_user_agent` | Medium | 1h | T1550, T1595 | A client user agent that does not belong on the credential. |
| `cwdf_temp_credential_vending_new_source` | Medium | 1h | T1530, T1567 | Temporary data-access credentials or download URLs issued in bulk, refused, or to a public IP and client new for the principal's credential vending. |
| `cwdf_token_multi_network_rotation` | Medium | 1h | T1090, T1550 | One PAT or service principal credential authenticates from many networks in one run. |
| `cwdf_uc_metadata_enumeration_burst` | Medium | 1h | T1526, T1619 | Unity Catalog metadata enumeration far above the principal's own baseline. |
| `cwdf_uc_privilege_or_exposure_change` | High | 1h | T1098, T1537 | A change that opens data beyond its boundary. |
| `cwdf_workspace_export_burst` | High | 1h | T1213, T1552, T1567 | Workspace exports across other users' home folders, of credential-shaped files, or in bulk from a source that never exported. |

Family 22 (SQL result files downloaded from root storage by an unknown IP) needs your cloud storage access
logs and is in `templates/` as an untested template.

## Development

```bash
uv run lakewatch/tools/build_rules.py                                   # regenerate rules/
uv run --with pytest --with pyyaml pytest lakewatch/tests -q            # rule checks
uv run lakewatch/tools/try_fixtures.py --profile <p> --warehouse-id <id> # planted attacks per rule
uv run lakewatch/tools/backtest.py --profile <p> --warehouse-id <id>     # rows per run on your data
cd lakewatch/demo && uv run --frozen --extra dev pytest -q              # demo checks
```

## Credits

The demo, its rule format and correlation approach are by Alex Ott. The attack families come from David Veuve's
coverage analysis. The deployer's idempotent update pattern
(content hash, owner-only update mask, managed rules and pruning) follows Andy Weaver's
[genie-trace-monitoring](https://github.com/andyweaves/genie-trace-monitoring).
