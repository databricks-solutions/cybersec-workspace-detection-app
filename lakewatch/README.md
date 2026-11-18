# Lakewatch detections for Databricks audit logs

This folder runs this repository's detections as [Lakewatch](https://docs.databricks.com/aws/en/lakewatch/introduction-to-lakewatch/)
detection rules on your `system.access.audit` table. There is nothing to ingest: Lakewatch rules read the system
table directly.

| Path | What it is |
|------|------------|
| [`SETUP.md`](SETUP.md) | From a workspace with no Lakewatch to running rules: enablement, a locked-down environment, the run-as service principal, the Content library rules, this folder's rules, and investigation with Genie. Start here. |
| `rules/` | 21 rule files (`cwda_*.yaml`), generated from the detections in this repository |
| `deploy.py` | Validates and deploys the rules (idempotent; `--dry-run`, `--prune`, `--run-as`) |
| `tools/build_rules.py` | Regenerates `rules/` from `genie-agent/functions/` and the notebooks' metadata |
| `tests/` | Rule checks: up to date with the detections, `IN_TIMERANGE` window, placeholders, MITRE, context keys |
| [`demo/`](demo/README.md) | A self-contained demo on a synthetic audit table with a planted credential attack: stage and correlation rules, hunts, a dashboard and a Genie Agent (by Alex Ott) |

## Quick start

Follow [`SETUP.md`](SETUP.md). With Lakewatch set up, the rules deploy in two commands:

```bash
uv run lakewatch/deploy.py --profile <ws-profile> --catalog <lakewatch_catalog> --schema detection \
  --warehouse-id <warehouse-id> --run-as <sp-application-id> --dry-run
uv run lakewatch/deploy.py --profile <ws-profile> --catalog <lakewatch_catalog> --schema detection \
  --warehouse-id <warehouse-id> --run-as <sp-application-id>
```

Rules are created disabled. Back-test each on the Lakewatch Query page, then enable the ones you want.

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

## Development

```bash
uv run lakewatch/tools/build_rules.py                                   # regenerate rules/
uv run --with pytest --with pyyaml pytest lakewatch/tests -q            # rule checks
cd lakewatch/demo && uv run --frozen --extra dev pytest -q              # demo checks
```

## Credits

The demo, its rule format and correlation approach are by Alex Ott. The deployer's idempotent update pattern
(content hash, owner-only update mask, managed rules and pruning) follows Andy Weaver's
[genie-trace-monitoring](https://github.com/andyweaves/genie-trace-monitoring).
