# Detection Tracker

Complete inventory of all security detections including existing implementations and planned additions.

## Existing Detections (34 Total)

### Event-based Detections (16)

High-confidence security events requiring immediate attention with 24-hour default time windows.

| Detection Name | File Path | Threat Models | Severity | Description |
|---------------|-----------|---------------|----------|-------------|
| SSO Config Changed | `/base/detections/event-based/sso_config_changed.py` | account_takeover, databricks_compromise | High | Detects changes to SSO configuration settings |
| TruffleHog Scan Detected | `/base/detections/event-based/trufflehog_scan_detected.py` | data_exfiltration, supply_chain | High | Detects TruffleHog scanning tool usage indicating credential scanning |
| Configuration Changes (Account Level) | `/base/detections/event-based/configuration_changes_account_level.py` | insider_threat, databricks_compromise, ransomware | High | Monitors account-level configuration changes |
| Configuration Changes (High Priority) | `/base/detections/event-based/configuration_changes_high_priority.py` | insider_threat, ransomware | High | Detects high-priority configuration modifications |
| Configuration Changes (Workspace Level) | `/base/detections/event-based/configuration_changes_workspace_level.py` | insider_threat, ransomware | High | Monitors workspace-level configuration changes |
| Verbose Audit Logging Disabled | `/base/detections/event-based/verbose_audit_logging_disabled.py` | insider_threat, ransomware | High | Detects when audit logging is disabled (audit evasion) |
| User Admin Account Change | `/base/detections/event-based/user_admin_account_change.py` | account_takeover, insider_threat, databricks_compromise | High | Monitors changes to admin user accounts |
| Attempted Logon from Denied IP | `/base/detections/event-based/attempted_logon_from_denied_ip.py` | account_takeover | Medium | Detects login attempts from IP addresses on deny lists |
| Databricks Employee Logon | `/base/detections/event-based/databricks_employee_logon.py` | databricks_compromise | Medium | Monitors Databricks employee access to customer workspaces |
| User Account Deleted | `/base/detections/event-based/user_account_deleted.py` | insider_threat, ransomware | Medium | Detects user account deletions |
| Group Deleted | `/base/detections/event-based/group_deleted.py` | insider_threat, ransomware | Medium | Detects group deletions |
| User Role Modified | `/base/detections/event-based/user_role_modified.py` | account_takeover, ransomware | Medium | Monitors user role modifications |
| Principal Removed from Group | `/base/detections/event-based/principal_removed_from_group.py` | insider_threat, ransomware | Medium | Detects when principals are removed from groups |
| Account Admin Privileged Role Assignment | `/base/detections/event-based/account_admin_privileged_role_assignment.py` | account_takeover, insider_threat, databricks_compromise | High | Detects direct account admin privilege grants or additions to account admin groups |
| Metastore Admin Privilege Granted | `/base/detections/event-based/metastore_admin_privilege_granted.py` | account_takeover, insider_threat | High | Detects metastore ownership changes or additions to metastore admin groups |
| Workspace Admin Privileged Role Assignment | `/base/detections/event-based/workspace_admin_privileged_role_assignment.py` | account_takeover, insider_threat, databricks_compromise | High | Detects workspace admin privilege grants or additions to the system admins group |

### Behavioral Detections (18)

Pattern analysis over 30-day default time windows for threat hunting and investigation.

| Detection Name | File Path | Threat Models | Window | Severity | Description |
|---------------|-----------|---------------|--------|----------|-------------|
| Access Token Created | `/base/detections/behavioral/access_token_created.py` | account_takeover, data_exfiltration, insider_threat, resource_abuse | 30 days | Medium | Monitors access token creation patterns |
| Access Token Deleted | `/base/detections/behavioral/access_token_deleted.py` | account_takeover | 30 days | Low | Monitors access token deletion patterns |
| Potential Data Movement (Explicit Creds) | `/base/detections/behavioral/potential_data_movement_explicit_creds.py` | data_exfiltration, insider_threat | 30 days | High | Detects data movement using explicit credentials |
| Potential Data Movement (SQL Queries) | `/base/detections/behavioral/potential_data_movement_sql_queries.py` | data_exfiltration, insider_threat | 30 days | High | Detects potential data exfiltration via SQL queries |
| Potential Data Movement (Workspace Downloads) | `/base/detections/behavioral/potential_data_movement_workspace_downloads.py` | data_exfiltration, insider_threat | 30 days | High | Detects data movement via workspace file downloads |
| Secret Scanning Activity | `/base/detections/behavioral/secret_scanning_activity.py` | data_exfiltration, insider_threat, supply_chain | 30 days | Medium | Detects secret enumeration and scanning activity |
| Token Scanning Activity | `/base/detections/behavioral/token_scanning_activity.py` | data_exfiltration, supply_chain | 30 days | Medium | Detects token scanning patterns |
| Session Hijacking (Multi-Device) | `/base/detections/behavioral/session_hijacking_multi_device.py` | account_takeover | 30 days | High | Detects sessions used across multiple devices |
| Session Hijacking (Frequent Logins) | `/base/detections/behavioral/session_hijacking_frequent_logins.py` | account_takeover | 30 days | Medium | Detects abnormally high login frequency |
| Session Hijacking (Session Count) | `/base/detections/behavioral/session_hijacking_session_count.py` | account_takeover | 30 days | Medium | Detects unusual session reuse patterns |
| Non-SSO Login Detected | `/base/detections/behavioral/non_sso_login_detected.py` | account_takeover | 30 days | Medium | Detects authentication not using SSO |
| Spike in Table Admin Activity | `/base/detections/behavioral/spike_in_table_admin_activity.py` | data_exfiltration, insider_threat, ransomware, resource_abuse | 30 days | Medium | Detects anomalous administrative activity spikes |
| User Account Created | `/base/detections/behavioral/user_account_created.py` | account_takeover, resource_abuse | 30 days | Low | Monitors user account creation patterns |
| User Password Changed | `/base/detections/behavioral/user_password_changed.py` | account_takeover | 30 days | Low | Monitors password change patterns |
| MFA Key Added | `/base/detections/behavioral/mfa_key_added.py` | account_takeover | 30 days | Low | Monitors MFA enrollment patterns |
| MFA Key Deleted | `/base/detections/behavioral/mfa_key_deleted.py` | account_takeover | 30 days | Medium | Detects MFA removal (potential bypass) |
| Group Created | `/base/detections/behavioral/group_created.py` | - | 30 days | Low | Monitors group creation patterns |
| Principal Added to Group | `/base/detections/behavioral/principal_added_to_group.py` | account_takeover | 30 days | Low | Monitors group membership additions |

---

## Lakewatch Rules (48 + 1 template)

The detections also run as scheduled [Lakewatch](../lakewatch/README.md) detection rules on `system.access.audit`.
Setup: [lakewatch/SETUP.md](../lakewatch/SETUP.md).

- **21 `cwda_*` rules** are generated from the Genie Agent functions (`genie-agent/functions/`) and the notebooks'
  metadata by `lakewatch/tools/build_rules.py`; a test fails when a rule drifts from its detection.
- **27 `cwdf_*` attack-family rules**, each with a synthetic fixture of a planted attack and near misses
  (`lakewatch/tests/fixtures/`):

| Rule | Severity | Runs every | What it reports |
|------|----------|------------|-----------------|
| `cwdf_anomalous_credential_minting` | High | 1h | A credential is minted anomalously -- a PAT or service principal secret from a creator IP new for the creator, a service principal minting its own PAT from a script, a token with no or very long expiry, or a PAT first used from a different IP new to the account within 72 hours of being minted. |
| `cwdf_api_cluster_privileged_or_ephemeral` | High | 1h | A cluster created or edited over the API with privilege-bearing configuration -- instance profiles, no isolation, literal storage keys -- or created and permanently deleted within the hour. |
| `cwdf_audit_log_self_read` | Low | 24h | A principal with no read of the audit log in the 90 days before starts reading system.access.audit. |
| `cwdf_command_execution_api_public_ip` | High | 1h | Remote command execution through the Command Execution API (1.2) from a public IP by a principal and IP with no such history. |
| `cwdf_compute_serving_resource_abuse` | Medium | 24h | Compute or model-serving resource abuse -- a principal's first GPU cluster or GPU serving endpoint, or a model-serving requester far above its own daily median or fanning out over many endpoints. |
| `cwdf_credential_new_network_and_client` | High | 1h | An external credential (personal access token or service principal OAuth secret) is used from a network and a client family that this credential has never used. |
| `cwdf_credential_pivot_same_source` | High | 1h | A credential is first used from the IP that just harvested secrets or credential files, or the IP that used a revoked token switches to another credential (or the revoked token still works). |
| `cwdf_denied_privileged_action_burst` | Medium | 1h | A burst of refused privileged or data actions by one principal -- many distinct refused action types, a self-grant attempt, or failed creates across several workspaces. |
| `cwdf_discovery_breadth_or_novel_actions` | Medium | 1h | One principal suddenly surveys many surfaces -- several discovery families from a new source IP, or several discovery actions it has never performed. |
| `cwdf_dormant_credential_reactivation` | Medium | 24h | A PAT idle for at least 30 days, or a service principal idle for at least 90 days, authenticates again from a public IP. |
| `cwdf_foreign_catalog_federation_abuse` | High | 1h | Lakehouse Federation abuse -- a foreign catalog created and deleted within minutes, a first-time foreign catalog creator, or federated queries against the provider's credential and user metadata. |
| `cwdf_identity_provisioning_anomaly` | High | 1h | An identity is provisioned or elevated outside the normal path -- auto-provisioned on a refused login, as an application, or from an IP new to the account, or added, re-enabled or made admin by an API client. |
| `cwdf_offensive_code_in_commands` | High | 1h | A submitted command or Python UDF definition steals cloud instance-metadata credentials, spawns a shell or socket, or encodes secrets to get past output redaction. |
| `cwdf_one_new_ip_many_principals` | High | 1h | One public IP with no sign-in history in the account presents the credentials of several principals, or reaches several workspaces, within one run. |
| `cwdf_refused_auth_spray` | High | 1h | Refused token logins or IP access list denials across workspaces from one source, with any later success from the same source. |
| `cwdf_run_output_and_query_history_harvest` | Medium | 1h | Bulk harvest of other principals' SQL query history or job run output by one principal from a public IP. |
| `cwdf_secret_bulk_read_burst` | High | 1h | A principal reads far more distinct secrets in one run than its own busiest hour of the last 30 days, after enumerating scopes, or from outside Databricks compute. |
| `cwdf_secret_scope_enumeration` | Medium | 1h | Secret scope enumeration -- keys listed across many scopes, refusals across scopes, scopes listed in several workspaces, or a principal enumerating secrets for the first time from a public IP. |
| `cwdf_sql_burst_new_client_or_volume` | High | 1h | SQL statements from a client application new to the principal, statement or row volume far above its own baseline, or a bulk-dump shape (hash-sharded reads). |
| `cwdf_sql_credential_hunting` | Medium | 1h | SQL that hunts for credentials -- information_schema searches for credential-named tables or columns, SELECTs of credential columns, read_files() content greps for key formats, or repeated secret() calls. |
| `cwdf_staged_code_one_time_run` | High | 1h | Code staged and run once from a new source -- import or upload, a one-time run or a create-and-run job, then the run output fetched or the code deleted, by one principal and IP with no run history from that IP. |
| `cwdf_suspicious_client_user_agent` | Medium | 1h | A client user agent that does not belong on the credential -- a browser on a PAT or service principal token login, a browser or curl on an OAuth client-credentials mint, or a known offensive tool. |
| `cwdf_temp_credential_vending_new_source` | Medium | 1h | Temporary data-access credentials or download URLs issued in bulk, refused, or to a public IP and client new for the principal's credential vending. |
| `cwdf_token_multi_network_rotation` | Medium | 1h | One PAT or service principal credential authenticates from many networks in one run -- at least 10 public /24s, or at least 3 /24s new for that credential. |
| `cwdf_uc_metadata_enumeration_burst` | Medium | 1h | Unity Catalog metadata enumeration far above the principal's own baseline -- list and get calls, schema breadth, or credential listings across workspaces. |
| `cwdf_uc_privilege_or_exposure_change` | High | 1h | A change that opens data beyond its boundary -- metastore external access toggled, EXTERNAL_USE, ALL PRIVILEGES or MANAGE granted, a grant to all account users, a Delta Sharing share or recipient created, or a Lakebase superuser role. |
| `cwdf_workspace_export_burst` | High | 1h | Workspace exports across other users' home folders, of credential-shaped files, or in bulk from a source that never exported. |

One more family rule, `cwdf_external_sql_result_download`, is a template (`lakewatch/templates/`): it needs cloud storage access
logs ingested into Lakewatch and is not tested.

## Planned Detections (Not Yet Implemented)

These detections are planned for future implementation based on security requirements and threat landscape evolution.

### Planned Event-based Detections

| Detection Name | Priority | Target Threat Models | Description | Notes |
|---------------|----------|---------------------|-------------|-------|
| IP Access List Changes | High | account_takeover, insider_threat | Monitor IP allowlist modifications | Critical for access control |
| Delta Sharing Recipients Configuration | Medium | data_exfiltration, insider_threat | Data sharing monitoring | UC Delta Sharing feature |
| Long Lifetime Token Generation | Medium | account_takeover, supply_chain | Long-lived token alerts | Tokens >90 days |
| Capsule8 Container Breakout Events | Critical | databricks_compromise | Container security events | Platform security |
| Capsule8 Host Security Settings Changes | Critical | databricks_compromise | Host security monitoring | Platform security |
| ClamAV Infected Files Found | Critical | supply_chain, ransomware | Malware detection | File scanning |

### Planned Behavioral Detections

| Detection Name | Priority | Target Threat Models | Description | Notes |
|---------------|----------|---------------------|-------------|-------|
| Repeated Failed Login Attempts | High | account_takeover | Brute force detection | Authentication attacks |
| Global Init Script Changes | High | supply_chain, insider_threat | Init script monitoring | Code injection risk |
| Install Library on All Clusters | Medium | supply_chain, resource_abuse | Library installation patterns | Supply chain monitoring |
| Mount Point Creation | Medium | data_exfiltration, insider_threat | DBFS mount monitoring | External storage access |
| Destructive Activities | High | ransomware, insider_threat | Destructive operation patterns | Combined destructions |
| Potential Privilege Escalation | High | account_takeover, insider_threat | Privilege escalation detection | Role/permission changes |
| Repeated Access to Secrets | Medium | data_exfiltration, insider_threat | Secret enumeration | Credential harvesting |
| Access to Multiple Workspaces | Medium | account_takeover, insider_threat | Cross-workspace access | Lateral movement |
| Use of Print Statements | Low | data_exfiltration | Sensitive data exposure | Code review detection |
| IP Addresses Used to Access Databricks | Low | account_takeover | IP usage patterns | Baseline monitoring |
| IP Address Ranges Used | Low | account_takeover | IP range analysis | Geographic patterns |
| Repeated Unauthorized UC Requests | High | insider_threat, account_takeover | Unity Catalog access attempts | Authorization failures |
| Repeated Unauthorized UC Data Requests | High | data_exfiltration, insider_threat | UC data access attempts | Data access denials |
| High Number of Read/Writes | Medium | resource_abuse, data_exfiltration | I/O anomaly detection | Usage patterns |

---

## Detection Coverage by Threat Model

### Account Takeover or Compromise (17 detections)
- **Event-based (6)**: SSO Config Changed, Attempted Logon from Denied IP, User Admin Account Change, User Role Modified, Account Admin Privileged Role Assignment, Metastore Admin Privilege Granted, Workspace Admin Privileged Role Assignment
- **Behavioral (11)**: Non-SSO Login, Session Hijacking (3), Access Token Created/Deleted, MFA Key Added/Deleted, User Password Changed, Principal Added to Group, User Account Created

### Data Exfiltration (8 detections)
- **Event-based (1)**: TruffleHog Scan Detected
- **Behavioral (7)**: Potential Data Movement (3 types), Secret Scanning, Token Scanning, Access Token Created, Spike in Table Admin Activity

### Insider Threat (17 detections)
- **Event-based (9)**: Configuration Changes (3 types), Verbose Audit Logging Disabled, User Admin Account Change, User Account Deleted, Group Deleted, Principal Removed from Group, Account Admin Privileged Role Assignment, Metastore Admin Privilege Granted, Workspace Admin Privileged Role Assignment
- **Behavioral (8)**: Potential Data Movement (3 types), Spike in Table Admin Activity, Secret Scanning, Access Token Created

### Supply Chain Attacks (3 detections)
- **Event-based (1)**: TruffleHog Scan Detected
- **Behavioral (2)**: Token Scanning, Secret Scanning

### Potential Compromise of Databricks (6 detections)
- **Event-based (6)**: Databricks Employee Logon, Configuration Changes (Account Level), SSO Config Changed, User Admin Account Change, Account Admin Privileged Role Assignment, Workspace Admin Privileged Role Assignment
- **Behavioral (0)**: None

### Ransomware Attacks (9 detections)
- **Event-based (7)**: Configuration Changes (3 types), User Account Deleted, Group Deleted, Principal Removed from Group, User Role Modified, Verbose Audit Logging Disabled
- **Behavioral (2)**: Spike in Table Admin Activity

### Resource Abuse (3 detections)
- **Event-based (0)**: None
- **Behavioral (3)**: Spike in Table Admin Activity, User Account Created, Access Token Created

---

## Detection Statistics

- **Total Existing Detections**: 34
  - Event-based: 16 (47%)
  - Behavioral: 18 (53%)

- **Total Planned Detections**: 20
  - Event-based: 6
  - Behavioral: 14

- **Severity Distribution (Existing)**:
  - High: 17 detections
  - Medium: 13 detections
  - Low: 4 detections

- **Most Covered Threat Models**:
  1. Account Takeover: 17 detections
  2. Insider Threat: 17 detections
  3. Ransomware: 9 detections
  4. Data Exfiltration: 8 detections

---

## Notes

### Detection Overlaps
Some existing "planned" detections from requirements already exist with different naming:
- ✅ `access_token_created.py` covers planned "Access_token_created"
- ✅ `group_created.py` covers planned "Group_created"
- ✅ `mfa_key_added.py` covers planned "Mfa_key_added"
- ✅ `mfa_key_deleted.py` covers planned "mfa_key_deleted"

### Future Enhancements
- Correlation rules combining multiple detections
- Machine learning-based anomaly detection
- Integration with SIEM platforms
- Automated response workflows
- Custom detection templates

---

*Last Updated: 2026-02-26*
