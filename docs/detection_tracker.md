# Detection Tracker

Complete inventory of all security detections including existing implementations and planned additions.

## Existing Detections (34 Total)

### Binary Detections (16)

High-confidence security events requiring immediate attention with 24-hour default time windows.

| Detection Name | File Path | Threat Models | Severity | Description |
|---------------|-----------|---------------|----------|-------------|
| SSO Config Changed | `/base/detections/binary/sso_config_changed.py` | account_takeover, databricks_compromise | High | Detects changes to SSO configuration settings |
| TruffleHog Scan Detected | `/base/detections/binary/trufflehog_scan_detected.py` | data_exfiltration, supply_chain | High | Detects TruffleHog scanning tool usage indicating credential scanning |
| Configuration Changes (Account Level) | `/base/detections/binary/configuration_changes_account_level.py` | insider_threat, databricks_compromise, ransomware | High | Monitors account-level configuration changes |
| Configuration Changes (High Priority) | `/base/detections/binary/configuration_changes_high_priority.py` | insider_threat, ransomware | High | Detects high-priority configuration modifications |
| Configuration Changes (Workspace Level) | `/base/detections/binary/configuration_changes_workspace_level.py` | insider_threat, ransomware | High | Monitors workspace-level configuration changes |
| Verbose Audit Logging Disabled | `/base/detections/binary/verbose_audit_logging_disabled.py` | insider_threat, ransomware | High | Detects when audit logging is disabled (audit evasion) |
| User Admin Account Change | `/base/detections/binary/user_admin_account_change.py` | account_takeover, insider_threat, databricks_compromise | High | Monitors changes to admin user accounts |
| Attempted Logon from Denied IP | `/base/detections/binary/attempted_logon_from_denied_ip.py` | account_takeover | Medium | Detects login attempts from IP addresses on deny lists |
| Databricks Employee Logon | `/base/detections/binary/databricks_employee_logon.py` | databricks_compromise | Medium | Monitors Databricks employee access to customer workspaces |
| User Account Deleted | `/base/detections/binary/user_account_deleted.py` | insider_threat, ransomware | Medium | Detects user account deletions |
| Group Deleted | `/base/detections/binary/group_deleted.py` | insider_threat, ransomware | Medium | Detects group deletions |
| User Role Modified | `/base/detections/binary/user_role_modified.py` | account_takeover, ransomware | Medium | Monitors user role modifications |
| Principal Removed from Group | `/base/detections/binary/principal_removed_from_group.py` | insider_threat, ransomware | Medium | Detects when principals are removed from groups |
| Account Admin Privileged Role Assignment | `/base/detections/binary/account_admin_privileged_role_assignment.py` | account_takeover, insider_threat, databricks_compromise | High | Detects direct account admin privilege grants or additions to account admin groups |
| Metastore Admin Privilege Granted | `/base/detections/binary/metastore_admin_privilege_granted.py` | account_takeover, insider_threat | High | Detects metastore ownership changes or additions to metastore admin groups |
| Workspace Admin Privileged Role Assignment | `/base/detections/binary/workspace_admin_privileged_role_assignment.py` | account_takeover, insider_threat, databricks_compromise | High | Detects workspace admin privilege grants or additions to the system admins group |

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

## Planned Detections (Not Yet Implemented)

These detections are planned for future implementation based on security requirements and threat landscape evolution.

### Planned Binary Detections

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
- **Binary (6)**: SSO Config Changed, Attempted Logon from Denied IP, User Admin Account Change, User Role Modified, Account Admin Privileged Role Assignment, Metastore Admin Privilege Granted, Workspace Admin Privileged Role Assignment
- **Behavioral (11)**: Non-SSO Login, Session Hijacking (3), Access Token Created/Deleted, MFA Key Added/Deleted, User Password Changed, Principal Added to Group, User Account Created

### Data Exfiltration (8 detections)
- **Binary (1)**: TruffleHog Scan Detected
- **Behavioral (7)**: Potential Data Movement (3 types), Secret Scanning, Token Scanning, Access Token Created, Spike in Table Admin Activity

### Insider Threat (17 detections)
- **Binary (9)**: Configuration Changes (3 types), Verbose Audit Logging Disabled, User Admin Account Change, User Account Deleted, Group Deleted, Principal Removed from Group, Account Admin Privileged Role Assignment, Metastore Admin Privilege Granted, Workspace Admin Privileged Role Assignment
- **Behavioral (8)**: Potential Data Movement (3 types), Spike in Table Admin Activity, Secret Scanning, Access Token Created

### Supply Chain Attacks (3 detections)
- **Binary (1)**: TruffleHog Scan Detected
- **Behavioral (2)**: Token Scanning, Secret Scanning

### Potential Compromise of Databricks (6 detections)
- **Binary (6)**: Databricks Employee Logon, Configuration Changes (Account Level), SSO Config Changed, User Admin Account Change, Account Admin Privileged Role Assignment, Workspace Admin Privileged Role Assignment
- **Behavioral (0)**: None

### Ransomware Attacks (9 detections)
- **Binary (7)**: Configuration Changes (3 types), User Account Deleted, Group Deleted, Principal Removed from Group, User Role Modified, Verbose Audit Logging Disabled
- **Behavioral (2)**: Spike in Table Admin Activity

### Resource Abuse (3 detections)
- **Binary (0)**: None
- **Behavioral (3)**: Spike in Table Admin Activity, User Account Created, Access Token Created

---

## Detection Statistics

- **Total Existing Detections**: 34
  - Binary: 16 (47%)
  - Behavioral: 18 (53%)

- **Total Planned Detections**: 20
  - Binary: 6
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
