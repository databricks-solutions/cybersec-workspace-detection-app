# Databricks Detection Tool

A collection of security detection notebooks for Databricks workspaces that analyze the `system.access.audit` table to identify potential security threats and suspicious activities.

## Quick Start

### What's Inside

This tool provides **34 security detections** organized by urgency and investigation approach:
- **16 Binary Detections** - High-confidence alerts for immediate response (24-hour default window)
- **18 Behavioral Detections** - Pattern analysis for threat hunting (30-day default window)

### Three Ways to Use This Tool

1. **🎯 Threat Model Investigations** - Generate investigation notebooks for 7 specific threat scenarios (Recommended for newcomers)
2. **📊 User Behavior Analysis** - Generate user-specific activity reports
3. **🔍 Individual Detections** - Execute specific detection notebooks for targeted analysis

👉 **New to this tool?** Start with [Threat Model Investigations](#threat-model-investigations) to investigate common security scenarios.

---

## Repository Structure

```
cybersec-workspace-detection-app/
├── base/
│   ├── detections/
│   │   ├── binary/          # 16 immediate alert detections (24-hour window)
│   │   └── behavioral/      # 18 threat hunting detections (30-day window)
│   └── notebooks/
│       ├── threat_models/   # 7 threat model notebook generators
│       │   ├── threat_model_account_takeover.py
│       │   ├── threat_model_data_exfiltration.py
│       │   └── ... (5 more)
│       ├── user_behavior_analysis.py  # User investigation generator
│       └── run_all_detections.py      # Batch execution utility
├── lib/
│   ├── common.py            # Shared detection utilities
│   ├── threat_model_mappings.py  # Detection-to-threat-model mappings
│   └── notebook_generator_base.py  # Notebook generation logic
└── docs/
    └── detection_tracker.md # Complete detection inventory
```

---

## Threat Model Investigations

Generate focused investigation notebooks combining multiple detections for specific threat scenarios. Based on [Databricks Security Best Practices](https://www.databricks.com/trust/security-features/best-practices).

### Available Threat Models

| Threat Model | Detections | Risk Description (Source: Databricks SBP) |
|-------------|-----------|-------------------------------------------|
| **Account Takeover or Compromise** | 17 detections | Databricks is a general-purpose compute platform that customers can set up to access critical data sources. If credentials belonging to a user were compromised by phishing, brute force, or other methods, an attacker might get access to all of the data accessible by the compromised user from the environment. |
| **Data Exfiltration** | 8 detections | If a malicious user or an attacker is able to log into a customer's environment, they may be able to exfiltrate sensitive data and then store it, sell it, or ransom it. |
| **Insider Threat** | 14 detections | High-performing engineers and data professionals will generally find the best or fastest way to complete their tasks, but sometimes that may do so in ways that create security impacts to their organizations. One user may think their job would be much easier if they didn't have to deal with security controls, or another might copy some data to simplify sharing of data. |
| **Supply Chain Attacks** | 3 detections | Historically, supply chain attacks have relied upon injecting malicious code into software libraries. More recently, we have started to see the emergence of AI model and data supply chain attacks, whereby the model, its weights or the data itself is maliciously altered. |
| **Potential Compromise of Databricks** | 4 detections | Security-minded customers sometimes voice a concern that Databricks itself might be compromised, which could result in the compromise of their environment. |
| **Ransomware Attacks** | 9 detections | Ransomware is a type of malware designed to deny an individual or organization access to their data, usually for the purposes of extortion. Encryption is often used as the vehicle for this attack. |
| **Resource Abuse** | 3 detections | Databricks can deploy large amounts of compute power. As such, it could be a valuable target for crypto mining if a customer's user account were compromised. |

### How to Generate a Threat Model Investigation

**Step 1: Run a Threat Model Generator**

Execute one of the 7 generator notebooks from your Databricks workspace:

```python
# Example: Generate Account Takeover investigation notebook
dbutils.notebook.run(
    "/Workspace/Repos/.../base/notebooks/threat_models/threat_model_account_takeover",
    timeout=3600,
    arguments={
        "time_range_days": "30",        # Window for behavioral detections
        "binary_time_range_hours": "24" # Window for binary detections
    }
)
```

**Step 2: Review Generated Notebook**

The generator creates a timestamped investigation notebook in `/generated/` containing:
- All relevant detections for that threat model
- Appropriate time windows for each detection type
- Detection metadata and risk descriptions
- Summary statistics

**Step 3: Execute Generated Notebook**

Run the generated notebook to execute all detections and review findings.

### Available Generators

```
/base/notebooks/threat_models/threat_model_account_takeover.py
/base/notebooks/threat_models/threat_model_data_exfiltration.py
/base/notebooks/threat_models/threat_model_insider_threat.py
/base/notebooks/threat_models/threat_model_supply_chain.py
/base/notebooks/threat_models/threat_model_databricks_compromise.py
/base/notebooks/threat_models/threat_model_ransomware.py
/base/notebooks/threat_models/threat_model_resource_abuse.py
```

**NOTE:** While activity might be shown, it does not automatically mean that malicious activity has occurred. It is important to investigate results in coordination with your usage of Databricks.

---

## User Behavior Analysis

Run user-specific analysis to examine all activities for a specific user across all detections.

Open and run the notebook directly in your Databricks workspace:

```
/base/notebooks/user_behavior_analysis.py
```

When prompted, provide the following parameters:
- **user_email**: Email address of the user to analyze
- **time_range_days**: Number of days to look back (default: 30)

The notebook will run all detections filtered to the specified user and display results inline.

---

## Detection Categories

### Binary Detections (16 Total)

**Purpose**: Immediate alerts for high-confidence security events
**Time Window**: 24 hours (configurable)
**Use Case**: Real-time monitoring and alerting

> **Note:** Events generated by these detections do not automatically indicate malicious activity. Many events occur during normal platform usage (e.g., configuration changes by admins, user management operations). Always investigate results in the context of your organization's expected Databricks usage patterns.

#### Configuration & Policy Changes (7)
- SSO Configuration Changes - `/base/detections/binary/sso_config_changed.py`
- Workspace-Level Configuration Changes - `/base/detections/binary/configuration_changes_workspace_level.py`
- Account-Level Configuration Changes - `/base/detections/binary/configuration_changes_account_level.py`
- High Priority Configuration Changes - `/base/detections/binary/configuration_changes_high_priority.py`
- Verbose Audit Logging Disabled - `/base/detections/binary/verbose_audit_logging_disabled.py`
- Attempted Logon from Denied IP - `/base/detections/binary/attempted_logon_from_denied_ip.py`
- Databricks Employee Logon Detection - `/base/detections/binary/databricks_employee_logon.py`

#### Identity & Access Management (9)
- User Admin Account Changes - `/base/detections/binary/user_admin_account_change.py`
- User Role Modifications - `/base/detections/binary/user_role_modified.py`
- User Account Deletion - `/base/detections/binary/user_account_deleted.py`
- Group Deletion - `/base/detections/binary/group_deleted.py`
- Principal Removed from Group - `/base/detections/binary/principal_removed_from_group.py`
- TruffleHog Scan Detected - `/base/detections/binary/trufflehog_scan_detected.py`
- Account Admin Privileged Role Assignment - `/base/detections/binary/account_admin_privileged_role_assignment.py`
- Metastore Admin Privilege Granted - `/base/detections/binary/metastore_admin_privilege_granted.py`
- Workspace Admin Privileged Role Assignment - `/base/detections/binary/workspace_admin_privileged_role_assignment.py`

### Behavioral Detections (18 Total)

**Purpose**: Pattern analysis and threat hunting
**Time Window**: 30 days (configurable)
**Use Case**: Investigation and anomaly detection

> **Note:** Events generated by these detections do not automatically indicate malicious activity. Many events occur during normal platform usage (e.g., token creation, MFA changes, group management). Always investigate results in the context of your organization's expected Databricks usage patterns.

#### Authentication & Session Patterns (6)
- Non-SSO Login Detection - `/base/detections/behavioral/non_sso_login_detected.py`
- Session Hijacking (Multi-Device) - `/base/detections/behavioral/session_hijacking_multi_device.py`
- Session Hijacking (Frequent Logins) - `/base/detections/behavioral/session_hijacking_frequent_logins.py`
- Session Hijacking (High Session Count) - `/base/detections/behavioral/session_hijacking_session_count.py`
- MFA Key Added - `/base/detections/behavioral/mfa_key_added.py`
- MFA Key Deleted - `/base/detections/behavioral/mfa_key_deleted.py`

#### Token & Credential Management (4)
- Access Token Created - `/base/detections/behavioral/access_token_created.py`
- Access Token Deleted - `/base/detections/behavioral/access_token_deleted.py`
- Token Scanning Activity - `/base/detections/behavioral/token_scanning_activity.py`
- Secret Scanning Activity - `/base/detections/behavioral/secret_scanning_activity.py`

#### Data Movement & Exfiltration (3)
- Potential Data Movement via SQL Queries - `/base/detections/behavioral/potential_data_movement_sql_queries.py`
- Potential Data Movement via Workspace Downloads - `/base/detections/behavioral/potential_data_movement_workspace_downloads.py`
- Potential Data Movement via Explicit Credentials - `/base/detections/behavioral/potential_data_movement_explicit_creds.py`

#### User & Group Management (5)
- User Account Created - `/base/detections/behavioral/user_account_created.py`
- User Password Changed - `/base/detections/behavioral/user_password_changed.py`
- Group Created - `/base/detections/behavioral/group_created.py`
- Principal Added to Group - `/base/detections/behavioral/principal_added_to_group.py`
- Spike in Table Admin Activity - `/base/detections/behavioral/spike_in_table_admin_activity.py`

---

## Running Individual Detections

Each detection notebook can be run independently for targeted analysis.

### Binary Detection Example

High-confidence immediate alert:

```python
# File: /base/detections/binary/sso_config_changed.py
result = sso_config_changed(
    earliest="2025-01-28T00:00:00",  # Last 24 hours
    latest="2025-01-29T00:00:00"
)
display(result)
```

### Behavioral Detection Example

Pattern analysis for threat hunting:

```python
# File: /base/detections/behavioral/potential_data_movement_sql_queries.py
result = potential_data_movement_sql_queries(
    earliest="2024-12-30T00:00:00",  # Last 30 days
    latest="2025-01-29T00:00:00"
)
display(result)
```

---

## Installation

### Prerequisites
- Databricks workspace with Unity Catalog enabled
- Access to `system.access.audit` table
- Appropriate permissions to create and run workflows

### Setup

1. **Clone Repository**: Import to your Databricks workspace
   ```
   Repos → Add Repo → [GitHub URL]
   ```

2. **Review Detection Tracker**: See `/docs/detection_tracker.md` for complete detection inventory

3. **Choose Your Approach**:
   - **Recommended**: Start with threat model notebooks for comprehensive investigations
   - **Alternative**: Run individual detections for targeted analysis
   - **User-Specific**: Generate user behavior reports for specific users

---

## Architecture

### Core Components
- **Detection Notebooks** - Individual security detection logic
- **Common Library** - Shared utilities and enrichment functions
- **Audit Table Integration** - Direct queries against `system.access.audit`

### Data Sources
- `system.access.audit` - Primary audit log table
- `system.query.history` - Query execution history (some detections)

### Dependencies
- **PySpark** - Core data processing framework
- **PyYAML** - YAML parsing for detection metadata
- **GeoIP2** - IP address geolocation capabilities (optional)
- **NetAddr** - IP address manipulation utilities

---

## Additional Resources

- **[Databricks Security Best Practices](https://www.databricks.com/trust/security-features/best-practices)** - Official security guidance
- **[Detection Tracker](/docs/detection_tracker.md)** - Complete detection inventory with current and planned detections
- **[Security Analysis Tool (SAT)](https://github.com/databricks-industry-solutions/security-analysis-tool)** - Automated security configuration monitoring

---

## How to Get Help

Databricks support doesn't cover this content. For questions or bugs, please open a GitHub issue and the team will help on a best effort basis.

---

## License

© 2025 Databricks, Inc. All rights reserved. The source in this notebook is provided subject to the Databricks License [https://databricks.com/db-license-source]. All included or referenced third party libraries are subject to the licenses set forth below.

| library  | description             | license    | source                                              |
|----------|-------------------------|------------|-----------------------------------------------------|
| pyyaml   | YAML parsing           | MIT        | https://github.com/yaml/pyyaml                     |
| geoip2   | IP address geolocation | Apache 2.0 | https://github.com/maxmind/GeoIP2-python           |
| netaddr  | IP address manipulation| BSD        | https://github.com/netaddr/netaddr                 |
