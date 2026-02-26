# Databricks notebook source
# MAGIC %md
# MAGIC # Threat Model Mappings
# MAGIC
# MAGIC This file contains:
# MAGIC - Official risk descriptions from Databricks Security Best Practices
# MAGIC - Mappings of detections to threat models
# MAGIC
# MAGIC Source: Databricks Security Best Practices for AWS (Version 2.2 - December 2025)

# COMMAND ----------

# Risk descriptions sourced from Databricks Security Best Practices for AWS (Version 2.2 - December 2025)
THREAT_MODEL_RISK_DESCRIPTIONS = {
    "account_takeover": "Databricks is a general-purpose compute platform that customers can set up to access critical data sources. If credentials belonging to a user at one of our customers were compromised by phishing, brute force, or other methods, an attacker might get access to all of the data accessible from the environment.",

    "data_exfiltration": "If a malicious user or an attacker is able to log into a customer's environment, they may be able to exfiltrate sensitive data and then store it, sell it, or ransom it.",

    "insider_threat": "High-performing engineers and data professionals will generally find the best or fastest way to complete their tasks, but sometimes that may do so in ways that create security impacts to their organizations. One user may think their job would be much easier if they didn't have to deal with security controls, or another might copy some data to a public storage account or other cloud resource to simplify sharing of data. We can provide education for these users, but companies should also consider providing guardrails.",

    "supply_chain": "Historically, supply chain attacks have relied upon injecting malicious code into software libraries. That code is then executed without the knowledge of the unsuspecting target. More recently, however, we have started to see the emergence of AI model and data supply chain attacks, whereby the model, its weights or the data itself is maliciously altered.",

    "databricks_compromise": "Security-minded customers sometimes voice a concern that Databricks itself might be compromised, which could result in the compromise of their environment.",

    "ransomware": "Ransomware is a type of malware designed to deny an individual or organization access to their data, usually for the purposes of extortion. Encryption is often used as the vehicle for this attack. In recent years, there have been several high profile ransomware attacks that have brought large organizations to their knees.",

    "resource_abuse": "Databricks can deploy large amounts of compute power. As such, it could be a valuable target for crypto mining if a customer's user account were compromised."
}

# COMMAND ----------

# Mappings from threat models to detection file paths (relative to base/detections/)
# Detection paths use the format "binary/filename" or "behavioral/filename" (without .py extension)
THREAT_MODEL_MAPPINGS = {
    "account_takeover": [
        # Authentication & credential compromise
        "behavioral/non_sso_login_detected",
        "binary/attempted_logon_from_denied_ip",
        "binary/sso_config_changed",

        # Token abuse
        "behavioral/access_token_created",
        "behavioral/access_token_deleted",

        # MFA bypass
        "behavioral/mfa_key_deleted",
        "behavioral/mfa_key_added",
        "behavioral/user_password_changed",

        # Session hijacking
        "behavioral/session_hijacking_multi_device",
        "behavioral/session_hijacking_frequent_logins",
        "behavioral/session_hijacking_session_count",

        # Privilege escalation
        "binary/user_admin_account_change",
        "binary/user_role_modified",
        "binary/account_admin_privileged_role_assignment",
        "binary/metastore_admin_privilege_granted",
        "binary/workspace_admin_privileged_role_assignment",
        "behavioral/principal_added_to_group",
        "behavioral/user_account_created"
    ],

    "data_exfiltration": [
        # Data movement patterns
        "behavioral/potential_data_movement_explicit_creds",
        "behavioral/potential_data_movement_sql_queries",
        "behavioral/potential_data_movement_workspace_downloads",

        # Credential/token abuse
        "behavioral/access_token_created",
        "behavioral/secret_scanning_activity",
        "binary/trufflehog_scan_detected",
        "behavioral/token_scanning_activity",

        # High data access
        "behavioral/spike_in_table_admin_activity"
    ],

    "insider_threat": [
        # Data movement/exfiltration
        "behavioral/potential_data_movement_explicit_creds",
        "behavioral/potential_data_movement_sql_queries",
        "behavioral/potential_data_movement_workspace_downloads",

        # Administrative abuse & privilege escalation
        "binary/user_admin_account_change",
        "binary/configuration_changes_high_priority",
        "binary/configuration_changes_account_level",
        "binary/configuration_changes_workspace_level",
        "binary/account_admin_privileged_role_assignment",
        "binary/metastore_admin_privilege_granted",
        "binary/workspace_admin_privileged_role_assignment",

        # Audit evasion
        "binary/verbose_audit_logging_disabled",

        # Destructive activities
        "binary/user_account_deleted",
        "binary/group_deleted",
        "binary/principal_removed_from_group",

        # Suspicious patterns
        "behavioral/spike_in_table_admin_activity",
        "behavioral/secret_scanning_activity",
        "behavioral/access_token_created"
    ],

    "supply_chain": [
        # Credential scanning (detecting compromised secrets in code/libraries)
        "binary/trufflehog_scan_detected",
        "behavioral/token_scanning_activity",
        "behavioral/secret_scanning_activity"
    ],

    "databricks_compromise": [
        # Databricks employee access monitoring
        "binary/databricks_employee_logon",

        # Account-level configuration changes
        "binary/configuration_changes_account_level",
        "binary/sso_config_changed",
        "binary/user_admin_account_change",
        "binary/account_admin_privileged_role_assignment",
        "binary/workspace_admin_privileged_role_assignment"
    ],

    "ransomware": [
        # Configuration tampering to disrupt access
        "binary/configuration_changes_high_priority",
        "binary/configuration_changes_account_level",
        "binary/configuration_changes_workspace_level",

        # Destructive activities to deny access
        "binary/user_account_deleted",
        "binary/group_deleted",
        "binary/principal_removed_from_group",
        "binary/user_role_modified",
        "behavioral/spike_in_table_admin_activity",

        # Audit evasion
        "binary/verbose_audit_logging_disabled"
    ],

    "resource_abuse": [
        # Unusual compute/resource usage patterns
        "behavioral/spike_in_table_admin_activity",

        # Suspicious account/token creation
        "behavioral/user_account_created",
        "behavioral/access_token_created"
    ]
}

# COMMAND ----------
