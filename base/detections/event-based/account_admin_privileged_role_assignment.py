# Databricks notebook source
# MAGIC %run ../../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: Kotaiba Alachkar
# MAGIC   created: '2026-02-06T12:00:00'
# MAGIC   modified: '2026-02-06T12:00:00'
# MAGIC   uuid: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Account Admin Privileged Role Assignment
# MAGIC     description: Detects when account admin privileges are assigned to specific users
# MAGIC       or service principals through direct privilege grants, or when users/SPNs are
# MAGIC       added to designated account admin groups.
# MAGIC     objective: 'Identify targeted and granular account admin privilege grants through
# MAGIC       direct assignment to individual principals (setAccountAdmin, setAdmin), account
# MAGIC       ownership changes (changeAccountOwner), or by adding specific users/SPNs to
# MAGIC       monitored account admin groups. Uses a configurable widget to specify known
# MAGIC       account admin group names (comma-separated). This detection focuses on individual
# MAGIC       and targeted privilege escalation events rather than group-level role assignments.
# MAGIC       Account admin is the highest privilege level in Databricks and grants complete
# MAGIC       control over workspace management, billing, user management, and security settings.
# MAGIC       Unauthorized grants could indicate privilege escalation attempts, insider threats,
# MAGIC       or compromised accounts attempting to establish persistence.'
# MAGIC     taxonomy:
# MAGIC       - MITRE.TA0003.Persistence
# MAGIC       - MITRE.T1098.Account_Manipulation
# MAGIC     fidelity: high
# MAGIC     category: DETECTION
# MAGIC     false_positives: Legitimate administrative actions by authorized account admins
# MAGIC       during normal user provisioning, role changes, or organizational restructuring.
# MAGIC       Ensure the admin_groups parameter includes only groups that actually have
# MAGIC       account admin entitlements to reduce false positives.
# MAGIC     severity: high
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: account_admin_privileged_role_assignment
# MAGIC     input:
# MAGIC       earliest: '2025-01-01'
# MAGIC       latest: '2026-02-25'
# MAGIC     expect:
# MAGIC       count: '>=0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs:
# MAGIC     - table: system.access.audit
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - alert_id
# MAGIC     - alertTime
# MAGIC     - eventTime
# MAGIC     - src_user
# MAGIC     - event_type
# MAGIC     - principal_type
# MAGIC     - target_principal
# MAGIC     - source_ip
# MAGIC     - event_data
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC ## Rule Coverage: account_admin_privileged_role_assignment
# MAGIC
# MAGIC ### ✅ Covered Cases (Detected)
# MAGIC
# MAGIC | Scenario | Action | Detection Method |
# MAGIC |----------|--------|------------------|
# MAGIC | User granted account admin directly | `setAccountAdmin` | Direct audit log query |
# MAGIC | SPN granted account admin directly | `setAccountAdmin` | Direct audit log query |
# MAGIC | Account ownership changed | `changeAccountOwner` | Direct audit log query |
# MAGIC | User/SPN/Group added to specified admin groups | `addPrincipalToGroup` or `addPrincipalsToGroup` | Widget-configured group list |
# MAGIC | User/SPN added to a child group of a monitored admin group | `addPrincipalToGroup` or `addPrincipalsToGroup` | Transitive child group resolution (one level) |
# MAGIC | Any group membership change (no widget configured) | `addPrincipalToGroup` or `addPrincipalsToGroup` | All account-level group events captured for triage |
# MAGIC
# MAGIC **Optional:** set the `admin_groups` widget with comma-separated group names (e.g., `admins,account-administrators`) to scope group alerts. If left empty, all account-level group membership additions are captured.
# MAGIC
# MAGIC ### ❌ Uncovered Cases (NOT Detected)
# MAGIC
# MAGIC | Scenario | Recommendation |
# MAGIC |----------|----------------|
# MAGIC | Group granted account admin role/entitlements | Periodic manual review of group entitlements via Admin Console or API |
# MAGIC | User/SPN/Group added to admin groups not in widget | Keep widget updated with all known admin groups |
# MAGIC | User/SPN added to deeply nested groups (>1 level) that have account admin | Current resolution is one level deep; extend child group logic recursively if needed |
# MAGIC | Historical admin group members before detection deployment | Run initial group membership audit at deployment |
# MAGIC
# MAGIC **Important Notes:**
# MAGIC - This detection focuses on **individual privilege assignments** that are logged in audit events
# MAGIC - Child group resolution looks back at full audit history (unbounded) to find groups nested inside monitored admin groups
# MAGIC - For complete coverage, supplement with periodic group entitlement audits
# MAGIC - Keep the `admin_groups` widget parameter updated as new admin groups are created

# COMMAND ----------


@detect(output=Output.asDataFrame)
def account_admin_privileged_role_assignment(earliest: str = None, latest: str = None, admin_groups: str = ""):
    from pyspark.sql.functions import (col, current_timestamp, expr, to_timestamp,
                                       lit, coalesce, when, struct, to_json)
    import uuid

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()

    direct_admin_actions = [
        'setAccountAdmin',
        'changeAccountOwner'
    ]

    group_membership_actions = [
        'addPrincipalToGroup',
        'addPrincipalsToGroup'
    ]

    df = spark.table("system.access.audit")

    df_direct = df.filter(
        (col("event_time").between(earliest, latest)) &
        (col("service_name") == "accounts") &
        (col("action_name").isin(direct_admin_actions))
    )

    if admin_groups and admin_groups.strip():
        group_list = [g.strip() for g in admin_groups.split(",") if g.strip()]

        # Resolve one level of nested groups: find any non-user principals
        # (i.e. child groups) that were added to a monitored admin group in
        # audit history, and add them to the filter list.
        child_group_rows = df.filter(
            (col("service_name") == "accounts") &
            (col("action_name").isin(group_membership_actions)) &
            (col("request_params.targetGroupName").isin(group_list)) &
            col("request_params.principal").isNotNull() &
            (~col("request_params.principal").rlike(".*@.*")) &
            (~col("request_params.principal").rlike(
                "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
            ))
        ).select("request_params.principal").distinct().collect()

        child_groups = [row["principal"] for row in child_group_rows]
        expanded_group_list = list(set(group_list + child_groups))

        df_group_additions = df.filter(
            (col("event_time").between(earliest, latest)) &
            (col("service_name") == "accounts") &
            (col("action_name").isin(group_membership_actions)) &
            (col("request_params.targetGroupName").isin(expanded_group_list))
        )

        df_combined = df_direct.unionByName(df_group_additions, allowMissingColumns=True)
    else:
        # No admin groups configured — capture all account-level group membership
        # events for manual triage rather than silently dropping them.
        df_all_group_additions = df.filter(
            (col("event_time").between(earliest, latest)) &
            (col("service_name") == "accounts") &
            (col("action_name").isin(group_membership_actions))
        )
        df_combined = df_direct.unionByName(df_all_group_additions, allowMissingColumns=True)

    df_detailed = df_combined.select(
        to_timestamp(col("event_time")).alias("EVENT_DATE"),
        col("user_identity.email").alias("SRC_USER"),
        col("action_name").alias("ACTION"),
        col("source_ip_address").alias("SRC_IP"),
        col("service_name").alias("SERVICE_NAME"),
        coalesce(
            col("request_params.target_user_name"),
            col("request_params.targetUserName"),
            col("request_params.principal")
        ).alias("TARGET_PRINCIPAL_NAME"),
        col("request_params.targetUserId").alias("TARGET_USER_ID"),
        col("request_params.endpoint").alias("ENDPOINT"),
        col("request_params.targetGroupName").alias("TARGET_GROUP_NAME"),
        col("request_params.targetServicePrincipalName").alias("TARGET_SPN_NAME"),
        col("request_params.roles").alias("ROLES_ASSIGNED"),
        col("user_agent").alias("USER_AGENT"),
        col("workspace_id").alias("WORKSPACE_ID"),
        col("account_id").alias("ACCOUNT_ID"),
        col("request_id").alias("REQUEST_ID"),
        col("response.status_code").alias("STATUS_CODE"),
        col("response.error_message").alias("ERROR_MESSAGE"),
        col("audit_level").alias("AUDIT_LEVEL"),
        col("user_identity").alias("USER_IDENTITY"),
        col("request_params").alias("REQUEST_PARAMS"),
        col("response").alias("RESPONSE")
    )

    df_alert = df_detailed.select(
        lit(str(uuid.uuid4())).alias("alert_id"),
        current_timestamp().alias("alertTime"),
        col("EVENT_DATE").alias("eventTime"),
        col("SRC_USER").alias("src_user"),
        col("ACTION").alias("event_type"),
        when(col("TARGET_PRINCIPAL_NAME").rlike(".*@.*"), lit("User"))
            .when(col("TARGET_PRINCIPAL_NAME").rlike("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"), lit("SPN"))
            .otherwise(lit("Group")).alias("principal_type"),
        coalesce(col("TARGET_PRINCIPAL_NAME"), lit("N/A")).alias("target_principal"),
        col("SRC_IP").alias("source_ip"),
        to_json(struct([col(c) for c in df_detailed.columns])).alias("event_data")
    ).orderBy(col("eventTime").desc())

    return df_alert

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    dbutils.widgets.text("admin_groups", "admins", "Account Admin Groups (comma-separated)")

    admin_groups = dbutils.widgets.get("admin_groups")

    display(account_admin_privileged_role_assignment(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest"),
        admin_groups=admin_groups
    ))
