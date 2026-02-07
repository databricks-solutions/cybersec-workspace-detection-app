# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: Kotaiba Alachkar
# MAGIC   created: '2026-02-07T12:00:00'
# MAGIC   modified: '2026-02-07T12:00:00'
# MAGIC   uuid: 3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Workspace Admin Privileged Role Assignment
# MAGIC     description: Detects when workspace admin privileges are assigned to users/SPNs
# MAGIC       through direct admin entitlement grants or additions to the workspace admins group.
# MAGIC     objective: 'Identify workspace admin privilege grants through two mechanisms: (1)
# MAGIC       Direct admin entitlement assignment (setAdmin, addAdmin) which automatically adds
# MAGIC       principals to the admins group, or (2) Direct addition of users/SPNs to
# MAGIC       the system reserved "admins" group. The "admins" group is a fixed system group
# MAGIC       in every Databricks workspace that cannot be removed. Workspace admin grants full
# MAGIC       administrative control over workspace resources including clusters, jobs, notebooks,
# MAGIC       repos, and workspace settings. Unauthorized grants could indicate privilege
# MAGIC       escalation attempts, insider threats, or compromised accounts attempting to
# MAGIC       establish persistence.'
# MAGIC     taxonomy:
# MAGIC       - MITRE.TA0003.Persistence
# MAGIC       - MITRE.T1098.Account_Manipulation
# MAGIC     fidelity: high
# MAGIC     category: DETECTION
# MAGIC     false_positives: Legitimate administrative actions by authorized workspace admins
# MAGIC       during normal user provisioning, role changes, or organizational restructuring.
# MAGIC     severity: high
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: workspace_admin_privileged_role_assignment
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
# MAGIC     - workspace
# MAGIC     - source_ip
# MAGIC     - event_data
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC ## Rule Coverage: workspace_admin_privileged_role_assignment
# MAGIC
# MAGIC ### ✅ Covered Cases (Detected)
# MAGIC
# MAGIC | Scenario | Action | Detection Method |
# MAGIC |----------|--------|------------------|
# MAGIC | User/SPN granted workspace admin via direct entitlement (auto-adds to admins group) | `setAdmin` or `addAdmin` | Direct audit log query |
# MAGIC | User/SPN added directly to system "admins" group | `addPrincipalToGroup` or `addPrincipalsToGroup` | Monitors fixed system group "admins" |
# MAGIC
# MAGIC **Note:** The "admins" group is a fixed system-reserved group in every Databricks workspace that grants workspace admin privileges.
# MAGIC
# MAGIC ### ❌ Uncovered Cases (NOT Detected)
# MAGIC
# MAGIC | Scenario | Recommendation |
# MAGIC |----------|----------------|
# MAGIC | Historical workspace admin group members before detection deployment | Run initial group membership audit at deployment |
# MAGIC
# MAGIC **Important Notes:**
# MAGIC - This detection monitors both direct admin entitlement assignments AND the fixed "admins" system group
# MAGIC - Direct admin entitlement assignment automatically adds principals to the "admins" group (both events detected)
# MAGIC - For complete coverage, supplement with periodic group entitlement audits

# COMMAND ----------

@detect(output=Output.asDataFrame)
def workspace_admin_privileged_role_assignment(earliest: str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_timestamp, expr, to_timestamp,
                                       lit, coalesce, when, struct, to_json)
    import uuid

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()

    direct_admin_actions = [
        'setAdmin',
        'addAdmin'
    ]

    group_membership_actions = [
        'addPrincipalToGroup',
        'addPrincipalsToGroup'
    ]

    df = spark.table("system.access.audit")

    df_direct = df.filter(
        (col("event_time").between(earliest, latest)) &
        (col("action_name").isin(direct_admin_actions))
    )

    df_group_additions = df.filter(
        (col("event_time").between(earliest, latest)) &
        (col("service_name") == "accounts") &
        (col("action_name").isin(group_membership_actions)) &
        (col("request_params.targetGroupName") == "admins")
    )

    df_combined = df_direct.unionByName(df_group_additions, allowMissingColumns=True)

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
        col("request_params.target_group_name").alias("TARGET_GROUP_NAME"),
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
        col("WORKSPACE_ID").alias("workspace"),
        col("SRC_IP").alias("source_ip"),
        to_json(struct([col(c) for c in df_detailed.columns])).alias("event_data")
    ).orderBy(col("eventTime").desc())

    return df_alert

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()

    display(workspace_admin_privileged_role_assignment(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))

# COMMAND ----------
