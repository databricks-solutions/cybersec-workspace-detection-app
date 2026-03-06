# Databricks notebook source
# MAGIC %run ../../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: Kotaiba Alachkar
# MAGIC   created: '2026-02-06T12:00:00'
# MAGIC   modified: '2026-02-06T12:00:00'
# MAGIC   uuid: 2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Metastore Admin Privilege Granted
# MAGIC     description: Detects when metastore ownership is changed or when users/SPNs
# MAGIC       are added to designated metastore admin groups.
# MAGIC     objective: 'Identify metastore admin privilege grants through metastore
# MAGIC       ownership changes (updateMetastore with owner field) or by adding specific
# MAGIC       users/SPNs/nested groups to monitored metastore admin groups. Uses a configurable 
# MAGIC       widget to specify known metastore admin group names (comma-separated). Metastore
# MAGIC       admin is a high-level Unity Catalog privilege that grants complete control
# MAGIC       over managing catalogs, schemas, tables, views, and all data access permissions.
# MAGIC       Unauthorized grants could indicate privilege escalation attempts, insider threats,
# MAGIC       or compromised accounts attempting to establish persistence and gain unauthorized data access.'
# MAGIC     taxonomy:
# MAGIC       - MITRE.TA0003.Persistence
# MAGIC       - MITRE.T1098.Account_Manipulation
# MAGIC     fidelity: high
# MAGIC     category: DETECTION
# MAGIC     false_positives: Legitimate administrative actions by authorized account or
# MAGIC       metastore admins during normal user provisioning, role changes, or data
# MAGIC       governance restructuring.
# MAGIC     severity: high
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: metastore_admin_privilege_granted
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
# MAGIC ## Rule Coverage: metastore_admin_privilege_granted
# MAGIC
# MAGIC ### ✅ Covered Cases (Detected)
# MAGIC
# MAGIC | Scenario | Action | Detection Method |
# MAGIC |----------|--------|------------------|
# MAGIC | Metastore ownership changed | `updateMetastore` with owner field | Direct audit log query |
# MAGIC | User/SPN/Group added to specified metastore admin groups | `addPrincipalToGroup` or `addPrincipalsToGroup` | Widget-configured group list |
# MAGIC | User/SPN added to a child group of a monitored metastore admin group | `addPrincipalToGroup` or `addPrincipalsToGroup` | Transitive child group resolution (one level) |
# MAGIC | Any group membership change (no widget configured) | `addPrincipalToGroup` or `addPrincipalsToGroup` | All account-level group events captured for triage |
# MAGIC
# MAGIC **Optional:** set the `metastore_admin_groups` widget with comma-separated group names (e.g., `metastore-admins,unity-catalog-admins`) to scope group alerts. If left empty, all account-level group membership additions are captured.
# MAGIC
# MAGIC ### ❌ Uncovered Cases (NOT Detected)
# MAGIC
# MAGIC | Scenario | Recommendation |
# MAGIC |----------|----------------|
# MAGIC | User/SPN/Group added to metastore admin groups not in widget | Keep widget updated with all known metastore admin groups |
# MAGIC | User/SPN added to deeply nested groups (>1 level) that have metastore admin | Current resolution is one level deep; extend child group logic recursively if needed |
# MAGIC | Historical metastore admin group members before detection deployment | Run initial group membership audit at deployment |
# MAGIC
# MAGIC **Important Notes:**
# MAGIC - This detection focuses on **metastore ownership changes** and **group membership additions** that are logged in audit events
# MAGIC - Child group resolution looks back at full audit history (unbounded) to find groups nested inside monitored metastore admin groups
# MAGIC - For complete coverage, supplement with periodic group entitlement audits
# MAGIC - Keep the `metastore_admin_groups` widget parameter updated as new metastore admin groups are created

# COMMAND ----------

@detect(output=Output.asDataFrame)
def metastore_admin_privilege_granted(earliest: str = None, latest: str = None, metastore_admin_groups: str = ""):
    from pyspark.sql.functions import (col, current_timestamp, expr, to_timestamp,
                                       lit, coalesce, when, struct, to_json)
    import uuid

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()

    direct_metastore_admin_actions = [
        'updateMetastore'
    ]

    group_membership_actions = [
        'addPrincipalToGroup',
        'addPrincipalsToGroup'
    ]

    df = spark.table("system.access.audit")

    df_direct = df.filter(
        (col("event_time").between(earliest, latest)) &
        (col("action_name").isin(direct_metastore_admin_actions)) &
        (col("request_params.owner").isNotNull())
    )

    if metastore_admin_groups and metastore_admin_groups.strip():
        group_list = [g.strip() for g in metastore_admin_groups.split(",") if g.strip()]

        # Resolve one level of nested groups: find any non-user principals
        # (i.e. child groups) that were added to a monitored metastore admin group in
        # audit history, and add them to the filter list.
        _uuid_pat = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        _email_pat = ".*@.*"
        _base = (
            (col("service_name") == "accounts") &
            (col("action_name").isin(group_membership_actions)) &
            (col("request_params.targetGroupName").isin(group_list))
        )
        child_via_principal = df.filter(
            _base &
            col("request_params.principal").isNotNull() &
            (~col("request_params.principal").rlike(_email_pat)) &
            (~col("request_params.principal").rlike(_uuid_pat))
        ).select(col("request_params.principal").alias("child_group"))

        child_via_target_user = df.filter(
            _base &
            col("request_params.targetUserName").isNotNull() &
            (~col("request_params.targetUserName").rlike(_email_pat)) &
            (~col("request_params.targetUserName").rlike(_uuid_pat))
        ).select(col("request_params.targetUserName").alias("child_group"))

        child_group_rows = child_via_principal.union(child_via_target_user).distinct().collect()
        child_groups = [row["child_group"] for row in child_group_rows]
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
        when(col("request_params.target_user_name").isNotNull(), col("request_params.target_user_name"))
        .when(col("request_params.targetUserName").isNotNull(), col("request_params.targetUserName"))
        .when(col("request_params.owner").isNotNull(), col("request_params.owner"))
        .when(col("request_params.principal").isNotNull(), col("request_params.principal"))
        .otherwise(lit(None)).alias("TARGET_PRINCIPAL_NAME"),
        col("request_params.targetUserId").alias("TARGET_USER_ID"),
        col("request_params.metastore_id").alias("METASTORE_ID"),
        col("request_params.name").alias("METASTORE_NAME"),
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
    dbutils.widgets.text("metastore_admin_groups", "", "Metastore Admin Groups (comma-separated)")

    metastore_admin_groups = dbutils.widgets.get("metastore_admin_groups")

    display(metastore_admin_privilege_granted(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest"),
        metastore_admin_groups=metastore_admin_groups
    ))

# COMMAND ----------
