# Databricks notebook source
# MAGIC %run ../../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: Derek King - Databricks
# MAGIC   created: '2025-05-09T12:56:50'
# MAGIC   modified: '2025-05-09T12:56:50'
# MAGIC   uuid: 5f9ae8gc-6gch-535d-aa0f-33f7fgcc6556
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: High Priority Configuration Changes
# MAGIC     description: 'Detects high-priority configuration changes including verbose audit 
# MAGIC       logging modifications, IP access list changes, and customer-approved workspace 
# MAGIC       login configuration updates that could impact security posture.
# MAGIC 
# MAGIC       '
# MAGIC     objective: 'Monitor critical configuration changes that could weaken security 
# MAGIC       controls, modify access policies, or reduce system visibility. This includes 
# MAGIC       verbose audit logging being disabled, IP access list modifications, and 
# MAGIC       customer-approved workspace login configuration changes which may signal 
# MAGIC       attacker evasion, insider threat activity, or unauthorized configuration 
# MAGIC       tampering.
# MAGIC 
# MAGIC       '
# MAGIC     taxonomy: 
# MAGIC       - MITRE.TA0004.Privilege_Escalation
# MAGIC       - MITRE.T1484.Domain_or_Tenant_Policy_Modification
# MAGIC     fidelity: high
# MAGIC     category: DETECTION
# MAGIC     false_positives: admins reconfiguring workspaces. Consider coping to production or sensitive workspaces.
# MAGIC     severity: medium
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: configuration_changes_high_priority
# MAGIC     input:
# MAGIC       earliest: '2025-01-01'
# MAGIC       latest: '2025-02-25'
# MAGIC     expect:
# MAGIC       count: '>0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs:
# MAGIC     - table: system.access.audit
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - EVENT_DATE
# MAGIC     - action_name
# MAGIC     - audit_level
# MAGIC     - event_time
# MAGIC     - request_params
# MAGIC     - response.status_code
# MAGIC     - service_name
# MAGIC     - source_ip_address
# MAGIC     - user_agent
# MAGIC     - user_identity.email
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def configuration_changes_high_priority(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_date, date_sub, to_date, current_timestamp, 
                                       expr, unix_timestamp, round, from_unixtime, when, to_timestamp,
                                       lit, concat, coalesce)

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()

    # One workspaceConfEdit can carry several settings: workspaceConfKeys and workspaceConfValues
    # are comma-joined in matching positions (e.g. "enableProjectsAllowList,projectsAllowListPermissions"
    # / "false,ALL_REPOS"). Comparing the whole key string with "=" let a security setting changed in
    # the same request as another one through, so pair keys and values by position.
    disables_control = expr("""exists(transform(split(COALESCE(request_params['workspaceConfKeys'], ''), ','), (k, i) -> named_struct('key', trim(k), 'value', trim(try_element_at(split(COALESCE(request_params['workspaceConfValues'], ''), ','), i + 1)))), c -> c.key IN ('enableVerboseAuditLogs', 'enableIpAccessLists')
                                              AND lower(c.value) = 'false')""")
    key_changed = lambda key: expr(f"""exists(transform(split(COALESCE(request_params['workspaceConfKeys'], ''), ','), (k, i) -> named_struct('key', trim(k), 'value', trim(try_element_at(split(COALESCE(request_params['workspaceConfValues'], ''), ','), i + 1)))), c -> c.key = '{key}')""")

    df = spark.table("system.access.audit")

    # Filter for high-priority configuration changes
    df_filtered = df.filter(
        (col("event_time") >= earliest) & (col("event_time") <= latest) &
        (
            # IP Access List configuration changes
            col("action_name").isin("createIpAccessList", "deleteIpAccessList", "updateIpAccessList") |
            # Verbose audit logging, IP access lists on/off, Databricks employee access window,
            # maximum token lifetime -- in any position of a (possibly bundled) workspaceConfEdit
            ((col("action_name") == "workspaceConfEdit") & (expr("size(" + """filter(transform(split(COALESCE(request_params['workspaceConfKeys'], ''), ','), (k, i) -> named_struct('key', trim(k), 'value', trim(try_element_at(split(COALESCE(request_params['workspaceConfValues'], ''), ','), i + 1)))), c -> c.key IN ('enableVerboseAuditLogs', 'enableIpAccessLists', 'customerApprovedWSLoginExpirationTime', 'maxTokenLifetimeDays'))""" + ")") > 0))
        )
    ).select(
        to_timestamp(col("event_time")).alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        col("user_identity.email").alias("SRC_USER"),
        when(
            col("action_name") == "workspaceConfEdit",
            expr("""concat_ws(', ', transform(filter(transform(split(COALESCE(request_params['workspaceConfKeys'], ''), ','), (k, i) -> named_struct('key', trim(k), 'value', trim(try_element_at(split(COALESCE(request_params['workspaceConfValues'], ''), ','), i + 1)))), c -> c.key IN ('enableVerboseAuditLogs', 'enableIpAccessLists', 'customerApprovedWSLoginExpirationTime', 'maxTokenLifetimeDays')),
                                             c -> concat(c.key, ': ', coalesce(c.value, 'N/A'))))""")
        ).when(
            col("action_name").isin("createIpAccessList", "deleteIpAccessList", "updateIpAccessList"),
            concat(lit("IP Access List - "), col("action_name"))
        ).otherwise("Unknown Configuration").alias("CONFIG_CHANGE"),
        when(
            (col("action_name") == "workspaceConfEdit") & disables_control,
            "CRITICAL - Audit Logging or IP Access Lists Disabled"
        ).when(
            col("action_name").isin("deleteIpAccessList"),
            "HIGH - IP Access List Deleted"
        ).when(
            col("action_name").isin("createIpAccessList", "updateIpAccessList"),
            "MEDIUM - IP Access List Modified"
        ).when(
            (col("action_name") == "workspaceConfEdit") & key_changed("customerApprovedWSLoginExpirationTime"),
            "MEDIUM - Change to Databricks Employee Access Config"
        ).when(
            (col("action_name") == "workspaceConfEdit") & key_changed("maxTokenLifetimeDays"),
            "MEDIUM - Maximum Token Lifetime Changed"
        ).otherwise("MEDIUM - Configuration Change").alias("SEVERITY"),
        col("audit_level").alias("AUDIT_LEVEL"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_agent").alias("USER_AGENT"),
        col("request_params").alias("REQUEST_PARAMS")
    ).orderBy(col("EVENT_DATE").desc())

    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(configuration_changes_high_priority(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))