# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: David Veuve - Databricks
# MAGIC   created: '2025-06-04T12:00:00'
# MAGIC   modified: '2025-06-04T12:00:00'
# MAGIC   uuid: 2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Workspace Configuration Changes
# MAGIC     description: Detects when users modify workspace-level configurations, including
# MAGIC       security-relevant settings such as export restrictions and other workspace
# MAGIC       policies that could affect security posture.
# MAGIC     objective: 'Identify potentially suspicious workspace-level configuration changes
# MAGIC       that could weaken security controls, modify data export policies, or establish
# MAGIC       unauthorized access patterns. These modifications might indicate attempts to
# MAGIC       escalate privileges or bypass security controls at the workspace level. Maps
# MAGIC       to MITRE ATT&CK TA0004 - Privilege Escalation - T1484 - Domain or Tenant
# MAGIC       Policy Modification.'
# MAGIC     taxonomy: 
# MAGIC       - MITRE.TA0004.Privilege_Escalation
# MAGIC       - MITRE.T1484.Domain_or_Tenant_Policy_Modification
# MAGIC     fidelity: low
# MAGIC     category: DETECTION
# MAGIC     false_positives: unknown
# MAGIC     severity: low
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: configuration_changes_workspace_level
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
# MAGIC     - EVENT_TIME
# MAGIC     - SERVICE_NAME
# MAGIC     - ACTION_NAME
# MAGIC     - CONFIG_CHANGE_DESCRIPTION
# MAGIC     - USER_EMAIL
# MAGIC     - USER_AGENT
# MAGIC     - SOURCE_IP_ADDRESS
# MAGIC     - REQUEST_PARAMS
# MAGIC     - event_time
# MAGIC     - service_name
# MAGIC     - action_name
# MAGIC     - request_params.workspaceConfKeys
# MAGIC     - request_params.workspaceConfValues
# MAGIC     - user_identity.email
# MAGIC     - user_agent
# MAGIC     - source_ip_address
# MAGIC     - request_params
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def configuration_changes_workspace_level(earliest: str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_date, date_sub, current_timestamp, 
                                       expr, to_timestamp, concat, lit, coalesce)

    earliest = earliest or current_timestamp() - expr("INTERVAL 2 months")
    latest = latest or current_timestamp()
    
    df = spark.table("system.access.audit")
    
    # Filter for workspace configuration changes
    df_filtered = df.filter(
        (col("action_name") == "workspaceConfEdit") &
        (col("event_time").between(earliest, latest))
    ).select(
        to_timestamp(col("event_time")).alias("EVENT_TIME"),
        col("service_name").alias("SERVICE_NAME"),
        col("action_name").alias("ACTION_NAME"),
        concat(
            col("action_name"),
            lit(" for "),
            coalesce(col("request_params.workspaceConfKeys"), lit("unknown_key")),
            lit(": "),
            coalesce(col("request_params.workspaceConfValues"), lit("unknown_value"))
        ).alias("CONFIG_CHANGE_DESCRIPTION"),
        col("user_identity.email").alias("USER_EMAIL"),
        col("user_agent").alias("USER_AGENT"),
        col("source_ip_address").alias("SOURCE_IP_ADDRESS"),
        col("request_params").alias("REQUEST_PARAMS")
    ).orderBy(col("EVENT_TIME").desc())
    
    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(configuration_changes_workspace_level(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
# COMMAND ----------
