# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:20:38'
# MAGIC   modified: '2025-06-17T12:20:38'
# MAGIC   uuid: acfbe7ce-8108-4d6b-816b-f7963ec2bae1
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Verbose Audit Logging Disabled
# MAGIC     description: Detects when verbose audit logging is explicitly disabled at the
# MAGIC       workspace configuration level.
# MAGIC     fidelity: high
# MAGIC     category: POLICY
# MAGIC     objective: Monitor configuration changes that disable verbose audit logs to detect
# MAGIC       attempts at reducing system visibility, which may signal attacker evasion, insider
# MAGIC       threat activity, or unauthorized configuration tampering.
# MAGIC     false_positives: unknown
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: verbose_audit_disabled
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
def verbose_audit_disabled(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_date, date_sub, to_date, current_timestamp, 
                                       expr, unix_timestamp, round, from_unixtime, when, to_timestamp)

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()

    df = spark.table("system.access.audit")

    df_filtered = df.filter(
        (col("service_name") == "workspace") &
        (col("action_name").isin("workspaceConfEdit")) &
        (col("request_params").getItem("workspaceConfKeys") == "enableVerboseAuditLogs") &
        (col("request_params").getItem("workspaceConfValues") == "false") &
        (col("event_time") >= earliest) & (col("event_time") <= latest)
    ).select(
        to_timestamp(col("event_time")).alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        col("user_identity.email").alias("SRC_USER"),
        col("request_params").getItem("workspaceConfKeys").alias("CONF_KEY"),
        when(col("request_params").getItem("workspaceConfValues") == "false", "Disabled").otherwise("Enabled").alias("CONF_VALUE"),
        col("audit_level").alias("AUDIT_LEVEL"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_agent").alias("USER_AGENT")
    ).orderBy(col("EVENT_DATE").desc())

    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(verbose_audit_disabled(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
