# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:13:37'
# MAGIC   modified: '2025-06-17T12:13:37'
# MAGIC   uuid: 453d8ca5-1ffe-42c2-82c5-c830907df86f
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Principal Removed From Group
# MAGIC     description: Detects the removal of a user or service principal from a group
# MAGIC     fidelity: high
# MAGIC     category: POLICY
# MAGIC     objective: Monitor group membership changes to detect unauthorized removal of
# MAGIC       users or service principals from access groups, which may indicate privilege
# MAGIC       manipulation or attempts to disrupt access controls and auditing.
# MAGIC     false_positives: unknown
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: principal_removed_from_group
# MAGIC     input:
# MAGIC       earliest: '2020-01-01'
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
# MAGIC     - request_params.targetGroupName
# MAGIC     - request_params.targetUserName
# MAGIC     - response.status_code
# MAGIC     - service_name
# MAGIC     - source_ip_address
# MAGIC     - user_agent
# MAGIC     - user_identity.email
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def principal_removed_from_group(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import col, current_date, date_sub, to_date, current_timestamp, expr, when

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()
    df = spark.table("system.access.audit")
    df_filtered = df.filter(
        (col("service_name") == "accounts") &
        col("action_name").isin("removePrincipalFromGroup") &
        (col("event_time") >= earliest) & (col("event_time") <= latest), 
    ).select(
        col("event_time").alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_identity.email").alias("SRC_USER"),
        col("request_params.targetUserName").alias("TARGET_USER"),
        when(
            col("action_name").isin("removePrincipalFromGroup", "addPrincipalToGroup"), col("request_params.targetGroupName")
        ).when(
            col("action_name").isin("createGroup", "removeGroup"), col("request_params.targetUserName")
        ).alias("USER_GROUP"),
        col("user_agent").alias("USER_AGENT"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        col("audit_level").alias("AUDIT_LEVEL")
    ).orderBy(col("EVENT_DATE").desc())
    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(principal_removed_from_group(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
