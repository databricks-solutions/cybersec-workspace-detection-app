# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:04:06'
# MAGIC   modified: '2025-06-17T12:04:06'
# MAGIC   uuid: 0586fc83-f4c5-492e-83e4-867cd71d1a8e
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Group Created
# MAGIC     description: Detects the creation of user groups within the accounts service.
# MAGIC     fidelity: high
# MAGIC     category: POLICY
# MAGIC     objective: Track group creation events to detect unauthorized role or permission
# MAGIC       group provisioning, which could indicate privilege escalation or lateral movement
# MAGIC       preparation by a threat actor.
# MAGIC     false_positives: unknown
# MAGIC     severity: high
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: group_created
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
# MAGIC     - request_params.endpoint
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
def group_created(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import col, current_date, date_sub, to_date, current_timestamp, expr, when

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()
    df = spark.table("system.access.audit")
    df_filtered = df.filter(
        (col("service_name") == "accounts") &
        col("action_name").isin("createGroup") &
        (col("event_time") >= earliest) & (col("event_time") <= latest), 
    ).select(
        col("event_time").alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        when(
            (col("request_params.endpoint") == "permissionAssignment") | 
            (col("request_params.endpoint") == "roleAssignment"),
            col("request_params.targetUserName")
        ).otherwise(col("request_params.targetGroupName")).alias("GROUP"), 
        col("user_identity.email").alias("SRC_USER"),
        col("audit_level").alias("AUDIT_LEVEL"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_agent").alias("USER_AGENT")
    ).orderBy(col("EVENT_DATE").desc())
    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(group_created(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
