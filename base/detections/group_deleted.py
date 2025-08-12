# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: Derek King - Databricks
# MAGIC   created: '2025-05-09T12:56:50'
# MAGIC   modified: '2025-05-09T12:56:50'
# MAGIC   uuid: 4e8de7fb-5fbe-424c-99be-22e6efbb5445
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Group Deleted
# MAGIC     description: 'Detects the deletion of user or role groups through the accounts
# MAGIC       service.
# MAGIC 
# MAGIC       '
# MAGIC     objective: 'Monitor group deletions to detect unauthorized dismantling of access
# MAGIC       control structures,
# MAGIC 
# MAGIC       which could indicate privilege abuse, insider threats, or attempts to erase
# MAGIC       evidence of prior access.
# MAGIC 
# MAGIC       '
# MAGIC     taxonomy: []
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: group_deleted
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
# MAGIC     - request_params.targetGroupId
# MAGIC     - request_params.targetUserName
# MAGIC     - response.status_code
# MAGIC     - service_name
# MAGIC     - source_ip_address
# MAGIC     - user_agent
# MAGIC     - user_identity.email
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def group_deleted(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import col, current_date, date_sub, to_date, current_timestamp, expr, when

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()
    df = spark.table("system.access.audit")
    df_filtered = df.filter(
        (col("service_name") == "accounts") &
        col("action_name").isin("removeGroup") &
        (col("event_time") >= earliest) & (col("event_time") <= latest), 
    ).select(
        col("event_time").alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        when(
            (col("request_params.endpoint") == "permissionAssignment") | 
            (col("request_params.endpoint") == "roleAssignment"),
            col("request_params.targetUserName")
        ).otherwise(col("request_params.targetGroupId")).alias("GROUP"), 
        col("user_identity.email").alias("SRC_USER"),
        col("audit_level").alias("AUDIT_LEVEL"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_agent").alias("USER_AGENT")
    ).orderBy(col("EVENT_DATE").desc())
    return df_filtered

# COMMAND ----------

display(group_deleted(earliest="2020-01-01", latest="2025-02-25"))