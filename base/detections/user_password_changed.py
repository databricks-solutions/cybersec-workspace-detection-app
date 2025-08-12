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
# MAGIC     name: User Password Changed
# MAGIC     description: 'Detects password change events performed through the accounts service.
# MAGIC 
# MAGIC       '
# MAGIC     objective: 'Track password changes across user accounts to identify potentially
# MAGIC       unauthorized credential resets,
# MAGIC 
# MAGIC       which could indicate account takeover attempts, insider misuse, or lateral movement
# MAGIC       within the environment.
# MAGIC 
# MAGIC       '
# MAGIC     taxonomy: []
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: user_password_changed
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
# MAGIC     - request_params.newPasswordSource
# MAGIC     - request_params.targetUserId
# MAGIC     - response.status_code
# MAGIC     - service_name
# MAGIC     - source_ip_address
# MAGIC     - user_agent
# MAGIC     - user_identity.email
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def user_password_changed(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import col, current_date, date_sub, to_date, current_timestamp, expr, when

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()
    df = spark.table("system.access.audit")

    df_filtered = df.filter(
        (col("service_name") == "accounts") &
        col("action_name").isin("changePassword") &
        (col("event_time") >= earliest) & (col("event_time") <= latest), 
    ).select(
        col("event_time").alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        col("user_identity.email").alias("SRC_USER"),
        col("request_params.targetUserId").alias("TARGET_USER"),
        col("request_params.newPasswordSource").alias("PASSWORD_SOURCE"),
        col("audit_level").alias("AUDIT_LEVEL"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_agent").alias("USER_AGENT"),
    ).orderBy(col("EVENT_DATE").desc())

    return df_filtered

# COMMAND ----------

display(user_password_changed(earliest="2020-01-01", latest="2025-02-25"))