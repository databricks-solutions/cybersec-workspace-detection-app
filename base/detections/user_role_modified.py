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
# MAGIC     name: User Role Modified
# MAGIC     description: 'Detects changes to user roles or administrative group membership.
# MAGIC 
# MAGIC       '
# MAGIC     objective: 'Track modifications to user roles or elevation to administrative groups
# MAGIC       to identify potential privilege escalation,
# MAGIC 
# MAGIC       unauthorized access provisioning, or insider threat activity.
# MAGIC 
# MAGIC       '
# MAGIC     taxonomy: []
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: user_role_modified
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
# MAGIC     - action_name
# MAGIC     - event_time
# MAGIC     - service_name
# MAGIC ```

# COMMAND ----------


@detect(output=Output.asDataFrame)
def user_role_modified(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import col, current_date, date_sub, to_date, current_timestamp, expr, when    

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()
    df = spark.table("system.access.audit")

    df_filtered = df.select("event_time", "user_identity", "request_params", "action_name") \
    .where((col("service_name") == "accounts") &
           (col("action_name").isin("addUserToAdminGroup", "modifyUserRole")) &
           (col("event_time").between(earliest, latest))) \
    .orderBy(col("event_time").desc())


    return df_filtered

# COMMAND ----------

display(user_role_modified(earliest="2020-01-01", latest="2025-02-25"))

# COMMAND ----------

