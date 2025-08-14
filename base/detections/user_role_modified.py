# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:07:36'
# MAGIC   modified: '2025-06-17T12:07:36'
# MAGIC   uuid: 456f1e21-ba8b-4321-9954-18647d317988
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: User Role Modified
# MAGIC     description: Detects changes to user roles or administrative group membership.
# MAGIC     fidelity: high
# MAGIC     category: POLICY
# MAGIC     objective: Track modifications to user roles or elevation to administrative groups
# MAGIC       to identify potential privilege escalation, unauthorized access provisioning,
# MAGIC       or insider threat activity.
# MAGIC     false_positives: unknown
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
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

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(user_role_modified(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))



