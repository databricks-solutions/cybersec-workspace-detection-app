# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:09:49'
# MAGIC   modified: '2025-06-17T12:09:49'
# MAGIC   uuid: ae8eeedf-aa3d-4611-ad8d-0deed1bbd255
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Principal Added To Group
# MAGIC     description: Detects the addition of a user or service principal to a group.
# MAGIC     fidelity: high
# MAGIC     category: POLICY
# MAGIC     objective: Monitor group membership assignments to detect unauthorized privilege
# MAGIC       escalation or role provisioning, which may signal insider misuse or preparatory
# MAGIC       steps in a broader attack.
# MAGIC     false_positives: unknown
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: principal_added_to_group
# MAGIC     input:
# MAGIC       earliest: '2025-03-17 22:00:00'
# MAGIC       latest: '2025-03-18'
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
# MAGIC     - request_params.target_group_name
# MAGIC     - request_params.target_user_name
# MAGIC     - response.status_code
# MAGIC     - service_name
# MAGIC     - source_ip_address
# MAGIC     - user_agent
# MAGIC     - user_identity.email
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def principal_added_to_group(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import col, current_date, date_sub, to_date, current_timestamp, expr, when

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()
    df = spark.table("system.access.audit")
    df_filtered = df.filter(
        (col("service_name") == "accounts") &
        col("action_name").isin("addPrincipalToGroup") &
        (col("event_time") >= earliest) & (col("event_time") <= latest), 
    ).select(
        col("event_time").alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        col("request_params.target_user_name").alias("TARGET_USER"),
        when(
            col("action_name").isin("removePrincipalFromGroup", "addPrincipalToGroup"), col("request_params.target_group_name")
        ).when(
            col("action_name").isin("createGroup", "removeGroup"), col("request_params.target_user_name")
        ).alias("USER_GROUP"),
        col("user_identity.email").alias("SRC_USER"),
        col("audit_level").alias("AUDIT_LEVEL"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_agent").alias("USER_AGENT")
    ).orderBy(col("EVENT_DATE").desc())
    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(principal_added_to_group(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
