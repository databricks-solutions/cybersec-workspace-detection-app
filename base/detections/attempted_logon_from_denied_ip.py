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
# MAGIC     name: Attempted Logon from Denied IP
# MAGIC     description: 'Detects blocked login attempts from IP addresses denied by workspace
# MAGIC       access control policies.
# MAGIC 
# MAGIC       '
# MAGIC     objective: 'Identify logon attempts from explicitly denied IPs that bypass known
# MAGIC       service agents and telemetry paths,
# MAGIC 
# MAGIC       which may indicate unauthorized scanning activity, policy testing, or brute-force
# MAGIC       attempts from untrusted networks.
# MAGIC 
# MAGIC       '
# MAGIC     taxonomy: []
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: attempted_logon_from_denied_ip
# MAGIC     input:
# MAGIC       earliest: '2025-03-13'
# MAGIC       latest: '2025-03-14'
# MAGIC       ignore_tokens: true
# MAGIC     expect:
# MAGIC       count: '>0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs:
# MAGIC     - table: system.access.audit
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - action_name
# MAGIC     - audit_level
# MAGIC     - event_time
# MAGIC     - request_params.path
# MAGIC     - response.status_code
# MAGIC     - service_name
# MAGIC     - source_ip_address
# MAGIC     - user_agent
# MAGIC     - user_identity.email
# MAGIC     - workspace_id
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def attempted_logon_from_denied_ip(earliest:str = None, latest: str = None, ignore_tokens: bool = False):
    from pyspark.sql.functions import (col, current_date, date_sub, to_date, current_timestamp, 
                                       expr, unix_timestamp, round, from_unixtime, when, to_timestamp)

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()

    known_user_agents = [
        "databricks",
        "Databricks-Service/driver",
        "Databricks-Runtime",
        "Delta-Sharing-SparkStructuredStreaming",
        "RawDBHttpClient",
        "mlflow-python",
        "obsSDK-scala/1.0.0",
        "wsfs/1.0",
        "feature-store"
    ]
    known_ua_regex = "|".join(known_user_agents)

    excluded_paths = [
        "telemetry",
        "delta-commit",
        "health"
    ]
    excluded_paths_regex = "|".join(excluded_paths)

    df = spark.table("system.access.audit")

    if ignore_tokens:
        uuid_pattern = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        df = df.filter(~col("user_identity.email").rlike(uuid_pattern))

    df_filtered = df.filter(
        (col("service_name") == "accounts") &
        (col("action_name").isin("IpAccessDenied")) &
        (~F.col("user_agent").rlike(known_ua_regex)) &
        (~col("request_params.path").rlike(excluded_paths_regex)) &
        (col("event_time") >= earliest) & (col("event_time") <= latest)
    ).select(
        to_timestamp(col("event_time")).alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        col("user_identity.email").alias("SRC_USER"),
        col("request_params.path").alias("PATH"),
        col("workspace_id").alias("WORKSPACE_ID"),
        col("source_ip_address").alias("SRC_IP"),
        col("response.status_code").alias("RESPONSE_CODE"),
        col("user_agent").alias("USER_AGENT"),
        col("audit_level").alias("AUDIT_LEVEL")
    )
    
    return df_filtered

# COMMAND ----------

df = attempted_logon_from_denied_ip(earliest="2025-03-13", latest="2025-03-14", ignore_tokens=True)
display(df)