# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:05:00'
# MAGIC   modified: '2025-06-17T12:05:00'
# MAGIC   uuid: bd7b94f0-40fa-42c5-b7a0-ef6b72e96ee6
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Session Hijacking Multi Device
# MAGIC     description: Detects rapid user session reuse across different IP addresses or
# MAGIC       user agents
# MAGIC     fidelity: low
# MAGIC     category: DETECTION
# MAGIC     objective: Identify potential session hijacking by flagging logins that switch
# MAGIC       between IPs or devices within a short timeframe, which may indicate credential
# MAGIC       theft, account compromise, or abuse of persistent sessions.
# MAGIC     false_positives: databricks redacts the JSESSION_ID field making this detection
# MAGIC       noisy, and prone to errors
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: session_hijack_multi_session_multi_device
# MAGIC     input:
# MAGIC       earliest: '2020-01-01'
# MAGIC       latest: '2025-02-25'
# MAGIC     expect:
# MAGIC       count: '>0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs: []
# MAGIC     required_columns: []
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def session_hijack_multi_session_multi_device(earliest: str, latest: str = None, threshold_secs: int = 600):
    from pyspark.sql import functions as F
    from pyspark.sql.window import Window

    earliest = earliest or F.current_timestamp() - F.expr("INTERVAL 24 hours")
    latest = latest or F.current_timestamp()
    
    private_ip_regex = r'^(10\..*|192\.168\..*|172\.(1[6-9]|2[0-9]|3[0-1])\..*)$'
    known_user_agents = [
        "Databricks-Service/driver",
        "Databricks-Runtime",
        "Delta-Sharing-SparkStructuredStreaming"
    ]
    known_ua_regex = "|".join(known_user_agents)

    # Load audit logs within the time range
    df = spark.read.table("system.access.audit") \
        .filter((F.col("event_time") >= earliest) & (F.col("event_time") <= latest)) \
        .filter(F.col("service_name") == "accounts") \
        .filter(F.col("action_name").isin(["login", "tokenLogin", "samlLogin", "jwtLogin"])) \
        .filter(~F.col("source_ip_address").rlike(private_ip_regex)) \
        .filter(~F.col("user_agent").rlike(known_ua_regex)) \
        .filter(F.col("session_id").isNotNull()) \
        .select("event_time", "user_identity.email", "session_id", "source_ip_address", "user_agent", "audit_level")

    # Define window partitioning by user and ordering by event_time
    window_spec = Window.partitionBy("email").orderBy("event_time")

    # Add previous login information
    df = df.withColumn("previous_ip", F.lag("source_ip_address").over(window_spec)) \
          .withColumn("previous_agent", F.lag("user_agent").over(window_spec)) \
          .withColumn("previous_time", F.lag("event_time").over(window_spec))

    # Calculate time difference in seconds
    df = df.withColumn("time_diff_seconds", F.unix_timestamp("event_time") - F.unix_timestamp("previous_time"))


    # Determine the reason for flagging (IP change, user agent change, or both)
    df = df.withColumn(
        "trigger_reason",
        F.when((F.col("previous_ip") != F.col("source_ip_address")) & (F.col("previous_agent") != F.col("user_agent")), "Different IP & User-Agent")
        .when(F.col("previous_ip") != F.col("source_ip_address"), "Different IP")
        .when(F.col("previous_agent") != F.col("user_agent"), "Different User-Agent")
        .otherwise(None)
    )

    # Filter for different IPs or user agents within the suspicious time threshold
    df_suspicious = df.filter(
        (F.col("previous_ip").isNotNull()) &
        (F.col("trigger_reason").isNotNull()) &  # Ensure there is a valid trigger reason
        (F.col("time_diff_seconds") < threshold_secs)
    )

    return df_suspicious

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(session_hijack_multi_session_multi_device(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
