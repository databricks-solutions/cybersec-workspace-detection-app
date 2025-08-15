# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:14:26'
# MAGIC   modified: '2025-06-17T12:14:26'
# MAGIC   uuid: 53e42333-ee45-4772-83b2-74699c581748
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Session Hijacking Session Count
# MAGIC     description: Detects user sessions reused across multiple public IPs or devices
# MAGIC       within a short timeframe.
# MAGIC     fidelity: low
# MAGIC     category: DETECTION
# MAGIC     objective: Identify suspicious reuse of authenticated sessions by tracking access
# MAGIC       patterns that involve multiple distinct public IP addresses or user agents within
# MAGIC       a 24-hour period, indicating potential session hijacking or credential sharing.
# MAGIC     false_positives: High. JSESSION_ID needed for reliable tracking is redacted in
# MAGIC       the databricks audit logs
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: session_hijack_session_count
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

# MAGIC %md
# MAGIC ### Session ID Reuse Across Different Public IPs or User Agents
# MAGIC Detects session tokens being reused across different public IP addresses or devices.
# MAGIC

# COMMAND ----------

@detect(output=Output.asDataFrame)
def session_hijack_session_count(earliest: str=None, latest: str = None):
    from pyspark.sql import functions as F
    earliest = earliest or F.current_timestamp() - F.expr("INTERVAL 24 hours")
    latest = latest or F.current_timestamp()

    private_ip_regex = r'^(10\..*|192\.168\..*|172\.(1[6-9]|2[0-9]|3[0-1])\..*)$'

    known_user_agents = [
        "databricks",
        "Databricks-Service/driver",
        "Databricks-Runtime",
        "Delta-Sharing-SparkStructuredStreaming",
        "RawDBHttpClient",
        "mlflow-python",
        "feature-store"
    ]
    known_ua_regex = "|".join(known_user_agents)

    # Load audit logs within the time range
    df_sessions = spark.table("system.access.audit") \
        .filter((F.col("event_time") >= earliest) & (F.col("event_time") <= latest)) \
        .filter(F.col("session_id").isNotNull()) \
        .filter(~F.col("source_ip_address").rlike(private_ip_regex)) \
        .filter(~F.col("user_agent").rlike(known_ua_regex)) \
        .select("event_time", "session_id", "user_identity.email", "source_ip_address", "user_agent", "audit_level")

    # Group by session_id and user, count distinct IPs and user agents
    df_session_stats = df_sessions.groupBy("source_ip_address", "email", "audit_level") \
        .agg(
            F.countDistinct("source_ip_address").alias("ip_count"),
            F.countDistinct("user_agent").alias("agent_count"),
            F.collect_set("source_ip_address").alias("source_ip_address_list"),
            F.collect_set("user_agent").alias("user_agent_list"),
            F.min("event_time").alias("first_seen"),
            F.max("event_time").alias("last_seen")
        )

    df_session_stats = df_session_stats.withColumn(
        "session_duration_hours",
        ((F.unix_timestamp("last_seen") - F.unix_timestamp("first_seen")) / 3600).cast("float")
    )

    # Filter for sessions that were used across multiple public IPs or devices **AND** within the first 24 hours
    df_hijacked_sessions = df_session_stats.filter(
        ((F.col("ip_count") > 1) | (F.col("agent_count") > 1)) &  # Different IPs or User Agents
        (F.col("session_duration_hours") <= 24)  # Only consider sessions within the first 24 hours
    )

    # Filter for sessions that were used across multiple public IPs or devices
    df_hijacked_sessions = df_hijacked_sessions.filter((F.col("ip_count") > 1) | (F.col("agent_count") > 1))

    return df_hijacked_sessions

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(session_hijack_session_count(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
