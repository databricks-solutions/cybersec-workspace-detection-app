# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:11:43'
# MAGIC   modified: '2025-06-17T12:11:43'
# MAGIC   uuid: c1855110-7429-4d41-ab1e-ad23dd3e1ea3
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Session Hijacking Frequent Logins
# MAGIC     description: Detects a high volume of login events from different public IPs and
# MAGIC       user agents in a short time window.
# MAGIC     fidelity: low
# MAGIC     category: DETECTION
# MAGIC     objective: Identify burst login activity that may indicate session hijacking or
# MAGIC       automated attempts to reuse stolen credentials, by tracking users logging in
# MAGIC       from multiple IPs with unusual frequency over a short duration.
# MAGIC     false_positives: High -- JSESSION_ID has been redacted in databricks logs
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: session_hijack_high_session_count
# MAGIC     input:
# MAGIC       earliest: '2025-02-23'
# MAGIC       latest: '2025-02-25'
# MAGIC       threshold_seconds: 60
# MAGIC     expect:
# MAGIC       count: '>0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs: []
# MAGIC     required_columns: []
# MAGIC ```

# COMMAND ----------

def session_hijack_high_session_count(earliest: str=None, latest: str = None, threshold_seconds: int=600, threshold_value: int=2):
    from pyspark.sql import functions as F
    from pyspark.sql.window import Window

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
        "feature-store",
        "dbr:"
    ]
    known_ua_regex = "|".join(known_user_agents)

    # Load audit logs within the time range
    df_logins = spark.read.table("system.access.audit") \
        .filter((F.col("event_time") >= earliest) & (F.col("event_time") <= latest)) \
        .filter(F.col("service_name") == "accounts") \
        .filter(F.col("action_name").isin(["login", "tokenLogin", "samlLogin", "jwtLogin"])) \
        .filter(~F.col("source_ip_address").rlike(private_ip_regex)) \
        .filter(F.col("user_identity.email").isNotNull()) \
        .filter(~F.col("user_agent").rlike(known_ua_regex)) \
        .select(
            F.col("user_identity.email").alias("email"),
            "event_time",
            "source_ip_address",
            "user_agent"
        )

    # Define window function partitioned by user and sliding within the suspicious time threshold
    window_spec = Window.partitionBy("email").orderBy(F.col("event_time").cast("long")).rangeBetween(-threshold_seconds, 0)

    # Count logins in the suspicious time range
    df_logins = df_logins.withColumn("login_count", F.count("*").over(window_spec))

    # Aggregate login counts per user over the entire time window
    df_aggregated_logins = df_logins.groupBy("email") \
        .agg(
            F.count("*").alias("total_logins").cast("int"),  # Total logins over the time period
            F.countDistinct("source_ip_address").alias("unique_ips"),  # Unique IPs used
            F.min("event_time").alias("first_seen"),  # First login time in window
            F.max("event_time").alias("last_seen"),  # Last login time in window
            F.max("login_count").alias("max_login_count").cast("int")  # Maximum login count observed in the threshold window
        )

    # Filter for users exceeding the login threshold
    df_suspicious_logins = df_aggregated_logins.filter(F.col("max_login_count") >= threshold_value)

    return df_suspicious_logins

# COMMAND ----------
if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(session_hijack_high_session_count(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest"),
        threshold_seconds=60
    ))
