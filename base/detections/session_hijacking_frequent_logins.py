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
# MAGIC     name: Session Hijack - High Session Count
# MAGIC     description: 'Detects a high volume of login events from different public IPs
# MAGIC       and user agents in a short time window.
# MAGIC 
# MAGIC       '
# MAGIC     objective: 'Identify burst login activity that may indicate session hijacking
# MAGIC       or automated attempts to reuse stolen credentials,
# MAGIC 
# MAGIC       by tracking users logging in from multiple IPs with unusual frequency over a
# MAGIC       short duration.
# MAGIC 
# MAGIC       '
# MAGIC     taxonomy: []
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

display(session_hijack_high_session_count(earliest="2025-02-23", latest="2025-02-25", threshold_seconds=60))