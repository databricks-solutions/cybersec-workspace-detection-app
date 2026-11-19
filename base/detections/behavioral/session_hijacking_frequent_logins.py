# Databricks notebook source
# MAGIC %run ../../../lib/common

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

@detect(output=Output.asDataFrame)
def session_hijack_high_session_count(earliest: str=None, latest: str = None, threshold_seconds: int=600, threshold_value: int=2,
                                      min_distinct_ips: int=1):
    from pyspark.sql import functions as F
    from pyspark.sql.window import Window

    earliest = earliest or F.current_timestamp() - F.expr("INTERVAL 24 hours")
    latest = latest or F.current_timestamp()

    # RFC 1918, CGNAT / Databricks-internal (100.64.0.0/10), loopback, link-local and IPv6 unique-local.
    private_ip_regex = (r'^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.'
                        r'|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|127\.|169\.254\.|(?i)f[cd][0-9a-f]{2}:)')

    # Databricks-internal service clients only. A bare "databricks" used to be in this list; it
    # matched databricks-cli and the databricks-sdk-* clients (case-sensitive), so an actor's own
    # SDK/CLI traffic was dropped. Keep SDK, CLI and connector clients.
    known_user_agents = [
        "Databricks-Service/driver",
        "Databricks-Runtime",
        "Delta-Sharing-SparkStructuredStreaming",
        "RawDBHttpClient",
        "wsfs/",
        "mlflow-python",
        "feature-store",
        "dbr:"
    ]
    known_ua_regex = "|".join(known_user_agents)

    # Interactive and token logins. Entra (aad*) and OAuth (oidc*, mintOAuthToken) are what service
    # principals and Entra tokens use; without them those identities were invisible.
    login_actions = ["login", "tokenLogin", "samlLogin", "jwtLogin", "aadTokenLogin", "oidcTokenAuthorization",
                     "aadBrowserLogin", "oidcBrowserLogin", "mintOAuthToken"]

    # Load audit logs within the time range
    df_logins = spark.table("system.access.audit") \
        .filter((F.col("event_time") >= earliest) & (F.col("event_time") <= latest)) \
        .filter(F.col("service_name") == "accounts") \
        .filter(F.col("action_name").isin(login_actions)) \
        .filter(~F.col("source_ip_address").rlike(private_ip_regex)) \
        .filter(F.col("user_identity.email").isNotNull()) \
        .filter(~F.coalesce(F.col("user_agent"), F.lit("")).rlike(known_ua_regex)) \
        .select(
            F.col("user_identity.email").alias("email"),
            "event_time",
            "source_ip_address",
            "user_agent"
        )

    # Define window function partitioned by user and sliding within the suspicious time threshold
    window_spec = Window.partitionBy("email").orderBy(F.col("event_time").cast("long")).rangeBetween(-threshold_seconds, 0)

    # Count logins, and distinct public IPs, in the suspicious time range
    df_logins = df_logins \
        .withColumn("login_count", F.count("*").over(window_spec)) \
        .withColumn("ips_in_window", F.size(F.collect_set("source_ip_address").over(window_spec)))

    # Aggregate login counts per user over the entire time window
    df_aggregated_logins = df_logins.groupBy("email") \
        .agg(
            F.count("*").alias("total_logins").cast("int"),  # Total logins over the time period
            F.countDistinct("source_ip_address").alias("unique_ips"),  # Unique IPs used
            F.min("event_time").alias("first_seen"),  # First login time in window
            F.max("event_time").alias("last_seen"),  # Last login time in window
            F.max("login_count").alias("max_login_count").cast("int"),  # Maximum login count observed in the threshold window
            F.max("ips_in_window").alias("max_ips_in_window").cast("int")  # Most distinct public IPs seen within one threshold window
        )

    # Filter for users exceeding the login threshold. Every API call with a token is a tokenLogin
    # row, so with token logins included, login_count alone is met by most active principals;
    # min_distinct_ips=2 keeps only principals seen from several public IPs within the window.
    df_suspicious_logins = df_aggregated_logins.filter(
        (F.col("max_login_count") >= threshold_value) &
        (F.col("max_ips_in_window") >= min_distinct_ips)
    )

    return df_suspicious_logins

# COMMAND ----------
if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(session_hijack_high_session_count(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest"),
        threshold_seconds=60
    ))
