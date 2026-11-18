# Databricks notebook source
# MAGIC %run ../../../lib/common

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
        "feature-store"
    ]
    known_ua_regex = "|".join(known_user_agents)

    # Platform egress: IPs that also carry Databricks-internal authentication in the window
    # (cluster-internal PATs, in-house OAuth clients behind Apps / serverless). A user's token
    # relayed by a Databricks App shows up from these; they are not a second location.
    platform_ips = spark.table("system.access.audit") \
        .filter((F.col("event_time") >= earliest) & (F.col("event_time") <= latest)) \
        .filter(F.col("request_params.authenticationMethod").isin("API_INT_PAT_TOKEN", "API_INHOUSE_OAUTH_TOKEN") |
                F.col("action_name").isin("workspaceInHouseOAuthClientAuthentication",
                                          "accountInHouseOAuthClientAuthentication")) \
        .select(F.col("source_ip_address").alias("platform_ip")).distinct()

    # Load audit logs within the time range. A credential is a browser session (session_id) or,
    # for token and OAuth logins, which carry no session_id, the token (request_params.tokenId)
    # or OAuth client (request_params.client_id).
    df_sessions = spark.table("system.access.audit") \
        .filter((F.col("event_time") >= earliest) & (F.col("event_time") <= latest)) \
        .withColumn("credential", F.coalesce(F.col("session_id"), F.col("request_params.tokenId"),
                                             F.col("request_params.client_id"))) \
        .filter(F.col("credential").isNotNull()) \
        .withColumn("credential_type", F.when(F.col("session_id").isNotNull(), F.lit("session")).otherwise(F.lit("token"))) \
        .filter(~F.col("source_ip_address").rlike(private_ip_regex)) \
        .filter(~F.coalesce(F.col("user_agent"), F.lit("")).rlike(known_ua_regex)) \
        .select("event_time", "session_id", "credential", "credential_type", "user_identity.email",
                "source_ip_address", "user_agent", "audit_level") \
        .join(platform_ips, F.col("source_ip_address") == F.col("platform_ip"), "left_anti")

    # Group by credential and user, count distinct IPs and user agents. (Grouping by
    # source_ip_address, as this rule used to, made ip_count always 1.)
    df_session_stats = df_sessions.groupBy("credential", "credential_type", "email") \
        .agg(
            F.max("audit_level").alias("audit_level"),
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

    # Filter for credentials used across multiple public IPs or devices **AND** within the first 24 hours.
    # A browser session counts on a new IP or a new user agent. A token counts only on a new IP:
    # one token used by two clients (CLI and a script) is normal; replay arrives from another network.
    df_hijacked_sessions = df_session_stats.filter(
        ((F.col("ip_count") > 1) |
         ((F.col("credential_type") == "session") & (F.col("agent_count") > 1))) &
        (F.col("session_duration_hours") <= 24)  # Only consider sessions within the first 24 hours
    )

    return df_hijacked_sessions

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(session_hijack_session_count(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
