# Databricks notebook source
# MAGIC %run ../../../lib/common

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
    
    # RFC 1918, CGNAT / Databricks-internal (100.64.0.0/10), loopback, link-local and IPv6 unique-local.
    private_ip_regex = (r'^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.'
                        r'|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|127\.|169\.254\.|(?i)f[cd][0-9a-f]{2}:)')
    known_user_agents = [
        "Databricks-Service/driver",
        "Databricks-Runtime",
        "Delta-Sharing-SparkStructuredStreaming"
    ]
    known_ua_regex = "|".join(known_user_agents)

    # Interactive and token logins, including Entra (aad*) and OAuth (oidc*, mintOAuthToken).
    login_actions = ["login", "tokenLogin", "samlLogin", "jwtLogin", "aadTokenLogin", "oidcTokenAuthorization",
                     "aadBrowserLogin", "oidcBrowserLogin", "mintOAuthToken"]

    # Platform egress: IPs that also carry Databricks-internal authentication in the window
    # (cluster-internal PATs, in-house OAuth clients behind Apps / serverless). A user's token
    # relayed by a Databricks App shows up from these; they are not a second location.
    platform_ips = spark.table("system.access.audit") \
        .filter((F.col("event_time") >= earliest) & (F.col("event_time") <= latest)) \
        .filter(F.col("request_params.authenticationMethod").isin("API_INT_PAT_TOKEN", "API_INHOUSE_OAUTH_TOKEN") |
                F.col("action_name").isin("workspaceInHouseOAuthClientAuthentication",
                                          "accountInHouseOAuthClientAuthentication")) \
        .select(F.col("source_ip_address").alias("platform_ip")).distinct()

    # Load audit logs within the time range. Token and OAuth login rows carry no session_id, so
    # requiring one (as this rule used to) hid PAT and OAuth replay entirely; the credential is
    # identified by request_params.tokenId (PAT / OAuth token) or client_id (OAuth M2M mint).
    df = spark.table("system.access.audit") \
        .filter((F.col("event_time") >= earliest) & (F.col("event_time") <= latest)) \
        .filter(F.col("service_name") == "accounts") \
        .filter(F.col("action_name").isin(login_actions)) \
        .filter(~F.col("source_ip_address").rlike(private_ip_regex)) \
        .filter(~F.coalesce(F.col("user_agent"), F.lit("")).rlike(known_ua_regex)) \
        .withColumn("token_credential", F.coalesce(F.col("request_params.tokenId"), F.col("request_params.client_id"))) \
        .withColumn("credential_type", F.when(F.col("token_credential").isNotNull(), F.lit("token")).otherwise(F.lit("user"))) \
        .withColumn("credential", F.coalesce(F.col("token_credential"), F.col("user_identity.email"))) \
        .filter(F.col("credential").isNotNull()) \
        .select("event_time", "user_identity.email", "session_id", "credential", "credential_type",
                "source_ip_address", "user_agent", "audit_level") \
        .join(platform_ips, F.col("source_ip_address") == F.col("platform_ip"), "left_anti")

    # Define window partitioning by credential (the token, or the user for interactive logins)
    window_spec = Window.partitionBy("credential").orderBy("event_time")

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

    # Filter for different IPs or user agents within the suspicious time threshold. For a token,
    # only an IP change counts: one token used by two clients (CLI and a script) from the same
    # host is normal, while replay of a stolen token arrives from another network.
    df_suspicious = df.filter(
        (F.col("previous_ip").isNotNull()) &
        (F.col("trigger_reason").isNotNull()) &  # Ensure there is a valid trigger reason
        (F.col("time_diff_seconds") < threshold_secs) &
        ((F.col("credential_type") == "user") | (F.col("previous_ip") != F.col("source_ip_address")))
    )

    return df_suspicious

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(session_hijack_multi_session_multi_device(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
