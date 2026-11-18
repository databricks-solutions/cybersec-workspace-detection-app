# Databricks notebook source
# MAGIC %run ../../../lib/common

# COMMAND ----------
# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:18:01'
# MAGIC   modified: '2025-06-17T12:18:01'
# MAGIC   uuid: 565ad252-a499-4c20-88b4-2c23b6a2bca2
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Token Scanning Activity
# MAGIC     description: Detects anomalously low activity from API tokens across multiple
# MAGIC       IP addresses.
# MAGIC     fidelity: low
# MAGIC     category: DETECTION
# MAGIC     objective: Identify suspicious low-usage patterns of API tokens (PATs, Entra ID and Databricks OAuth tokens)
# MAGIC       across varying IPs or user agents, which may indicate brute-force attempts to
# MAGIC       scan for valid tokens or abuse of leaked credentials. API connectivity using
# MAGIC       a token for scanning appears as a single login event, - with no further actions..
# MAGIC       Look for a comparatively low number per src_ip. (1 event is registered per connection
# MAGIC       attempt, whereas a genuine connection (auth'd) will have potentially 100's of
# MAGIC       entries)
# MAGIC     false_positives: unknown
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: token_scanning_activity
# MAGIC     input:
# MAGIC       earliest: '2025-01-01'
# MAGIC       latest: '2025-03-01'
# MAGIC       threshold: 0.5
# MAGIC     expect:
# MAGIC       count: '>0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs:
# MAGIC     - table: system.access.audit
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - RATE
# MAGIC     - account_id
# MAGIC     - action_name
# MAGIC     - authenticated
# MAGIC     - event_time
# MAGIC     - geo
# MAGIC     - latest_event_time
# MAGIC     - request_params
# MAGIC     - request_params.authenticationMethod
# MAGIC     - request_params.tokenId
# MAGIC     - service_name
# MAGIC     - source_ip_address
# MAGIC     - user_agent
# MAGIC     - user_identity.email
# MAGIC     - workspace_id
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def token_scanning_activity(earliest: str, latest: str, threshold: float = 0.5, min_ips: int = 2):

    from pyspark.sql.functions import col, min, max, regexp_replace, current_date, date_sub, count, first, concat, lit, when, struct, coalesce

    # External API credentials. API_INT_PAT_TOKEN (cluster-internal) is excluded on purpose.
    # Entra ID (API_AAD_OAUTH_TOKEN) and Databricks OAuth (API_OIDC_TOKEN) tokens are as
    # stealable as PATs; before this they were never examined.
    external_token_methods = ["API_EXT_PAT_TOKEN", "API_AAD_OAUTH_TOKEN", "API_OIDC_TOKEN"]
    # One credential = the token id when the event carries one, else the OAuth client id,
    # else the principal + method (so a token without an id is still examined).
    credential_id = coalesce(
        col("request_params.tokenId"),
        col("request_params.client_id"),
        concat(col("request_params.authenticationMethod"), lit(":"), col("user_identity.email"))
    )

    df = spark.table("system.access.audit")
    in_window = (col("event_time") >= earliest) & (col("event_time") <= latest)

    # Platform egress: IPs that also carry Databricks-internal authentication in the window
    # (cluster-internal PATs, in-house OAuth clients used by Apps / serverless). A user's
    # token relayed by a Databricks App or used on a cluster shows up from these IPs; they
    # are not a second location. On SFE this removed every private IP and the workspace's
    # serverless egress IP from the OAuth token population.
    platform_ips = df.filter(in_window & (
        col("request_params.authenticationMethod").isin("API_INT_PAT_TOKEN", "API_INHOUSE_OAUTH_TOKEN") |
        col("action_name").isin("workspaceInHouseOAuthClientAuthentication", "accountInHouseOAuthClientAuthentication")
    )).select(regexp_replace(col("source_ip_address"), r':\d+$', '').alias("platform_ip")).distinct()

    # Check if GeoIP enrichment is available
    geo_available = geo_info is not None

    # Build base select columns
    select_cols = [
        "*",
        concat(col("source_ip_address"), lit('-'), col("user_agent")).alias("src_ua"),
        when(col("source_ip_address").isNotNull() & (col("source_ip_address") != ""), lit(True))
        .otherwise(lit(False))
        .alias("authenticated")
    ]

    # Add geo column if available, otherwise use null struct
    if geo_available:
        select_cols.insert(1, geo_info(regexp_replace(col("source_ip_address"), r':\d+', '')).alias('geo'))
    else:
        select_cols.insert(1, lit(None).cast("struct<latitude:double,longitude:double,city:string,country:string>").alias('geo'))

    df_filtered = df.filter(
        col("request_params.authenticationMethod").isin(external_token_methods) & in_window
    ).join(
        platform_ips,
        regexp_replace(col("source_ip_address"), r':\d+$', '') == col("platform_ip"),
        "left_anti"
    ).select(
        *select_cols
    ).groupBy(
        credential_id.alias("tokenId"),
        regexp_replace(col("source_ip_address"), r':\d+', '').alias("source_ip_address")
    ).agg(
        min(col("event_time")).alias("min_event_time"),
        max(col("event_time")).alias("latest_event_time"),
        first(col("user_agent")).alias("user_agent"),
        first(col("user_identity.email")).alias("token_owner"),
        count(col("action_name")).alias("ACTIONS"),
        first(col("service_name")).alias("service_name"),
        first(col("action_name")).alias("action_name"),
        first(col("account_id")).alias("account_id"),
        first(col("workspace_id")).alias("workspace_id"),
        first(col("request_params")).alias("request_params"),
        first(col("request_params.authenticationMethod")).alias("authentication_method"),
        first(col("geo")).alias("geo"),
        first(col("authenticated")).alias("authenticated")
    ).orderBy(
        col("latest_event_time").desc()
    )

    # Add lat/lon columns (will be null if GeoIP not available)
    df_filtered = df_filtered.select(
        "*",
        col("geo.latitude").alias("lat"),
        col("geo.longitude").alias("lon")
    )

    # Calculate the Average Unique Queries per SRC_USER
    df_avg = df_filtered.groupBy("token_owner").agg(
        F.avg("ACTIONS").alias("AVG_ACTIONS")
    )

    # Join the aggregated DataFrame with the averages
    df_final = df_filtered.join(df_avg, "token_owner")

    # Compute the normalized rate (RATE)
    df_final = df_final.withColumn("RATE", F.expr("ROUND((ACTIONS / AVG_ACTIONS), 2)"))

    # One row per (credential, IP), so rows per credential = distinct IPs that presented it.
    # Short-lived OAuth tokens naturally have few actions per IP, so a low RATE alone is not a
    # signal; the credential must also appear from at least min_ips IPs (min_ips=1 restores
    # the original low-RATE-only behaviour).
    from pyspark.sql.window import Window
    df_final = df_final.withColumn("credential_ip_count", count(lit(1)).over(Window.partitionBy("tokenId")))

    # Apply threshold filter
    df_final = df_final.filter((col("RATE") <= threshold) & (col("credential_ip_count") >= min_ips))

    return df_final

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(token_scanning_activity(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest"),
        threshold=0.5
    ))
