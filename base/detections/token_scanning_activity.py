# Databricks notebook source
# MAGIC %run ../../lib/common

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
# MAGIC     objective: Identify suspicious low-usage patterns of personal access tokens (PATs)
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
def token_scanning_activity(earliest: str, latest: str, threshold: int = 0):

    from pyspark.sql.functions import col, min, max, regexp_replace, current_date, date_sub, count, first, concat, lit, when

    df = spark.table("system.access.audit")

    df_filtered = df.filter(
        (col("request_params.authenticationMethod") == "API_EXT_PAT_TOKEN") &
        (col("event_time") >= earliest) & (col("event_time") <= latest)
    ).select(
        "*",
        geo_info(regexp_replace(col("source_ip_address"), r':\d+', '')).alias('geo'),
        concat(col("source_ip_address"), lit('-'), col("user_agent")).alias("src_ua"),
        # New 'authenticated' column: True if source_ip_address is not null/empty, False otherwise
        when(col("source_ip_address").isNotNull() & (col("source_ip_address") != ""), lit(True))
        .otherwise(lit(False))
        .alias("authenticated")
    ).groupBy(
        col("request_params.tokenId"),
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
        first(col("geo")).alias("geo"),
        first(col("authenticated")).alias("authenticated")  # Include authenticated in aggregation
    ).orderBy(
        col("latest_event_time").desc()
    )

    df_filtered = df_filtered.select("*", df_filtered.geo.latitude.alias("lat"), df_filtered.geo.longitude.alias("lon"))

    # Calculate the Average Unique Queries per SRC_USER
    df_avg = df_filtered.groupBy("token_owner").agg(
        F.avg("ACTIONS").alias("AVG_ACTIONS")
    )

    # Join the aggregated DataFrame with the averages
    df_final = df_filtered.join(df_avg, "token_owner")

    # Compute the normalized rate (RATE)
    df_final = df_final.withColumn("RATE", F.expr("ROUND((ACTIONS / AVG_ACTIONS), 2)"))

    # Apply threshold filter
    df_final = df_final.filter(col("RATE") <= threshold)

    return df_final

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(token_scanning_activity(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest"),
        threshold=0.5
    ))
