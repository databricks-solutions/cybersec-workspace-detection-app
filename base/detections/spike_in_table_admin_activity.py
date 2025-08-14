# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:02:36'
# MAGIC   modified: '2025-06-17T12:02:36'
# MAGIC   uuid: 37ae13e6-8e76-4928-98ee-5c303dfc259d
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Spike In Table Admin Activity
# MAGIC     description: Detects abnormal increases in unique admin-level queries executed
# MAGIC       by users.
# MAGIC     fidelity: low
# MAGIC     category: POLICY
# MAGIC     objective: Identify spikes in administrative command usage by calculating deviations
# MAGIC       from a user average query volume, helping detect potential misuse of privileges,
# MAGIC       compromised accounts, or scripted attacks.
# MAGIC     false_positives: unknown
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: spikes_in_admin_activity
# MAGIC     input:
# MAGIC       earliest: '2025-01-01'
# MAGIC       latest: '2025-03-03'
# MAGIC       threshold: 1.5
# MAGIC     expect:
# MAGIC       count: '>0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs:
# MAGIC     - table: system.access.audit
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - QUERY_DATE
# MAGIC     - RATE
# MAGIC     - event_time
# MAGIC     - request_params.commandText
# MAGIC     - source_ip_address
# MAGIC     - user_identity.email
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC # Abnormal Table and DB Access
# MAGIC
# MAGIC ###Description
# MAGIC
# MAGIC Most accounts regularly access a limited set of databases, schemas, views, and tables, but
# MAGIC unless there is prior insight, an attacker needs to enumerate a multitude of sources. These
# MAGIC spikes in the number of databases/schemas/views/tables can be indicative of attacker activity.
# MAGIC
# MAGIC ###Observations
# MAGIC
# MAGIC Look for distinctive spikes in unique views/tables accessed by user accounts impacted
# MAGIC by the attacker. Since there are more views/tables than schemas, and more schemas than
# MAGIC databases, analysis of views/tables can show more distinctive peaks and valleys.
# MAGIC
# MAGIC ###Warnings about FP/Noise
# MAGIC
# MAGIC Normalizing the results as a fraction from the average can be a better way to look for spikes,
# MAGIC rather than the raw aggregate numbers. Raw numbers can cause a loud service account to
# MAGIC drown out the enumeration of an attacker’s activity. The below aggregation normalizes the daily
# MAGIC unique numbers as a percentage of that entry’s average.

# COMMAND ----------

@detect(output=Output.asDataFrame)
def spikes_in_admin_activity(earliest: str, latest: str, threshold: int = 0):
    """
    Identifies spikes in admin activity by analyzing unique queries issued by users.
    
    Args:
        earliest (str): The earliest timestamp to filter events.
        latest (str): The latest timestamp to filter events.
        threshold (int): Minimum normalized rate threshold (default=0). Rows with a lower rate will be filtered out.

    Returns:
        pyspark.sql.DataFrame: Filtered DataFrame with normalized ratio (RATE) and threshold applied.
    """
    from pyspark.sql.functions import (
        col, count, countDistinct, date_format, expr, lit, lower, max, min, to_date, upper, avg
    )    
    df = spark.table("system.access.audit")

    # Filter relevant events
    df_filtered = df.filter(
        (~upper(col("request_params.commandText")).like("%THIS IS A SYSTEM GENERATED QUERY%")) &
        (
            upper(col("request_params.commandText")).like("%CREATE USER%") |
            upper(col("request_params.commandText")).like("%ALTER USER%") |
            upper(col("request_params.commandText")).like("%ALTER ACCOUNT%") |
            upper(col("request_params.commandText")).like("%ALTER PASSWORD POLICY%") |
            upper(col("request_params.commandText")).like("%APPLY PASSWORD POLICY%") |
            upper(col("request_params.commandText")).like("%GRANT USAGE%") |
            upper(col("request_params.commandText")).like("%GRANT CREATE%") |
            upper(col("request_params.commandText")).like("%GRANT APPLY%") |
            upper(col("request_params.commandText")).like("%SHOW GRANT%") |
            upper(col("request_params.commandText")).like("%GRANT ROLE%")
        ) & 
        (col("event_time") >= earliest) & 
        (col("event_time") <= latest)
    )

    # Aggregate data per user, IP, and date
    df_aggregated = df_filtered.groupBy(
        to_date(col("event_time")).alias("QUERY_DATE"),
        col("user_identity.email").alias("SRC_USER"),
        col("source_ip_address").alias("SRC_IP")
    ).agg(
        min(date_format(expr("to_utc_timestamp(event_time, 'UTC')"), "yyyy-MM-dd HH:mm:ss")).alias("EARLIEST_UTC"),
        max(date_format(expr("to_utc_timestamp(event_time, 'UTC')"), "yyyy-MM-dd HH:mm:ss")).alias("LATEST_UTC"),
        countDistinct(to_date(col("event_time"))).alias("DAY_COUNT"),
        countDistinct(expr("sha(request_params.commandText)")).alias("UNIQUE_QUERIES"),
        count(col("request_params.commandText")).alias("TOTAL_QUERIES"),
        expr("collect_set(request_params.commandText)").alias("COMMANDS"),
        countDistinct(col("source_ip_address")).alias("UNIQ_IP")
    )

    # Calculate the Average Unique Queries per SRC_USER
    df_avg = df_aggregated.groupBy("SRC_USER").agg(
        avg("UNIQUE_QUERIES").alias("AVG_UNIQUE_QUERIES")
    )

    # Join the aggregated DataFrame with the averages
    df_final = df_aggregated.join(df_avg, "SRC_USER")

    # Compute the normalized rate (RATE)
    df_final = df_final.withColumn("RATE", expr("ROUND((UNIQUE_QUERIES / AVG_UNIQUE_QUERIES), 2)"))

    # Apply threshold filter
    df_final = df_final.filter(col("RATE") > threshold)

    # Order results by QUERY_DATE in descending order
    df_final = df_final.orderBy(col("QUERY_DATE").desc())

    return df_final


# COMMAND ----------
if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(spikes_in_admin_activity(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest"),
        threshold=1.5
    ))
