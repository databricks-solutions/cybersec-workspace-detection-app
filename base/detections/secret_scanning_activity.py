# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: David Veuve - Databricks
# MAGIC   created: '2025-06-04T12:00:00'
# MAGIC   modified: '2025-06-04T12:00:00'
# MAGIC   uuid: 7f3e4b8c-9d2a-4f6e-8b5c-1a9e7d3b4c8f
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Secrets Discovery
# MAGIC     description: Detects when someone enumerates what secrets exist in the environment
# MAGIC       by looking for users who list secret scopes and access multiple secrets.
# MAGIC     objective: 'Identify potential reconnaissance activities where an attacker or
# MAGIC       malicious insider enumerates available secrets in the environment. This detection
# MAGIC       triggers when users list secret scopes and subsequently access a high number of
# MAGIC       secrets, which may indicate secret discovery or credential harvesting attempts.
# MAGIC       Maps to MITRE ATT&CK TA0007 - Discovery - T1526 - Cloud Service Discovery.'
# MAGIC     taxonomy: 
# MAGIC       - MITRE.TA0007.Discovery
# MAGIC       - MITRE.T1526.Cloud_Service_Discovery
# MAGIC     fidelity: high
# MAGIC     category: DETECTION
# MAGIC     false_positives: Adjust scopes_threshold and secrets_threshold to manage false positives for your environment. Real world testing shows this behavior is rare.
# MAGIC     severity: high
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: secret_scanning_activity
# MAGIC     input:
# MAGIC       earliest: '2025-01-01'
# MAGIC       latest: '2025-02-25'
# MAGIC       scopes_threshold: 1
# MAGIC       secrets_threshold: 15
# MAGIC     expect:
# MAGIC       count: '>0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs:
# MAGIC     - table: system.access.audit
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - EVENT_DATE
# MAGIC     - SERVICE_NAME
# MAGIC     - ACTION_NAME
# MAGIC     - SCOPES_ENUMERATED
# MAGIC     - SECRETS_USED
# MAGIC     - ANALYSIS
# MAGIC     - USER_EMAIL
# MAGIC     - event_time
# MAGIC     - action_name
# MAGIC     - request_params.scope
# MAGIC     - request_params.key
# MAGIC     - user_identity.email
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def secret_scanning_activity(earliest: str = None, latest: str = None, scopes_threshold: int = 1, secrets_threshold: int = 15):
    from pyspark.sql.functions import (col, current_date, date_sub, to_date, current_timestamp, 
                                       expr, sum as spark_sum, size, collect_set, concat, lit, 
                                       when, coalesce, to_timestamp)

    earliest = earliest or current_timestamp() - expr("INTERVAL 2 months")
    latest = latest or current_timestamp()
    
    df = spark.table("system.access.audit")
    
    # Filter for secret-related actions within the time range
    df_filtered = df.filter(
        (col("action_name").isin("listScopes", "getSecret")) &
        (col("event_time").between(earliest, latest))
    )
    
    # Aggregate data by event_date, service_name, action_name, and user email
    aggregated_data = df_filtered.groupBy(
        to_date(col("event_time")).alias("event_date"),
        col("service_name"),
        col("action_name"),
        col("user_identity.email").alias("email")
    ).agg(
        spark_sum(when(col("action_name") == "listScopes", 1).otherwise(0)).alias("scopes_enumerated"),
        size(collect_set(
            concat(
                coalesce(col("request_params.scope"), lit("")),
                lit(": "),
                coalesce(col("request_params.key"), lit(""))
            )
        )).alias("secrets_used")
    )
    
    # Filter for users who enumerated scopes and used many secrets
    final_result = aggregated_data.filter(
        (col("scopes_enumerated") >= scopes_threshold) &
        (col("secrets_used") >= secrets_threshold)
    ).select(
        to_timestamp(col("event_date")).alias("EVENT_DATE"),
        col("service_name").alias("SERVICE_NAME"),
        col("action_name").alias("ACTION_NAME"),
        concat(
            col("scopes_enumerated").cast("string"),
            lit(" scopes enumerated ("),
            col("secrets_used").cast("string"),
            lit(" secrets used)")
        ).alias("ANALYSIS"),
        col("email").alias("USER_EMAIL"),
        col("scopes_enumerated").alias("SCOPES_ENUMERATED"),
        col("secrets_used").alias("SECRETS_USED")
    ).orderBy(col("EVENT_DATE").desc())
    
    return final_result

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(secret_scanning_activity(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
# COMMAND ----------
