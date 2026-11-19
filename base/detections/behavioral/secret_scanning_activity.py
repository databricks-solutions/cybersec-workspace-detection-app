# Databricks notebook source
# MAGIC %run ../../../lib/common

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
# MAGIC       by looking for principals who list secret scopes, secrets or ACLs and read many
# MAGIC       distinct secrets on the same day.
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
# MAGIC     - SECRETS_REFUSED
# MAGIC     - ANALYSIS
# MAGIC     - USER_EMAIL
# MAGIC     - event_time
# MAGIC     - service_name
# MAGIC     - action_name
# MAGIC     - response.status_code
# MAGIC     - request_params.scope
# MAGIC     - request_params.key
# MAGIC     - user_identity.email
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def secret_scanning_activity(earliest: str = None, latest: str = None, scopes_threshold: int = 1, secrets_threshold: int = 15):
    from pyspark.sql.functions import (col, current_date, date_sub, to_date, current_timestamp,
                                       expr, sum as spark_sum, size, collect_set, concat, lit,
                                       when, coalesce, to_timestamp, concat_ws, array_sort)

    earliest = earliest or current_timestamp() - expr("INTERVAL 2 months")
    latest = latest or current_timestamp()
    
    df = spark.table("system.access.audit")

    enumeration_actions = ["listScopes", "listSecrets", "listAcls"]

    # Secret-related actions in the window. service_name = 'secrets' matters: Unity
    # Catalog also emits a listSecrets action, with different request_params.
    df_filtered = df.filter(
        (col("service_name") == "secrets") &
        (col("action_name").isin(enumeration_actions + ["getSecret"])) &
        (col("event_time").between(earliest, latest))
    )

    is_enumeration = col("action_name").isin(enumeration_actions)
    is_successful_read = (col("action_name") == "getSecret") & (col("response.status_code") == 200)
    is_refused = col("response.status_code") != 200

    # One row per principal per day. Grouping by action_name as well (as this rule
    # used to) puts the enumeration and the reads in different rows, so both
    # thresholds can never be met in the same row and the detection never fires.
    aggregated_data = df_filtered.groupBy(
        to_date(col("event_time")).alias("event_date"),
        col("user_identity.email").alias("email")
    ).agg(
        spark_sum(when(is_enumeration, 1).otherwise(0)).alias("scopes_enumerated"),
        # Distinct secrets actually read: successful getSecret only. Refused reads and
        # the listing calls (which carry no key) are not counted here.
        size(collect_set(when(
            is_successful_read,
            concat(
                coalesce(col("request_params.scope"), lit("")),
                lit(": "),
                coalesce(col("request_params.key"), lit(""))
            )
        ))).alias("secrets_used"),
        # Refused secrets calls, reported separately. They are common in normal
        # traffic (applications probing optional secrets), so they don't feed a threshold.
        spark_sum(when(is_refused, 1).otherwise(0)).alias("secrets_refused"),
        concat_ws(",", array_sort(collect_set(col("action_name")))).alias("actions")
    )

    # Principals who enumerated secrets and read many distinct secrets the same day
    final_result = aggregated_data.filter(
        (col("scopes_enumerated") >= scopes_threshold) &
        (col("secrets_used") >= secrets_threshold)
    ).select(
        to_timestamp(col("event_date")).alias("EVENT_DATE"),
        lit("secrets").alias("SERVICE_NAME"),
        col("actions").alias("ACTION_NAME"),
        concat(
            col("scopes_enumerated").cast("string"),
            lit(" enumeration calls ("),
            col("secrets_used").cast("string"),
            lit(" distinct secrets read, "),
            col("secrets_refused").cast("string"),
            lit(" refused)")
        ).alias("ANALYSIS"),
        col("email").alias("USER_EMAIL"),
        col("scopes_enumerated").alias("SCOPES_ENUMERATED"),
        col("secrets_used").alias("SECRETS_USED"),
        col("secrets_refused").alias("SECRETS_REFUSED")
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
