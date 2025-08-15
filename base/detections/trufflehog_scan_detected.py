# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: david.veuve
# MAGIC   created: '2025-08-14T12:00:00'
# MAGIC   modified: '2025-08-14T12:00:00'
# MAGIC   uuid: 8f4e5c9d-3b3b-5f7f-9c6d-2b0f8e4c5d9g
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: TruffleHog Scan Detected
# MAGIC     description: Detects when TruffleHog scanning tool is used, indicating potential
# MAGIC       credential scanning activity and likely credential leakage.
# MAGIC     fidelity: high
# MAGIC     category: DETECTION
# MAGIC     objective: Identify when TruffleHog scanning tool is used in the environment,
# MAGIC       which typically indicates an attacker is scanning for hardcoded credentials,
# MAGIC       API keys, or other secrets. This is a high-fidelity indicator of credential
# MAGIC       scanning activity and potential credential compromise.
# MAGIC     false_positives: Low -- TruffleHog is a specific security scanning tool with
# MAGIC       a distinctive user agent string. False positives are unlikely unless there
# MAGIC       are legitimate security testing activities.
# MAGIC     severity: high
# MAGIC     taxonomy:
# MAGIC     - MITRE.TA0007.Discovery
# MAGIC     - MITRE.T1526.Cloud_Service_Discovery
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: trufflehog_scan_detected
# MAGIC     input:
# MAGIC       earliest: '2025-01-01'
# MAGIC       latest: '2025-02-25'
# MAGIC     expect:
# MAGIC       count: '>=0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs:
# MAGIC     - table: system.access.audit
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - EVENT_TIME
# MAGIC     - SOURCE_IP_ADDRESS
# MAGIC     - USER_AGENT
# MAGIC     - SRC_USER
# MAGIC     - TOKEN_ID
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def trufflehog_scan_detected(earliest: str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_timestamp, expr, to_date, to_timestamp)

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()
    
    # Load audit logs within the time range
    df = spark.table("system.access.audit")
    
    # Filter for TruffleHog user agent within the time range
    df_filtered = df.filter(
        (col("event_time").between(earliest, latest)) &
        (col("user_agent").like("%TruffleHog%"))
    )
    
    # Select relevant columns and format the output
    final_result = df_filtered.select(
        to_timestamp(col("event_time")).alias("EVENT_TIME"),
        col("source_ip_address").alias("SOURCE_IP_ADDRESS"),
        col("user_agent").alias("USER_AGENT"),
        col("request_params.tokenId").alias("TOKEN_ID"),
        col("user_identity.email").alias("SRC_USER")
    ).orderBy(col("EVENT_TIME").desc())
    
    return final_result

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(trufflehog_scan_detected(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
# COMMAND ----------
