# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:21:38'
# MAGIC   modified: '2025-06-17T12:21:38'
# MAGIC   uuid: 479f8708-b446-4a2a-af32-0c14ee52a5d4
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Access Token Deleted
# MAGIC     description: Detects access tokens being revoked via the accounts service.
# MAGIC     fidelity: high
# MAGIC     category: POLICY
# MAGIC     objective: Monitor for explicit revocation of access tokens to track potentially
# MAGIC       suspicious cleanup activity, such as unauthorized credential invalidation or
# MAGIC       the concealment of prior access.
# MAGIC     false_positives: unknown
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: access_token_deleted
# MAGIC     input:
# MAGIC       earliest: '2020-01-01'
# MAGIC       latest: '2025-02-25'
# MAGIC     expect:
# MAGIC       count: '>0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs:
# MAGIC     - table: system.access.audit
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - EVENT_DATE
# MAGIC     - action_name
# MAGIC     - audit_level
# MAGIC     - event_time
# MAGIC     - request_params.tokenHash
# MAGIC     - response.status_code
# MAGIC     - service_name
# MAGIC     - source_ip_address
# MAGIC     - user_agent
# MAGIC     - user_identity.email
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def access_token_deleted(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import col, current_date, date_sub, to_date, current_timestamp, expr, to_timestamp

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()
    df = spark.table("system.access.audit")

    df_filtered = df.filter(
        (col("service_name") == "accounts") &
        col("action_name").isin("revokeDbToken") &
        (col("event_time") >= earliest) & (col("event_time") <= latest), 
    ).select(
        to_timestamp(col("event_time")).alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_identity.email").alias("SRC_USER"),
        col("request_params.tokenHash").alias("TOKEN_HASH"),
        col("user_agent").alias("USER_AGENT"),
        col("response.status_code").alias("STATUS"),
        col("audit_level").alias("AUDIT_LEVEL")
    ).orderBy(col("EVENT_DATE").desc())
    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(access_token_deleted(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))