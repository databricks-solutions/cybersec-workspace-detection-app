# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T11:54:55'
# MAGIC   modified: '2025-06-17T11:54:55'
# MAGIC   uuid: 60daabdb-eec7-45f1-8d66-9911344140f8
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Sso Config Changed
# MAGIC     description: Detects creation or update of single sign-on (SSO) configuration
# MAGIC       settings.
# MAGIC     fidelity: high
# MAGIC     category: POLICY
# MAGIC     objective: Monitor for changes to SSO configuration to detect unauthorized identity
# MAGIC       provider tampering, which could allow attackers to redirect authentication flows
# MAGIC       or weaken enterprise access controls.
# MAGIC     false_positives: unknown
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: sso_config_changed
# MAGIC     input:
# MAGIC       earliest: '2025-03-13'
# MAGIC       latest: '2025-03-14'
# MAGIC     expect:
# MAGIC       count: '>0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs:
# MAGIC     - table: system.access.audit
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - action_name
# MAGIC     - audit_level
# MAGIC     - event_time
# MAGIC     - request_params
# MAGIC     - response.status_code
# MAGIC     - service_name
# MAGIC     - source_ip_address
# MAGIC     - user_agent
# MAGIC     - user_identity.email
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asAlert)
def sso_config_changed(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_date, date_sub, to_date, current_timestamp, 
                                       expr, unix_timestamp, round, from_unixtime, when, to_timestamp)

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()

    df = spark.table("system.access.audit")

    df_filtered = df.filter(
        (col("service_name") == "ssoConfigBackend") &
        (col("action_name").isin("create", "update")) &
        (col("event_time") >= earliest) & (col("event_time") <= latest)
    ).select(
        to_timestamp(col("event_time")).alias("EVENT_DATE"),
        col("service_name").alias("SERVICE"),
        col("action_name").alias("ACTION"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        col("user_identity.email").alias("SRC_USER"),
        col("request_params").getItem("status").alias("SSO_STATUS"),
        col("request_params").getItem("config").alias("SSO_CONFIG"),
        col("source_ip_address").alias("SRC_IP"),
        col("response.status_code").alias("RESPONSE_CODE"),
        col("user_agent").alias("USER_AGENT"),
        col("audit_level").alias("AUDIT_LEVEL")
    )

    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(sso_config_changed(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
