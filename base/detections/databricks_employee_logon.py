# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:15:52'
# MAGIC   modified: '2025-06-17T12:15:52'
# MAGIC   uuid: a1491bb6-ee58-47f3-b64c-9358948ca4d4
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Databricks Employee Logon
# MAGIC     description: Detects successful GENIE_AUTH logins that occurred without verbose
# MAGIC       auditing at the workspace level.
# MAGIC     fidelity: high
# MAGIC     category: POLICY
# MAGIC     objective: Identify successful authentication events from Databricks employees
# MAGIC       to ensure compliance with policies.
# MAGIC     false_positives: unknown
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: databricks_employee_logon
# MAGIC     input:
# MAGIC       earliest: '2025-03-15'
# MAGIC       latest: '2025-03-19'
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
# MAGIC     - request_params.authentication_method
# MAGIC     - response.status_code
# MAGIC     - service_name
# MAGIC     - source_ip_address
# MAGIC     - user_agent
# MAGIC     - user_identity.email
# MAGIC     - workspace_id
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def databricks_employee_logon(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_date, date_sub, to_date, current_timestamp, 
                                       expr, unix_timestamp, round, from_unixtime, when, to_timestamp)

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()

    df = spark.table("system.access.audit")
    
    df_filtered = df.filter(
        (col("service_name") == "accounts") &
        ((col("action_name").isin("login", "certLogin", "jwtLogin", "mfaLogin",
                                 "passwordVerifyAuthentication", "samlLogin")) &
            (col("request_params.authentication_method").isin("GENIE_AUTH"))) &
        (col("response.status_code") == 200) &
        (col("audit_level") == "WORKSPACE_LEVEL") &
        (col("event_time") >= earliest) & (col("event_time") <= latest)
    ).select(
        to_timestamp(col("event_time")).alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        col("user_identity.email").alias("SRC_USER"),
        col("request_params.authentication_method").alias("AUTH_METHOD"),
        col("workspace_id").alias("WORKSPACE_ID"),
        col("audit_level").alias("AUDIT_LEVEL"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_agent").alias("USER_AGENT")
    )

    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(databricks_employee_logon(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
