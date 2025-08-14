# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: David Veuve - Databricks
# MAGIC   created: '2025-06-04T12:00:00'
# MAGIC   modified: '2025-06-04T12:00:00'
# MAGIC   uuid: 8a4f5c6d-1e2b-4a3c-9f8e-7b5d9a1c3e2f
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Potential Data Movement Commands with Explicit Credentials
# MAGIC     description: Detects events where users execute commands that could involve explicit
# MAGIC       credentials for data movement operations, such as DBFS mounts, storage credential
# MAGIC       operations, or connection management.
# MAGIC     objective: 'Identify potentially suspicious data movement activities where explicit
# MAGIC       credentials might be provided instead of using existing secure configurations.
# MAGIC       These operations could indicate data exfiltration attempts or unauthorized data
# MAGIC       movement to external cloud accounts. Maps to MITRE ATT&CK TA0010 - Exfiltration
# MAGIC       - T1537 - Transfer Data to Cloud Account.'
# MAGIC     taxonomy: 
# MAGIC       - MITRE.TA0010.Exfiltration
# MAGIC       - MITRE.T1537.Transfer_Data_to_Cloud_Account
# MAGIC     fidelity: medium
# MAGIC     category: DETECTION
# MAGIC     false_positives: normal user behavior that involves copying data, and normal admin activity that should generally be reviewed.
# MAGIC     severity: high
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: potential_data_movement_explicit_creds
# MAGIC     input:
# MAGIC       earliest: '2025-01-01'
# MAGIC       latest: '2025-02-25'
# MAGIC     expect:
# MAGIC       count: '>0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs:
# MAGIC     - table: system.access.audit
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - EVENT_TIME
# MAGIC     - SERVICE_NAME
# MAGIC     - ACTION_NAME
# MAGIC     - USER_EMAIL
# MAGIC     - USER_AGENT
# MAGIC     - SOURCE_IP_ADDRESS
# MAGIC     - REQUEST_PARAMS
# MAGIC     - event_time
# MAGIC     - service_name
# MAGIC     - action_name
# MAGIC     - user_identity.email
# MAGIC     - user_agent
# MAGIC     - source_ip_address
# MAGIC     - request_params
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def potential_data_movement_explicit_creds(earliest: str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_date, date_sub, current_timestamp, 
                                       expr, to_timestamp)

    earliest = earliest or current_timestamp() - expr("INTERVAL 2 months")
    latest = latest or current_timestamp()
    
    # List of actions that could involve explicit credentials for data movement
    suspicious_actions = [
        'mount',
        'createStorageCredential', 
        'updateStorageCredential',
        'createConnection',
        'updateConnection'
    ]
    
    df = spark.table("system.access.audit")
    
    # Filter for data movement actions with potential explicit credentials
    df_filtered = df.filter(
        (col("action_name").isin(suspicious_actions)) &
        (col("event_time").between(earliest, latest))
    ).select(
        to_timestamp(col("event_time")).alias("EVENT_TIME"),
        col("service_name").alias("SERVICE_NAME"),
        col("action_name").alias("ACTION_NAME"),
        col("user_identity.email").alias("USER_EMAIL"),
        col("user_agent").alias("USER_AGENT"),
        col("source_ip_address").alias("SOURCE_IP_ADDRESS"),
        col("request_params").alias("REQUEST_PARAMS")
    ).orderBy(col("EVENT_TIME").desc())
    
    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(potential_data_movement_explicit_creds(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
# COMMAND ----------
