# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: David Veuve - Databricks
# MAGIC   created: '2025-06-04T12:00:00'
# MAGIC   modified: '2025-06-04T12:00:00'
# MAGIC   uuid: 3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Potential Data Movement via Workspace Downloads
# MAGIC     description: Detects downloads from the workspace including exports, large query
# MAGIC       results, file downloads, and model artifacts that could indicate data
# MAGIC       exfiltration attempts.
# MAGIC     objective: 'Identify potentially suspicious download activities that could indicate
# MAGIC       data exfiltration attempts. This includes large query result downloads, workspace
# MAGIC       exports in non-source formats, file downloads, and model version downloads.
# MAGIC       These activities may indicate unauthorized data movement or intellectual property
# MAGIC       theft. Maps to MITRE ATT&CK TA0010 - Exfiltration - T1567 - Exfiltration Over
# MAGIC       Web Service.'
# MAGIC     taxonomy: 
# MAGIC       - MITRE.TA0010.Exfiltration
# MAGIC       - MITRE.T1567.Exfiltration_Over_Web_Service
# MAGIC     fidelity: low
# MAGIC     category: DETECTION
# MAGIC     false_positives: normal user activities
# MAGIC     severity: medium
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: potential_data_movement_workspace_downloads
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
# MAGIC     - request_params.workspaceExportFormat
# MAGIC     - request_params.fileType
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def potential_data_movement_workspace_downloads(earliest: str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_date, date_sub, current_timestamp, 
                                       expr, to_timestamp, when, lit, coalesce)

    earliest = earliest or current_timestamp() - expr("INTERVAL 2 months")
    latest = latest or current_timestamp()
    
    # Define suspicious download actions
    direct_download_actions = [
        'downloadPreviewResults',
        'downloadLargeResults', 
        'filesGet',
        'getModelVersionDownloadUri',
        'getModelVersionSignedDownloadUri'
    ]
    
    df = spark.table("system.access.audit")
    
    # Filter for various download/export activities that could indicate data exfiltration
    df_filtered = df.filter(
        (col("event_time").between(earliest, latest)) &
        (
            # Direct download actions
            (col("action_name").isin(direct_download_actions)) |
            # Workspace exports (excluding SOURCE format which is normal development)
            (
                (col("action_name") == "workspaceExport") &
                (coalesce(col("request_params.workspaceExportFormat"), lit("")) != "SOURCE")
            ) |
            # Query result downloads (excluding arrows format which is normal)
            (
                (col("action_name") == "downloadQueryResult") &
                (coalesce(col("request_params.fileType"), lit("")) != "arrows")
            )
        )
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
    display(potential_data_movement_workspace_downloads(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))

# COMMAND ----------
