# Databricks notebook source
# MAGIC %run ../../../lib/common

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
# MAGIC       exports (all formats), file downloads, MLflow artifact/trace reads and model
# MAGIC       version downloads, aggregated per principal, source IP and hour.
# MAGIC       These activities may indicate unauthorized data movement or intellectual property
# MAGIC       theft. Maps to MITRE ATT&CK TA0010 - Exfiltration - T1567 - Exfiltration Over
# MAGIC       Web Service.'
# MAGIC     taxonomy: 
# MAGIC       - MITRE.TA0010.Exfiltration
# MAGIC       - MITRE.T1567.Exfiltration_Over_Web_Service
# MAGIC     fidelity: low
# MAGIC     category: DETECTION
# MAGIC     false_positives: CLI/CI workspace sync exporting one home folder can exceed min_objects;
# MAGIC       tune min_objects per environment. Cross-home sweeps (min_foreign_homes) are rarer.
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
# MAGIC     - WINDOW_START
# MAGIC     - USER_EMAIL
# MAGIC     - SOURCE_IP_ADDRESS
# MAGIC     - EVENTS
# MAGIC     - DISTINCT_OBJECTS
# MAGIC     - FOREIGN_HOMES
# MAGIC     - RESULT_DOWNLOADS
# MAGIC     - event_time
# MAGIC     - action_name
# MAGIC     - user_identity.email
# MAGIC     - user_agent
# MAGIC     - source_ip_address
# MAGIC     - request_params.workspaceExportFormat
# MAGIC     - request_params.fileType
# MAGIC     - request_params.notebookFullPath
# MAGIC     - request_params.path
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def potential_data_movement_workspace_downloads(earliest: str = None, latest: str = None,
                                                min_objects: int = 200, min_foreign_homes: int = 3,
                                                min_result_downloads: int = 1):
    """Download / export activity aggregated per principal, source IP and hour.

    A bucket is reported when ANY of these holds:
      - min_objects distinct objects (notebooks, files, artifacts, model versions) left in the hour;
      - min_foreign_homes other users' home folders (/Users/<x>, /Repos/<x>) were exported from;
      - min_result_downloads query/notebook result downloads (actual data, rare) happened.

    SOURCE-format workspace exports are included: SOURCE is what the REST API, CLI and
    scripted dumps use, so excluding it hid most bulk exports. Heavy legitimate exporters
    (CLI sync, CI, SAT) export one home folder; a sweep across many users' homes is the
    exfiltration shape. Set all three thresholds to 0/1 to get every bucket.
    """
    from pyspark.sql.functions import (col, current_timestamp, expr, lit, coalesce, when, concat,
                                       date_trunc, regexp_extract, lower, count, countDistinct,
                                       collect_set, min as spark_min, max as spark_max, sum as spark_sum,
                                       slice as spark_slice, array_sort, size)

    earliest = earliest or current_timestamp() - expr("INTERVAL 2 months")
    latest = latest or current_timestamp()

    direct_download_actions = [
        'downloadPreviewResults',
        'downloadLargeResults',
        'filesGet',
        'createDownloadUrl',                    # pre-signed download link for a volume/workspace file
        'getModelVersionDownloadUri',
        'getModelVersionSignedDownloadUri',
        'readArtifact',                         # MLflow artifact read
        'readTraceData',                        # MLflow trace read
        'workspaceExport',
    ]
    result_download_actions = ['downloadPreviewResults', 'downloadLargeResults', 'downloadQueryResult']

    df = spark.table("system.access.audit").filter(
        col("event_time").between(earliest, latest) & (
            col("action_name").isin(direct_download_actions) |
            # Query result downloads (excluding arrows, which is the UI rendering results)
            ((col("action_name") == "downloadQueryResult") &
             (coalesce(col("request_params.fileType"), lit("")) != "arrows")) |
            # UC model version read credential (model weights leaving via short-lived cloud creds)
            ((col("action_name") == "generateTemporaryModelVersionCredential") &
             (col("request_params.operation") == "READ_MODEL_VERSION"))
        )
    )

    path = coalesce(col("request_params.notebookFullPath"), col("request_params.path"),
                    col("request_params.filePath"))
    obj = coalesce(
        path,
        col("request_params.artifactLocation"),
        col("request_params.request_id"),
        concat(col("request_params.model_name"), lit("/"), col("request_params.version")),
        col("event_id"),
    )
    home = regexp_extract(coalesce(path, lit("")), r'^(/Workspace)?/(Users|Repos)/([^/]+)', 3)
    email = col("user_identity.email")

    df = df.select(
        date_trunc("hour", col("event_time")).alias("WINDOW_START"),
        email.alias("USER_EMAIL"),
        col("source_ip_address").alias("SOURCE_IP_ADDRESS"),
        col("event_time"), col("action_name"), col("user_agent"),
        col("request_params.workspaceExportFormat").alias("export_format"),
        obj.alias("object"),
        when((home != "") & (lower(home) != lower(email)), home).alias("foreign_home"),
    )

    agg = df.groupBy("WINDOW_START", "USER_EMAIL", "SOURCE_IP_ADDRESS").agg(
        count(lit(1)).alias("EVENTS"),
        countDistinct("object").alias("DISTINCT_OBJECTS"),
        countDistinct("foreign_home").alias("FOREIGN_HOMES"),
        spark_sum(when(col("action_name").isin(result_download_actions), 1).otherwise(0)).alias("RESULT_DOWNLOADS"),
        array_sort(collect_set("action_name")).alias("ACTIONS"),
        array_sort(collect_set("export_format")).alias("EXPORT_FORMATS"),
        array_sort(collect_set("user_agent")).alias("USER_AGENTS"),
        spark_slice(array_sort(collect_set("foreign_home")), 1, 20).alias("FOREIGN_HOME_SAMPLE"),
        spark_slice(array_sort(collect_set("object")), 1, 20).alias("OBJECT_SAMPLE"),
        spark_min("event_time").alias("FIRST_SEEN"),
        spark_max("event_time").alias("LAST_SEEN"),
    )

    return agg.filter(
        (col("DISTINCT_OBJECTS") >= min_objects) |
        (col("FOREIGN_HOMES") >= min_foreign_homes) |
        (col("RESULT_DOWNLOADS") >= min_result_downloads)
    ).orderBy(col("WINDOW_START").desc())

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(potential_data_movement_workspace_downloads(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))

# COMMAND ----------
