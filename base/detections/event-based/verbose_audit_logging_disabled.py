# Databricks notebook source
# MAGIC %run ../../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:20:38'
# MAGIC   modified: '2025-06-17T12:20:38'
# MAGIC   uuid: acfbe7ce-8108-4d6b-816b-f7963ec2bae1
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Verbose Audit Logging Disabled
# MAGIC     description: Detects when verbose audit logging is explicitly disabled at the
# MAGIC       workspace configuration level.
# MAGIC     fidelity: high
# MAGIC     category: POLICY
# MAGIC     objective: Monitor configuration changes that disable verbose audit logs to detect
# MAGIC       attempts at reducing system visibility, which may signal attacker evasion, insider
# MAGIC       threat activity, or unauthorized configuration tampering.
# MAGIC     false_positives: unknown
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: verbose_audit_disabled
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
# MAGIC     - EVENT_DATE
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

@detect(output=Output.asDataFrame)
def verbose_audit_disabled(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_date, date_sub, to_date, current_timestamp, 
                                       expr, unix_timestamp, round, from_unixtime, when, to_timestamp,
                                       lit, lower)

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()

    df = spark.table("system.access.audit")

    # workspaceConfKeys / workspaceConfValues are comma-joined in matching positions when one
    # request changes several settings, so look for the pair anywhere in the list instead of
    # comparing the whole string (which let "...,enableVerboseAuditLogs" / "...,false" through).
    # Values are not escaped: a list setting's value can contain a comma and shift the positions.
    # Setting names never contain a comma, so values are paired only when the token counts match;
    # otherwise the value is unknown and configuration_changes_high_priority reports the edit by key.
    verbose_value = expr("""try_element_at(filter(transform(split(COALESCE(request_params['workspaceConfKeys'], ''), ','), (k, i) -> named_struct('key', trim(k), 'value', CASE WHEN size(split(COALESCE(request_params['workspaceConfKeys'], ''), ',')) = size(split(COALESCE(request_params['workspaceConfValues'], ''), ',')) THEN trim(try_element_at(split(COALESCE(request_params['workspaceConfValues'], ''), ','), i + 1)) END)), c -> c.key = 'enableVerboseAuditLogs'), 1).value""")

    df_filtered = df.filter(
        (col("action_name").isin("workspaceConfEdit")) &
        (lower(verbose_value) == "false") &
        (col("event_time") >= earliest) & (col("event_time") <= latest)
    ).select(
        to_timestamp(col("event_time")).alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        col("user_identity.email").alias("SRC_USER"),
        lit("enableVerboseAuditLogs").alias("CONF_KEY"),
        when(lower(verbose_value) == "false", "Disabled").otherwise("Enabled").alias("CONF_VALUE"),
        col("audit_level").alias("AUDIT_LEVEL"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_agent").alias("USER_AGENT")
    ).orderBy(col("EVENT_DATE").desc())

    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(verbose_audit_disabled(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
