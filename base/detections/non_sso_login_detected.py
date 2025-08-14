# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:01:22'
# MAGIC   modified: '2025-06-17T12:01:22'
# MAGIC   uuid: 9c9a83ff-472a-408b-ae7c-148637267699
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Non Sso Login Detected
# MAGIC     description: Detects successful user logins that bypass SSO-based authentication
# MAGIC       methods.
# MAGIC     fidelity: high
# MAGIC     category: POLICY
# MAGIC     objective: Identify authentication events that do not use the approved browser-based
# MAGIC       SAML SSO method, which may signal use of service credentials, misconfigured
# MAGIC       identity settings, or potential account compromise.
# MAGIC     false_positives: unknown
# MAGIC     severity: low
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: non_sso_login_detected
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
# MAGIC     - EVENT_DATE
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
def non_sso_login_detected(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_date, date_sub, to_date, current_timestamp, 
                                       expr, unix_timestamp, round, from_unixtime, when, to_timestamp)

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()

    df = spark.table("system.access.audit")
    
    df_filtered = df.filter(
        (col("service_name") == "accounts") &
        ((col("action_name").isin("login", "certLogin", "jwtLogin", "mfaLogin",
                                 "passwordVerifyAuthentication", "samlLogin")) &
         (~col("request_params.authentication_method").isin("BROWSER_BYO_IDP_SAML"))
        ) &
        (col("response.status_code") == 200) &
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
    ).orderBy(col("EVENT_DATE").desc())

    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(non_sso_login_detected(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
