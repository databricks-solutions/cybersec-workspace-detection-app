# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: root
# MAGIC   created: '2025-05-09T12:56:50'
# MAGIC   modified: '2025-05-09T12:56:50'
# MAGIC   uuid: 4e8de7fb-5fbe-424c-99be-22e6efbb5445
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Access Token Created
# MAGIC     description: Detects access tokens created from unknown IPs or user agents with
# MAGIC       a non-zero lifetime.
# MAGIC     objective: 'Identify potentially suspicious access token creation events by filtering
# MAGIC       for: the `generateDbToken` action within the `accounts` service, tokens created
# MAGIC       outside of known IP address and user agent baselines, and tokens with a measurable
# MAGIC       lifespan (i.e., not ephemeral). This helps surface anomalous authentication
# MAGIC       behavior that may signify credential abuse, script-based automation, or unauthorized
# MAGIC       access attempts.
# MAGIC 
# MAGIC       '
# MAGIC     taxonomy: []
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: access_token_created
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
# MAGIC     - TOKEN_LIFETIME_DAYS
# MAGIC     - action_name
# MAGIC     - audit_level
# MAGIC     - event_time
# MAGIC     - request_params.tokenExpirationTime
# MAGIC     - request_params.userId
# MAGIC     - response.status_code
# MAGIC     - service_name
# MAGIC     - source_ip_address
# MAGIC     - user_agent
# MAGIC     - user_identity.email
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def access_token_created(earliest:str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_date, date_sub, to_date, current_timestamp, 
                                       expr, unix_timestamp, round, from_unixtime, when, to_timestamp)

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()
    
    known_user_agents = [r'(?i)linux auth.*$']
    known_ua_regex = "|".join(known_user_agents)

    known_src_ips = ["52.9.53.2"]
    known_src_ips_regex = "|".join(known_src_ips)

    df = spark.table("system.access.audit")
 
    df_filtered = df.filter(
        (col("service_name") == "accounts") &
        (col("action_name").isin("generateDbToken")) &
        (~col("user_agent").rlike(known_ua_regex)) &
        (~col("source_ip_address").rlike(known_src_ips_regex)) &
        (col("event_time").between(earliest, latest))
    ).withColumn(
        "TOKEN_LIFETIME_DAYS",
        round(((unix_timestamp(from_unixtime(col("request_params.tokenExpirationTime") / 1000)) - unix_timestamp(col("event_time"))) / 3600 / 24),0)
    )
    
    df_filtered = df_filtered.filter(col("TOKEN_LIFETIME_DAYS") > 0
    ).select(
        to_timestamp(col("event_time")).alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        col("TOKEN_LIFETIME_DAYS"),
        col("audit_level").alias("AUDIT_LEVEL"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_identity.email").alias("SRC_USER"),
        col("request_params.userId").alias("USER"),
        col("user_agent").alias("USER_AGENT")
    ).orderBy(col("EVENT_DATE").desc())
    

    return df_filtered

# COMMAND ----------

display(access_token_created(earliest="2025-01-01", latest="2025-02-25"))

# COMMAND ----------

