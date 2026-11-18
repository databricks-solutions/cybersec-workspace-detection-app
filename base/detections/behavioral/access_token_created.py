# Databricks notebook source
# MAGIC %run ../../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T11:59:15'
# MAGIC   modified: '2025-06-17T11:59:15'
# MAGIC   uuid: ea49708b-50cf-4926-b734-c8acef522744
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Access Token Created
# MAGIC     description: Detects access tokens created from unknown IPs or user agents with
# MAGIC       a non-zero lifetime.
# MAGIC     fidelity: high
# MAGIC     category: POLICY
# MAGIC     objective: 'Identify potentially suspicious access token creation events by filtering
# MAGIC       for: the `generateDbToken` action within the `accounts` service, tokens created
# MAGIC       outside of known IP address and user agent baselines, and tokens with a measurable
# MAGIC       lifespan (i.e., not ephemeral). This helps surface anomalous authentication
# MAGIC       behavior that may signify credential abuse, script-based automation, or unauthorized
# MAGIC       access attempts.'
# MAGIC     false_positives: unknown
# MAGIC     severity: high
# MAGIC     taxonomy:
# MAGIC     - none
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
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
# MAGIC     - TOKEN_LIFETIME_HOURS
# MAGIC     - NO_EXPIRY
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
                                       expr, unix_timestamp, round, from_unixtime, when, to_timestamp, coalesce, lit)

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
        (~coalesce(col("user_agent"), lit("")).rlike(known_ua_regex)) &
        (~coalesce(col("source_ip_address"), lit("")).rlike(known_src_ips_regex)) &
        (col("event_time").between(earliest, latest))
    ).withColumn(
        # Lifetime in hours. tokenExpirationTime is epoch milliseconds; a null, zero or
        # negative value means the token never expires -- the most dangerous case, so it is
        # kept and labelled rather than dropped. (Rounding to whole days and filtering > 0
        # used to drop both no-expiry tokens and tokens living under 12 hours.)
        "TOKEN_LIFETIME_HOURS",
        when(col("request_params.tokenExpirationTime").cast("bigint") > 0,
             round((col("request_params.tokenExpirationTime").cast("bigint") / 1000
                    - unix_timestamp(col("event_time"))) / 3600, 2))
    ).withColumn(
        "NO_EXPIRY", col("TOKEN_LIFETIME_HOURS").isNull()
    )

    df_filtered = df_filtered.select(
        to_timestamp(col("event_time")).alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        when(col("response.status_code") == 200, "Success").otherwise("Failure").alias("STATUS"),
        round(col("TOKEN_LIFETIME_HOURS") / 24, 2).alias("TOKEN_LIFETIME_DAYS"),
        col("TOKEN_LIFETIME_HOURS"),
        col("NO_EXPIRY"),
        col("audit_level").alias("AUDIT_LEVEL"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_identity.email").alias("SRC_USER"),
        col("request_params.userId").alias("USER"),
        col("user_agent").alias("USER_AGENT")
    ).orderBy(col("EVENT_DATE").desc())
    

    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(access_token_created(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))

# COMMAND ----------

