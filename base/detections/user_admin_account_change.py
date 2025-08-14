# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: David Veuve - Databricks
# MAGIC   created: '2025-06-04T12:00:00'
# MAGIC   modified: '2025-06-04T12:00:00'
# MAGIC   uuid: 4d5e6f7a-8b9c-0d1e-2f3a-4b5c6d7e8f9a
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Admin User Account Changes
# MAGIC     description: Detects when users modify admin-level privileges or admin group
# MAGIC       memberships, which could indicate privilege escalation attempts or unauthorized
# MAGIC       administrative access modifications.
# MAGIC     objective: 'Identify potentially suspicious changes to administrative privileges
# MAGIC       including direct admin role assignments, account ownership changes, and
# MAGIC       modifications to admin group memberships. These activities could indicate
# MAGIC       attempts to establish persistence through elevated privileges or unauthorized
# MAGIC       administrative access. Maps to MITRE ATT&CK TA0003 - Persistence - T1098
# MAGIC       - Account Manipulation.'
# MAGIC     taxonomy: 
# MAGIC       - MITRE.TA0003.Persistence
# MAGIC       - MITRE.T1098.Account_Manipulation
# MAGIC     fidelity: low
# MAGIC     category: DETECTION
# MAGIC     false_positives: normal admin activity that should generally be reviewed.
# MAGIC     severity: medium
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: user_admin_account_change
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
# MAGIC     - ACTION_DESCRIPTION
# MAGIC     - USER_EMAIL
# MAGIC     - USER_AGENT
# MAGIC     - SOURCE_IP_ADDRESS
# MAGIC     - REQUEST_PARAMS
# MAGIC     - event_time
# MAGIC     - service_name
# MAGIC     - action_name
# MAGIC     - request_params.targetGroupName
# MAGIC     - user_identity.email
# MAGIC     - user_agent
# MAGIC     - source_ip_address
# MAGIC     - request_params
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def user_admin_account_change(earliest: str = None, latest: str = None):
    from pyspark.sql.functions import (col, current_date, date_sub, current_timestamp, 
                                       expr, to_timestamp, concat, lit, coalesce, when)

    earliest = earliest or current_timestamp() - expr("INTERVAL 2 months")
    latest = latest or current_timestamp()
    
    # Define direct admin privilege actions
    direct_admin_actions = [
        'setAccountAdmin',
        'changeAccountOwner', 
        'setAdmin',
        'removeAdmin'
    ]
    
    # Define group membership actions that could affect admin privileges
    group_membership_actions = [
        'addPrincipalToGroup',
        'removePrincipalFromGroup'
    ]
    
    df = spark.table("system.access.audit")
    
    # Filter for admin-related changes
    df_filtered = df.filter(
        (col("event_time").between(earliest, latest)) &
        (
            # Direct admin privilege actions
            (col("action_name").isin(direct_admin_actions)) |
            # Admin group membership changes
            (
                (col("action_name").isin(group_membership_actions)) &
                (col("request_params.targetGroupName").contains("admin"))
            )
        )
    ).select(
        to_timestamp(col("event_time")).alias("EVENT_TIME"),
        col("service_name").alias("SERVICE_NAME"),
        col("action_name").alias("ACTION_NAME"),
        concat(
            col("action_name"),
            lit(": "),
            coalesce(col("request_params.targetGroupName"), lit("direct configuration"))
        ).alias("ACTION_DESCRIPTION"),
        col("user_identity.email").alias("USER_EMAIL"),
        col("user_agent").alias("USER_AGENT"),
        col("source_ip_address").alias("SOURCE_IP_ADDRESS"),
        col("request_params").alias("REQUEST_PARAMS")
    ).orderBy(col("EVENT_TIME").desc())
    
    return df_filtered

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(user_admin_account_change(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
    
# COMMAND ----------
