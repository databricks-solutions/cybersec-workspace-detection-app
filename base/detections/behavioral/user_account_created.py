# Databricks notebook source
# MAGIC %run ../../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: derek.king
# MAGIC   created: '2025-06-17T12:19:35'
# MAGIC   modified: '2025-06-17T12:19:35'
# MAGIC   uuid: 4883ddd6-e357-40a9-a45d-98ab07c81856
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: User Account Created
# MAGIC     description: Detects new user accounts created via the admin console.
# MAGIC     fidelity: high
# MAGIC     category: POLICY
# MAGIC     objective: Identify user account creation events through the admin console to
# MAGIC       detect unauthorized provisioning activity, potential insider threats, or abuse
# MAGIC       of administrative privileges.
# MAGIC     false_positives: If the account is created by a user whose role requires creating 
# MAGIC       user accounts, then this is likely a false positive. But account creation is also 
# MAGIC       a key way to maintain persistence.
# MAGIC     severity: high
# MAGIC     taxonomy:
# MAGIC     - MITRE.T1098.Account_Manipulation
# MAGIC     - MITRE.T1098.001.Account_Manipulation.Create_Account
# MAGIC     - MITRE.T1078.Valid_Accounts
# MAGIC     - MITRE.T1078.001.Valid_Accounts.Default_Accounts
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC   version: 1.0.0
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: user_account_created
# MAGIC     input:
# MAGIC       earliest: '2024-01-01'
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
# MAGIC     - request_params.endpoint
# MAGIC     - request_params.targetUserName
# MAGIC     - response.status_code
# MAGIC     - service_name
# MAGIC     - source_ip_address
# MAGIC     - user_agent
# MAGIC     - user_identity.email
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def user_account_created(earliest:str = None, latest: str = None,
                         endpoints: list = ["adminConsole", "scim", "autoUserCreation"]):
    """Identities created in the account.

    endpoints: where the add came from. adminConsole = admin UI, scim = SCIM API (scripts,
    Terraform, IdP provisioning -- and an attacker with an admin token), autoUserCreation =
    just-in-time provisioning on first SSO login (logged with a null status). Add
    "DatabricksApps" to also see the service principals Databricks Apps create for
    themselves.
    """
    from pyspark.sql.functions import col, current_date, date_sub, to_date, current_timestamp, expr, when

    earliest = earliest or current_timestamp() - expr("INTERVAL 24 hours")
    latest = latest or current_timestamp()
    df = spark.table("system.access.audit")

    df_filtered = df.filter(
        (col("service_name") == "accounts") &
        (col("action_name").isin(["add"])) &  
        ((col("response.status_code").cast("int") == 200) | col("response.status_code").isNull()) &
        (col("request_params.endpoint").isin(endpoints)) &
        (col("event_time").between(earliest, latest))  
    ).select(
        col("event_time").alias("EVENT_DATE"),
        col("action_name").alias("ACTION"),
        when(col("response.status_code") == 200, "Success").when(col("response.status_code").isNull(), "Unknown")
            .otherwise("Failure").alias("STATUS"),
        col("user_identity.email").alias("SRC_USER"),
        col("request_params.targetUserName").alias("TARGET_USER"),
        when(col("request_params.targetUserName").rlike(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),
             "service_principal").otherwise("user").alias("TARGET_KIND"),
        col("request_params.endpoint").alias("ENDPOINT"),
        col("source_ip_address").alias("SRC_IP"),
        col("user_agent").alias("USER_AGENT"),
        col("audit_level").alias("AUDIT_LEVEL")
    ).orderBy(col("EVENT_DATE").desc())
    
    return df_filtered

# COMMAND ----------
if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(user_account_created(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
