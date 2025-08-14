# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: David Veuve - Databricks
# MAGIC   created: '2025-06-04T12:00:00'
# MAGIC   modified: '2025-06-04T12:00:00'
# MAGIC   uuid: 9b5e6f7a-2c3d-4b4e-8f9a-6c7e8d2f4a3b
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Potential Data Movement Commands with SQL Queries
# MAGIC     description: Detects SQL queries that contain COPY INTO statements with explicit
# MAGIC       credentials, which could indicate data exfiltration attempts using SQL commands
# MAGIC       with embedded credentials.
# MAGIC     objective: 'Identify potentially suspicious SQL queries that use COPY INTO commands
# MAGIC       with explicit credentials instead of using secure, pre-configured storage
# MAGIC       credentials. These queries could indicate attempts to exfiltrate data to
# MAGIC       external locations using embedded credentials in SQL statements. Maps to
# MAGIC       MITRE ATT&CK TA0010 - Exfiltration - T1537 - Transfer Data to Cloud Account.'
# MAGIC     taxonomy: 
# MAGIC       - MITRE.TA0010.Exfiltration
# MAGIC       - MITRE.T1537.Transfer_Data_to_Cloud_Account
# MAGIC     fidelity: high
# MAGIC     category: DETECTION
# MAGIC     false_positives: normal user behavior that involves copying data.
# MAGIC     severity: high
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: potential_data_movement_sql_queries
# MAGIC     input:
# MAGIC       earliest: '2025-01-01'
# MAGIC       latest: '2025-02-25'
# MAGIC       target_user: null
# MAGIC     expect:
# MAGIC       count: '>0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs:
# MAGIC     - table: system.query.history
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - START_TIME
# MAGIC     - EXECUTED_AS
# MAGIC     - STATEMENT_TEXT
# MAGIC     - QUERY_ID
# MAGIC     - WAREHOUSE_ID
# MAGIC     - COMPUTE_NAME
# MAGIC     - DURATION_MS
# MAGIC     - ROWS_PRODUCED
# MAGIC     - start_time
# MAGIC     - executed_as
# MAGIC     - statement_text
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def potential_data_movement_sql_queries(earliest: str = None, latest: str = None, target_user: str = None):
    from pyspark.sql.functions import (col, current_date, date_sub, current_timestamp, 
                                       expr, to_timestamp, upper, length, trim)

    earliest = earliest or current_timestamp() - expr("INTERVAL 2 months")
    latest = latest or current_timestamp()
    
    df = spark.table("system.query.history")
    
    # Base filter for time range and COPY INTO with CREDENTIALS
    df_filtered = df.filter(
        (col("start_time").between(earliest, latest)) &
        (upper(col("statement_text")).contains("COPY INTO")) &
        (upper(col("statement_text")).contains("CREDENTIALS")) &
        (~upper(col("statement_text")).contains("COPY INTO\\%CREDENTIALS%"))  # Exclude escaped patterns
    )
    
    # Apply user filter if specified
    if target_user:
        df_filtered = df_filtered.filter(col("executed_as") == target_user)
    
    # Select relevant columns for analysis
    df_result = df_filtered.select(
        to_timestamp(col("start_time")).alias("START_TIME"),
        col("executed_as").alias("EXECUTED_AS"),
        col("statement_text").alias("STATEMENT_TEXT"),
        col("query_id").alias("QUERY_ID"),
        col("warehouse_id").alias("WAREHOUSE_ID"),
        col("compute.name").alias("COMPUTE_NAME"),
        col("duration_ms").alias("DURATION_MS"),
        col("rows_produced").alias("ROWS_PRODUCED")
    ).orderBy(col("START_TIME").desc())
    
    return df_result

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(potential_data_movement_sql_queries(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
# COMMAND ----------
