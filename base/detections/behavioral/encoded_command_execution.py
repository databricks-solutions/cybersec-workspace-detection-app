# Databricks notebook source
# MAGIC %run ../../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: David Veuve - Databricks
# MAGIC   created: '2025-07-24T12:00:00'
# MAGIC   modified: '2025-07-24T12:00:00'
# MAGIC   uuid: b6500154-4635-43e4-b1fd-a2b59791a4bc
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Encoded Command Execution in SQL or Notebook Commands
# MAGIC     description: Detects SQL statements or notebook commands that use encoding/decoding
# MAGIC       functions (UNHEX, xxd, base64) to obfuscate and execute arbitrary commands.
# MAGIC       Attackers embed hex- or base64-encoded payloads inside SQL or shell expressions
# MAGIC       to evade content-based controls.
# MAGIC     objective: 'Identify SQL or notebook commands that contain encoded payloads
# MAGIC       decoded at runtime — a classic command-injection obfuscation technique observed
# MAGIC       in Databricks pen tests and red-team exercises. Encoded commands are used to
# MAGIC       hide curl exfiltration, reverse shells, and credential harvesting from
# MAGIC       plain-text keyword detections. Maps to MITRE ATT&CK TA0005 - Defense Evasion
# MAGIC       - T1027 - Obfuscated Files or Information, and TA0002 - Execution
# MAGIC       - T1059 - Command and Scripting Interpreter.'
# MAGIC     taxonomy:
# MAGIC       - MITRE.TA0005.Defense_Evasion
# MAGIC       - MITRE.T1027.Obfuscated_Files_or_Information
# MAGIC       - MITRE.TA0002.Execution
# MAGIC       - MITRE.T1059.Command_and_Scripting_Interpreter
# MAGIC     fidelity: high
# MAGIC     category: DETECTION
# MAGIC     false_positives: legitimate data-engineering use of UNHEX for binary data processing,
# MAGIC       developer testing of encoding functions, or hex literals in data migration scripts.
# MAGIC       Review STATEMENT_TEXT for context before escalating.
# MAGIC     severity: high
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: encoded_command_execution
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
# MAGIC     - table: system.access.audit
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - START_TIME
# MAGIC     - SRC_USER
# MAGIC     - STATEMENT_TEXT
# MAGIC     - STATEMENT_ID
# MAGIC     - ENCODING_TECHNIQUE
# MAGIC     - SOURCE
# MAGIC ```

# COMMAND ----------

@detect(output=Output.asDataFrame)
def encoded_command_execution(earliest: str = None, latest: str = None, target_user: str = None):
    from pyspark.sql.functions import (col, current_timestamp, expr, to_timestamp,
                                       upper, lit, when)

    earliest = earliest or current_timestamp() - expr("INTERVAL 7 days")
    latest = latest or current_timestamp()

    # --- Source 1: SQL query history ---
    # Covers SQL cells, DBSQL warehouses, and SQL-via-API
    qh = spark.table("system.query.history")

    qh_filtered = qh.filter(
        (col("start_time").between(earliest, latest)) &
        (
            # UNHEX() used to decode a hex string inside SQL
            upper(col("statement_text")).contains("UNHEX(") |
            # xxd reverse-decode: hex bytes piped through xxd -r -p and executed
            (col("statement_text").contains("xxd") & col("statement_text").contains("-r")) |
            # base64 decode piped to a shell. Match -d / --decode on a word boundary so
            # trivial evasions like `base64 -d|bash` and `base64 -d<<<...` are still caught.
            (col("statement_text").contains("base64") &
             col("statement_text").rlike(r"(--decode|-d)\b")) |
            # printf hex decode: printf "%s" "<hex>" piped to a shell. Require the pipe-to-shell
            # (or xxd) that makes the payload *executable* — printf + a bare hex run co-occurs
            # innocently (stripped UUIDs, SHA hashes, statement ids) and is a large FP source.
            (col("statement_text").contains("printf") &
             col("statement_text").rlike(r"[0-9a-fA-F]{20,}") &
             (col("statement_text").contains("xxd") |
              col("statement_text").rlike(r"\|\s*(ba)?sh\b")))
        )
    )

    if target_user:
        qh_filtered = qh_filtered.filter(col("executed_as") == target_user)

    qh_result = qh_filtered.select(
        to_timestamp(col("start_time")).alias("START_TIME"),
        col("executed_as").alias("SRC_USER"),
        col("statement_text").alias("STATEMENT_TEXT"),
        col("statement_id").alias("STATEMENT_ID"),
        # First-match label for triage, NOT an exhaustive list: a statement that uses
        # more than one technique (e.g. both UNHEX( and base64) reports only the first
        # branch that matches, in the order below.
        when(upper(col("statement_text")).contains("UNHEX("), lit("UNHEX"))
        .when(col("statement_text").contains("xxd") & col("statement_text").contains("-r"), lit("xxd decode"))
        .when(col("statement_text").contains("base64"), lit("base64 decode"))
        .when(col("statement_text").contains("printf"), lit("printf hex"))
        .otherwise(lit("encoded payload")).alias("ENCODING_TECHNIQUE"),
        lit("query_history").alias("SOURCE")
    )

    # --- Source 2: Audit log notebook/command events ---
    # Covers Python/Scala/R cells that embed shell commands via dbutils.fs or subprocess
    audit = spark.table("system.access.audit")

    # Command executions arrive under service_name "notebook", "jobs", and (via
    # submitCommand) as one-off submissions. On real workspaces "jobs" dwarfs "notebook"
    # by ~500x, and a scheduled job task is exactly where an encoded payload would live
    # (it also buys the attacker persistence and a schedule), so all three are in scope.
    audit_filtered = audit.filter(
        (col("event_time").between(earliest, latest)) &
        (col("service_name").isin("notebook", "jobs")) &
        (col("action_name").isin("runCommand", "submitCommand")) &
        (
            upper(col("request_params.commandText")).contains("UNHEX(") |
            (col("request_params.commandText").contains("xxd") &
             col("request_params.commandText").contains("-r")) |
            # base64 decode on a word boundary — catches `base64 -d|bash`, `base64 -d<<<...`
            (col("request_params.commandText").contains("base64") &
             col("request_params.commandText").rlike(r"(--decode|-d)\b")) |
            # printf hex decode piped to a shell (or xxd). Require the executable pipe to
            # avoid firing on printf + a bare hex run, which co-occurs innocently.
            (col("request_params.commandText").contains("printf") &
             col("request_params.commandText").rlike(r"[0-9a-fA-F]{20,}") &
             (col("request_params.commandText").contains("xxd") |
              col("request_params.commandText").rlike(r"\|\s*(ba)?sh\b")))
        )
    )

    if target_user:
        audit_filtered = audit_filtered.filter(col("user_identity.email") == target_user)

    audit_result = audit_filtered.select(
        to_timestamp(col("event_time")).alias("START_TIME"),
        col("user_identity.email").alias("SRC_USER"),
        col("request_params.commandText").alias("STATEMENT_TEXT"),
        col("request_params.commandId").alias("STATEMENT_ID"),
        # First-match label for triage, NOT exhaustive — see note on the query-history branch.
        when(upper(col("request_params.commandText")).contains("UNHEX("), lit("UNHEX"))
        .when(col("request_params.commandText").contains("xxd") &
              col("request_params.commandText").contains("-r"), lit("xxd decode"))
        .when(col("request_params.commandText").contains("base64"), lit("base64 decode"))
        .when(col("request_params.commandText").contains("printf"), lit("printf hex"))
        .otherwise(lit("encoded payload")).alias("ENCODING_TECHNIQUE"),
        lit("audit_log").alias("SOURCE")
    )

    return qh_result.union(audit_result).orderBy(col("START_TIME").desc())

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(encoded_command_execution(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))
# COMMAND ----------
