# Databricks notebook source
# MAGIC %run ../../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC ```yaml
# MAGIC dscc:
# MAGIC   author: David Veuve - Databricks
# MAGIC   created: '2026-07-30T12:00:00'
# MAGIC   modified: '2026-07-30T12:00:00'
# MAGIC   uuid: b4b7d1fe-8bfe-4979-85bf-14243ffb96b6
# MAGIC   content_type: detection
# MAGIC   detection:
# MAGIC     name: Bulk Notebook Export
# MAGIC     description: Detects when a principal exports an anomalously high number of
# MAGIC       distinct notebooks in a single day relative to their own historical baseline,
# MAGIC       which may indicate bulk source-code exfiltration.
# MAGIC     objective: 'Identify potential intellectual property or source-code exfiltration
# MAGIC       through bulk notebook exports. Each principal is measured against their own
# MAGIC       history using a per-user IQR-based fence (Q3 + iqr_multiplier * max(IQR,
# MAGIC       iqr_floor)), so a user who never bulk-exports is flagged at a far lower volume
# MAGIC       than an automated backup account. Self-exports (a principal reading files under
# MAGIC       its own home directory, e.g. Databricks Apps deployment bundles) are excluded as
# MAGIC       platform noise. Maps to MITRE ATT&CK TA0010 - Exfiltration - T1567 -
# MAGIC       Exfiltration Over Web Service.'
# MAGIC     taxonomy:
# MAGIC       - MITRE.TA0010.Exfiltration
# MAGIC       - MITRE.T1567.Exfiltration_Over_Web_Service
# MAGIC     fidelity: high
# MAGIC     category: DETECTION
# MAGIC     false_positives: Automated backup, migration, or platform tooling that legitimately
# MAGIC       exports many notebooks. Tune iqr_multiplier, iqr_floor, and no_baseline_threshold
# MAGIC       for your environment. The per-user baseline and self-export exclusion remove the
# MAGIC       most common sources of noise.
# MAGIC     severity: high
# MAGIC     platform:
# MAGIC     - databricks
# MAGIC dscc-tests:
# MAGIC   tests:
# MAGIC   - function: bulk_notebook_export
# MAGIC     input:
# MAGIC       earliest: '2025-01-01'
# MAGIC       latest: '2025-02-25'
# MAGIC     expect:
# MAGIC       count: '>=0'
# MAGIC       schema: []
# MAGIC       data: null
# MAGIC     mocked_inputs:
# MAGIC     - table: system.access.audit
# MAGIC       path: None
# MAGIC     required_columns:
# MAGIC     - EVENT_DATE
# MAGIC     - USER_EMAIL
# MAGIC     - NOTEBOOKS_EXPORTED
# MAGIC     - THRESHOLD_APPLIED
# MAGIC     - IQRS_FROM_MEDIAN
# MAGIC     - FORMATS_USED
# MAGIC     - ANALYSIS
# MAGIC     - event_time
# MAGIC     - action_name
# MAGIC     - user_identity.email
# MAGIC     - request_params.notebookFullPath
# MAGIC     - request_params.workspaceExportFormat
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC # Bulk Notebook Export
# MAGIC
# MAGIC ### Description
# MAGIC
# MAGIC Bulk export of notebook source is a classic source-code / intellectual-property
# MAGIC exfiltration pattern. A single `workspaceExport` is normal development activity; a
# MAGIC principal exporting hundreds of distinct notebooks in a day — especially notebooks
# MAGIC that are not their own — is not.
# MAGIC
# MAGIC ### Approach
# MAGIC
# MAGIC Rather than a single global threshold (which a loud automated account would dominate),
# MAGIC each principal is scored against **their own** history. For every principal we build a
# MAGIC baseline of daily distinct-notebook export counts and derive a Tukey-style fence:
# MAGIC
# MAGIC ```
# MAGIC fence = Q3 + iqr_multiplier * max(Q3 - Q1, iqr_floor)
# MAGIC ```
# MAGIC
# MAGIC The `iqr_floor` inside the IQR term guarantees a minimum absolute increase over the
# MAGIC user's normal level, so a normally-quiet user is not flagged for a small bump. A day
# MAGIC exceeding the fence is emitted, along with how many IQRs above the baseline median it
# MAGIC sits.
# MAGIC
# MAGIC ### Noise handling
# MAGIC
# MAGIC - **Per-user baseline** — automated backup accounts set their own (high) bar.
# MAGIC - **Trailing days excluded from the baseline** — a live, ongoing bulk export cannot
# MAGIC   inflate its own fence.
# MAGIC - **Self-exports excluded** — a principal reading files under its own home directory
# MAGIC   (`/Workspace/Users/<self>/...`) is platform/tooling behavior (e.g. Databricks Apps
# MAGIC   pulling a deployment bundle), not cross-user exfiltration.
# MAGIC - **No-baseline fallback** — a first-seen principal (no history before the trailing
# MAGIC   window) is scored against a fixed `no_baseline_threshold` so it is never invisible.

# COMMAND ----------

@detect(output=Output.asDataFrame)
def bulk_notebook_export(
    earliest: str = None,
    latest: str = None,
    baseline_exclude_days: int = 2,
    iqr_multiplier: float = 5.0,
    iqr_floor: int = 100,
    no_baseline_threshold: int = 600,
):
    """
    Detect bulk notebook exports that are anomalous relative to each principal's own history.

    Args:
        earliest (str): Earliest event_time to consider (defaults to 2 months ago).
        latest (str): Latest event_time to consider (defaults to now).
        baseline_exclude_days (int): Trailing days excluded from the baseline so a live
            bulk export cannot inflate its own fence.
        iqr_multiplier (float): Multiplier applied to the (floored) IQR when building the fence.
        iqr_floor (int): Minimum value used for the IQR term, guaranteeing a minimum
            absolute increase over the user's normal level.
        no_baseline_threshold (int): Flat threshold applied to principals with no baseline.

    Returns:
        pyspark.sql.DataFrame: One row per anomalous (user, day) bulk export.
    """
    from pyspark.sql.functions import (
        col, current_timestamp, expr, to_date, to_timestamp, countDistinct,
        collect_set, expr as F_expr, coalesce, lit, round as spark_round,
        concat, array_join, contains, date_sub, current_date, greatest,
        percentile_approx, when
    )

    earliest = earliest or current_timestamp() - expr("INTERVAL 2 months")
    latest = latest or current_timestamp()

    df = spark.table("system.access.audit")

    # Notebook export events in range, excluding self-home exports (platform/tooling noise).
    exports = df.filter(
        (col("action_name") == "workspaceExport") &
        (col("event_time").between(earliest, latest)) &
        (~contains(col("request_params.notebookFullPath"), col("user_identity.email")))
    ).select(
        to_date(col("event_time")).alias("event_date"),
        col("user_identity.email").alias("user_email"),
        col("request_params.notebookFullPath").alias("notebook_path"),
        col("request_params.workspaceExportFormat").alias("export_format"),
    )

    # One row per user per day: distinct notebooks exported.
    per_user_day = exports.groupBy("event_date", "user_email").agg(
        countDistinct("notebook_path").alias("notebooks_exported"),
        collect_set("export_format").alias("formats_used"),
    )

    # Per-user baseline (history minus the trailing days): median, IQR, and fence.
    baseline = per_user_day.filter(
        col("event_date") < date_sub(current_date(), baseline_exclude_days)
    )
    per_user_threshold = baseline.groupBy("user_email").agg(
        percentile_approx("notebooks_exported", 0.5).alias("median"),
        (percentile_approx("notebooks_exported", 0.75)
         - percentile_approx("notebooks_exported", 0.25)).alias("iqr"),
        (percentile_approx("notebooks_exported", 0.75)
         + iqr_multiplier * greatest(
             percentile_approx("notebooks_exported", 0.75)
             - percentile_approx("notebooks_exported", 0.25),
             lit(iqr_floor),
         )).alias("user_threshold"),
    )

    # Score every user-day against its own fence (flat fallback when no baseline exists).
    scored = per_user_day.join(per_user_threshold, on="user_email", how="left")
    effective_threshold = coalesce(col("user_threshold"), lit(no_baseline_threshold))

    result = scored.filter(
        col("notebooks_exported") >= effective_threshold
    ).select(
        to_timestamp(col("event_date")).alias("EVENT_DATE"),
        col("user_email").alias("USER_EMAIL"),
        col("notebooks_exported").alias("NOTEBOOKS_EXPORTED"),
        spark_round(effective_threshold, 1).alias("THRESHOLD_APPLIED"),
        spark_round(
            (col("notebooks_exported") - col("median")) / F_expr("nullif(iqr, 0)"), 1
        ).alias("IQRS_FROM_MEDIAN"),
        col("formats_used").alias("FORMATS_USED"),
        concat(
            col("notebooks_exported").cast("string"),
            lit(" notebooks exported (threshold "),
            spark_round(effective_threshold, 1).cast("string"),
            lit(", formats: "),
            array_join(col("formats_used"), "/"),
            lit(")"),
        ).alias("ANALYSIS"),
    ).orderBy(col("EVENT_DATE").desc(), col("NOTEBOOKS_EXPORTED").desc())

    return result

# COMMAND ----------

if __name__ == "__main__" or dbutils.widgets.get("earliest"):
    earliest, latest = get_time_range_from_widgets()
    display(bulk_notebook_export(
        earliest=dbutils.widgets.get("earliest"),
        latest=dbutils.widgets.get("latest")
    ))

# COMMAND ----------
