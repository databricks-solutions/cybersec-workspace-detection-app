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
# MAGIC     - SELF_HOME_NEW_NETWORK
# MAGIC     - SOURCE_IPS
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
# MAGIC - **Per-user baseline** — automated backup accounts set their own (high) bar. The
# MAGIC   baseline is read from its own trailing window, `baseline_days` long, ending
# MAGIC   `baseline_exclude_days` before `earliest`, so the detection works at any scan window
# MAGIC   (including a 24 h scheduled run) and in historical replays.
# MAGIC - **Gap before the scan window** — `baseline_exclude_days` keeps a live, ongoing bulk
# MAGIC   export that started just before `earliest` from inflating its own fence.
# MAGIC - **Self-exports from known networks excluded** — a principal reading files under its
# MAGIC   own home directory (`/Workspace/Users/<self>/...`) is usually platform/tooling behavior
# MAGIC   (e.g. Databricks Apps pulling a deployment bundle). Self-exports still COUNT when they
# MAGIC   come from a network (/24) the principal did not use in the baseline window and the IP
# MAGIC   is not Databricks platform egress, which is how a stolen token emptying its owner's
# MAGIC   home looks.
# MAGIC - **No-baseline fallback** — a first-seen principal (no export history in the baseline
# MAGIC   window) is scored against a fixed `no_baseline_threshold` so it is never invisible.

# COMMAND ----------

@detect(output=Output.asDataFrame)
def bulk_notebook_export(
    earliest: str = None,
    latest: str = None,
    baseline_exclude_days: int = 2,
    iqr_multiplier: float = 5.0,
    iqr_floor: int = 100,
    no_baseline_threshold: int = 50,
    baseline_days: int = 30,
):
    """
    Detect bulk notebook exports that are anomalous relative to each principal's own history.

    Args:
        earliest (str): Start of the scan window (defaults to 2 months ago).
        latest (str): End of the scan window (defaults to now).
        baseline_exclude_days (int): Gap between the end of the baseline window and
            `earliest`, so a live bulk export cannot inflate its own fence.
        iqr_multiplier (float): Multiplier applied to the (floored) IQR when building the fence.
        iqr_floor (int): Minimum value used for the IQR term, guaranteeing a minimum
            absolute increase over the user's normal level.
        no_baseline_threshold (int): Flat threshold applied to principals with no baseline.
        baseline_days (int): Length of the baseline window that ends
            `baseline_exclude_days` before `earliest`.

    Returns:
        pyspark.sql.DataFrame: One row per anomalous (user, day) bulk export.
    """
    from pyspark.sql import Column
    from pyspark.sql.functions import (
        col, current_timestamp, expr, to_date, to_timestamp, countDistinct,
        collect_set, expr as F_expr, coalesce, lit, round as spark_round,
        concat, array_join, contains, greatest, percentile_approx, when,
        regexp_extract, regexp_replace, nullif, slice as spark_slice, array_sort
    )

    earliest = earliest or current_timestamp() - expr("INTERVAL 2 months")
    latest = latest or current_timestamp()
    earliest_ts = earliest if isinstance(earliest, Column) else to_timestamp(lit(earliest))
    baseline_end = earliest_ts - expr(f"INTERVAL {int(baseline_exclude_days)} DAYS")
    baseline_start = baseline_end - expr(f"INTERVAL {int(baseline_days)} DAYS")

    df = spark.table("system.access.audit")
    ip = regexp_replace(col("source_ip_address"), r":\d+$", "")
    # /24 for IPv4, the full address otherwise.
    net = coalesce(nullif(regexp_extract(ip, r"^(\d+\.\d+\.\d+)\.", 1), lit("")), ip)
    self_home = contains(coalesce(col("request_params.notebookFullPath"), lit("")),
                         coalesce(col("user_identity.email"), lit(" ")))
    in_scan = col("event_time").between(earliest, latest)
    in_baseline = (col("event_time") >= baseline_start) & (col("event_time") < baseline_end)
    is_export = col("action_name") == "workspaceExport"

    # Platform egress: IPs Databricks itself authenticates from. An IP counts when it carries a
    # cluster-internal PAT or in-house OAuth token, or the in-house OAuth client action (Apps,
    # serverless) from a private address, or that action from a public address at service
    # volume: one principal at least 200 times in a day. A user's laptop calling a Databricks App
    # logs the same action from its own IP, far less often (at most 60 a day on the reference
    # workspace), so it stays in scope. A user's token relayed by an App or used on a cluster
    # shows up from platform egress; that is not a second location. Looks back 2 days before the
    # window so a short window still sees a full day of service traffic.
    from pyspark.sql import functions as _F
    _ip = ip
    _internal = _F.col("request_params.authenticationMethod").isin("API_INT_PAT_TOKEN", "API_INHOUSE_OAUTH_TOKEN")
    _inhouse = _F.col("action_name").isin("workspaceInHouseOAuthClientAuthentication",
                                           "accountInHouseOAuthClientAuthentication")
    platform_ips = (df
        .filter((_F.col("event_time") >= _F.lit(earliest).cast("timestamp") - _F.expr("INTERVAL 2 DAYS"))
                & (_F.col("event_time") <= latest) & (_internal | _inhouse))
        .groupBy(_ip.alias("_ip"), _F.col("user_identity.email"), _F.to_date("event_time"))
        .agg(_F.sum(_internal.cast("int")).alias("_internal"), _F.sum(_inhouse.cast("int")).alias("_inhouse"))
        .groupBy("_ip")
        .agg(_F.sum("_internal").alias("_internal"), _F.sum("_inhouse").alias("_inhouse"),
             _F.max("_inhouse").alias("_inhouse_day"))
        .filter((_F.col("_internal") > 0)
                | ((_F.col("_inhouse") > 0) & _F.col("_ip").rlike(r"^(10[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[01])[.]|100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.]|127[.])"))
                | (_F.col("_inhouse_day") >= 200))
        .select(_F.col("_ip").alias("platform_ip")))

    scan = df.filter(is_export & in_scan).select(
        to_date(col("event_time")).alias("event_date"),
        col("user_identity.email").alias("user_email"),
        col("request_params.notebookFullPath").alias("notebook_path"),
        col("request_params.workspaceExportFormat").alias("export_format"),
        ip.alias("ip"),
        net.alias("net"),
        self_home.alias("self_home"),
    )

    # Networks each scanned principal used (any action) in the baseline window.
    seen_nets = df.filter(in_baseline).select(
        col("user_identity.email").alias("user_email"), net.alias("net")
    ).join(scan.select("user_email").distinct(), "user_email", "left_semi").distinct() \
     .withColumn("seen_net", lit(True))

    scan = scan.join(seen_nets, ["user_email", "net"], "left") \
               .join(platform_ips, col("ip") == col("platform_ip"), "left") \
               .withColumn("self_home_new_network",
                           col("self_home") & col("seen_net").isNull() & col("platform_ip").isNull())
    exports = scan.filter(~col("self_home") | col("self_home_new_network"))

    # One row per user per day: distinct notebooks exported.
    per_user_day = exports.groupBy("event_date", "user_email").agg(
        countDistinct("notebook_path").alias("notebooks_exported"),
        countDistinct(when(col("self_home_new_network"), col("notebook_path"))).alias("self_home_new_network"),
        collect_set("export_format").alias("formats_used"),
        spark_slice(array_sort(collect_set("ip")), 1, 10).alias("source_ips"),
    )

    # Per-user baseline from its own trailing window (cross-user exports only).
    baseline = df.filter(is_export & in_baseline & ~self_home).groupBy(
        to_date(col("event_time")).alias("event_date"),
        col("user_identity.email").alias("user_email"),
    ).agg(countDistinct(col("request_params.notebookFullPath")).alias("notebooks_exported"))
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
        col("self_home_new_network").alias("SELF_HOME_NEW_NETWORK"),
        col("source_ips").alias("SOURCE_IPS"),
        concat(
            col("notebooks_exported").cast("string"),
            lit(" notebooks exported (threshold "),
            spark_round(effective_threshold, 1).cast("string"),
            lit(", formats: "),
            array_join(col("formats_used"), "/"),
            when(col("self_home_new_network") > 0,
                 concat(lit(", "), col("self_home_new_network").cast("string"),
                        lit(" from own home on a new network"))).otherwise(lit("")),
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
