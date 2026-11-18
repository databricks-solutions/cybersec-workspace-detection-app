"""Build dashboard/databricks_audit.lvdash.json (the AI/BI dashboard of the Databricks audit demo).

    uv run --frozen python dashboard/build_dashboard.py            # write the JSON
    uv run --frozen python dashboard/build_dashboard.py --check    # fail when the committed JSON is old
    uv run --frozen python dashboard/build_dashboard.py --verify   # also run each dataset on the warehouse

Dataset queries use bare table names (audit, principals, demo_signals); the bundle sets
dataset_catalog/dataset_schema. Time windows are relative to the data, never to the wall clock: the audit
window ends at max(event_time) of the audit table (the reset anchor). The signals are those created after
that anchor (the last reset), deduplicated on (rule, actor, event_time), because every rule run writes
its signals again. So page 1 shows the signals created after the last load (anchor = max(event_time)).

The hunt 6b dataset is read from hunts/h6_staged_intrusion.sql at build time (IDENTIFIER(...) table
references become bare names), so the dashboard and the hunt notebook cannot drift apart. Page 2 filters are
dataset parameters (:actor, :ip; 'All' = no filter), so the filter runs before the row cap of the actions.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DEMO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEMO / "src"))

from auditdemo.scenarios import ALL  # noqa: E402
from auditdemo.world import World  # noqa: E402

OUT = Path(__file__).with_name("databricks_audit.lvdash.json")
DEFAULT_ACTOR = "Maria Lopez"
SEED = 1337  # the default seed of the reset; only the display names are used, and they do not depend on it

STAGES = ["1 Access", "2 Discovery", "3 Secret harvest", "4 Execution", "5 Persistence",
          "6 Collection and clean-up", "Correlation"]
STAGE_COLORS = ["#0072B2", "#56B4E9", "#E69F00", "#CC79A7", "#D55E00", "#009E73", "#5B3A8C"]
ADA = "Stage rules (ada_)"
ADP = "Single-event rules (adp_)"
FAMILY_COLORS = {ADA: "#D55E00", ADP: "#8A939B"}
BACKGROUND = "Background (all other identities)"


def scenario_groups() -> list[tuple[str, str]]:
    """(label, display name) per scenario identity, in scenario order: 'S1 attack: Maria Lopez', ..."""
    world = World(SEED)
    out = []
    for s in ALL:
        kind = "attack" if s.key.startswith("S") else "decoy"
        names = sorted(world.get(a).display_name for a in s.actors(world))
        out += [(f"{s.key} {kind}: {n}", n) for n in names]
    return out


GROUPS = scenario_groups()
GROUP_ORDER = [g for g, _ in GROUPS] + [BACKGROUND]

_STAGE_CASE = "CASE stage " + " ".join(
    f"WHEN '{k}' THEN '{v}'" for k, v in zip(["1", "2", "3", "4", "5", "6", "corr"], STAGES)) + " ELSE 'Other' END"

# The signals of the last reset, one row per signal.
_SIG = f"""
anchor AS (SELECT max(event_time) AS t FROM audit),
sig AS (
  SELECT rule, actor, event_time,
         first(stage) AS stage, first(actor_kind) AS actor_kind, first(nullif(src_ip, '')) AS src_ip,
         coalesce(first(actor_name), actor) AS actor_name, first(summary) AS summary
  FROM demo_signals CROSS JOIN anchor
  WHERE created_at >= anchor.t AND event_time >= anchor.t - INTERVAL 1 DAY
  GROUP BY rule, actor, event_time
),
sig_named AS (
  SELECT *, {_STAGE_CASE} AS stage_label,
         CASE WHEN startswith(rule, 'ada_') THEN '{ADA}' ELSE '{ADP}' END AS family
  FROM sig
)"""

_GROUP_VALUES = ",\n    ".join(f"({i}, '{g}', '{n}')" for i, (g, n) in enumerate(GROUPS, 1))

HUNT6 = DEMO / "hunts" / "h6_staged_intrusion.sql"
_IDENTIFIER = re.compile(r"IDENTIFIER\('`' \|\| :catalog \|\| '`\.`' \|\| :schema \|\| '`\.`(\w+)`'\)")
ALL_VALUES = "All"  # the 'no filter' value of the page 2 parameters
ACTIONS_CAP = 20000


def hunt_6b() -> str:
    """The 6b query of the hunt notebook, with bare table names instead of IDENTIFIER(:catalog...)."""
    cells = HUNT6.read_text().split("-- COMMAND ----------")
    cell = next(c for c in cells if c.lstrip().startswith("-- 6b."))
    sql = _IDENTIFIER.sub(r"\1", cell[cell.index("WITH ev AS"):].strip())
    if ":catalog" in sql or ":schema" in sql or "IDENTIFIER" in sql:
        raise RuntimeError("hunt 6b: unexpected table reference left after the rewrite")
    return sql


# Page 2 parameters: an identity (display name) and a source IP; 'All' turns a filter off.
_PARAM_FILTER = "(:actor = 'All' OR {actor} = :actor) AND (:ip = 'All' OR {ip} = :ip)"

_H6B = f"""
SELECT chain, src_ip, reader_name, first_read_at, last_read_at, array_join(secrets_read, ', ') AS secrets_read,
       denied_reads, sp_name, sp_auth_at, sp_user_agent, first_priv_at, last_priv_at,
       array_join(sp_actions, ', ') AS sp_actions
FROM (
{hunt_6b()}
) AS h6b
WHERE (:actor = 'All' OR :actor IN (reader_name, sp_name)) AND (:ip = 'All' OR src_ip = :ip)
ORDER BY first_read_at
"""

_ACTIONS_BASE = """
base AS (
  SELECT a.event_time, a.user_identity.email AS actor,
         coalesce(p.display_name, a.user_identity.email) AS actor_name, a.source_ip_address AS src_ip,
         a.service_name, a.action_name, a.response.status_code AS status, a.user_agent, a.request_params
  FROM audit a LEFT JOIN principals p ON p.email = a.user_identity.email
  WHERE a.event_time >= (SELECT max(event_time) FROM audit) - INTERVAL 24 HOURS
)"""

DATASETS = {
    # One row per signal of the last reset (page 1 counters and stage chart).
    "ds_signals": f"""
WITH {_SIG.strip()}
SELECT event_time, rule, family, stage_label AS stage, actor, actor_name, actor_kind,
       coalesce(src_ip, '') AS src_ip, summary,
       CASE WHEN family = '{ADA}' THEN 1 ELSE 0 END AS is_ada,
       CASE WHEN family = '{ADP}' THEN 1 ELSE 0 END AS is_adp,
       CASE WHEN family = '{ADA}' THEN actor END AS ada_actor
FROM sig_named
ORDER BY event_time
""",
    # The incident timeline: stage-rule signals, one lane per identity, plus one lane per IP that
    # stage-rule signals of two or more identities share (the pivot).
    "ds_timeline": f"""
WITH {_SIG.strip()},
ada AS (SELECT * FROM sig_named WHERE family = '{ADA}'),
shared_ips AS (SELECT src_ip FROM ada WHERE src_ip IS NOT NULL GROUP BY src_ip HAVING count(DISTINCT actor) > 1),
lanes AS (
  SELECT a.actor_name AS lane, 'identity' AS lane_kind, a.event_time, a.stage_label, a.rule, a.src_ip,
         a.actor_name, a.summary, s.src_ip IS NOT NULL AS on_shared_ip
  FROM ada a LEFT JOIN shared_ips s ON s.src_ip = a.src_ip
  UNION ALL
  SELECT concat('IP ', a.src_ip), 'shared IP', a.event_time, a.stage_label, a.rule, a.src_ip, a.actor_name,
         a.summary, true
  FROM ada a JOIN shared_ips s ON s.src_ip = a.src_ip
),
-- Lane order: the identities that share an IP first, then that IP, then the rest by their first signal.
ordered AS (
  SELECT *, min(event_time) OVER (PARTITION BY lane) AS lane_start,
         CASE WHEN lane_kind = 'shared IP' THEN 1
              WHEN max(on_shared_ip) OVER (PARTITION BY lane) THEN 0
              ELSE 2 END AS lane_group
  FROM lanes
)
SELECT lane, lane_kind, event_time, stage_label AS stage, rule, src_ip, actor_name, summary,
       dense_rank() OVER (ORDER BY lane_group, lane_start, lane) AS lane_order
FROM ordered
ORDER BY event_time
""",
    # Decoy contrast: how many distinct adp_ and ada_ rules fired per scenario identity and for the rest.
    "ds_contrast": f"""
WITH {_SIG.strip()},
grps AS (
  SELECT * FROM VALUES
    {_GROUP_VALUES},
    ({len(GROUPS) + 1}, '{BACKGROUND}', CAST(NULL AS STRING))
  AS g(ord, grp, display_name)
),
members AS (SELECT g.ord, p.email FROM grps g JOIN principals p ON p.display_name = g.display_name),
fired AS (SELECT DISTINCT s.rule, trim(a) AS actor FROM sig_named s LATERAL VIEW explode(split(s.actor, ',')) x AS a),
hits AS (
  SELECT DISTINCT coalesce(m.ord, {len(GROUPS) + 1}) AS ord, f.rule
  FROM fired f LEFT JOIN members m ON m.email = f.actor
),
fam AS (SELECT * FROM VALUES ('{ADA}', 'ada_'), ('{ADP}', 'adp_') AS f(family, prefix))
SELECT g.ord, g.grp, f.family, count(h.rule) AS rules
FROM grps g CROSS JOIN fam f LEFT JOIN hits h ON h.ord = g.ord AND startswith(h.rule, f.prefix)
GROUP BY g.ord, g.grp, f.family
ORDER BY g.ord, f.family
""",
    # Page 2: the actions of the last 24 hours of the selected identity and IP (newest first, capped).
    "ds_actions": f"""
WITH {_ACTIONS_BASE.strip()}
SELECT event_time, actor, actor_name, src_ip, service_name, action_name, status, user_agent,
       to_json(request_params) AS request_params,
       timestamp_seconds(floor(unix_timestamp(event_time) / 600) * 600) AS ten_minutes
FROM base
WHERE {_PARAM_FILTER.format(actor="actor_name", ip="src_ip")}
ORDER BY event_time DESC
LIMIT {ACTIONS_CAP}
""",
    # Page 2: the choices of the two parameters.
    "ds_identities": f"""
WITH {_ACTIONS_BASE.strip()}
SELECT identity FROM (
  SELECT '{ALL_VALUES}' AS identity, 0 AS o
  UNION ALL
  SELECT DISTINCT actor_name, 1 FROM base WHERE actor_name IS NOT NULL
)
ORDER BY o, identity
""",
    "ds_ips": f"""
WITH {_ACTIONS_BASE.strip()}
SELECT ip FROM (
  SELECT '{ALL_VALUES}' AS ip, 0 AS o
  UNION ALL
  SELECT DISTINCT src_ip, 1 FROM base WHERE src_ip IS NOT NULL
)
ORDER BY o, ip
""",
    # Page 2: the signals of the last reset of the selected identity and IP.
    "ds_actor_signals": f"""
WITH {_SIG.strip()}
SELECT event_time, rule, stage_label AS stage, actor_name, coalesce(src_ip, '') AS src_ip, summary
FROM sig_named
WHERE {_PARAM_FILTER.format(actor="actor_name", ip="src_ip")}
ORDER BY event_time
""",
    # Page 2: hunt 6b, read from hunts/h6_staged_intrusion.sql.
    "ds_h6b_chain": _H6B,
}

THEME = {
    "canvasBackgroundColor": {"light": "#FCFCFC", "dark": "#1F272D"},
    "widgetBackgroundColor": {"light": "#FFFFFF", "dark": "#11171C"},
    "widgetBorderColor": {"light": "#FFFFFF", "dark": "#11171C"},
    "fontColor": {"light": "#11171C", "dark": "#E8ECF0"},
    "selectionColor": {"light": "#2272B4", "dark": "#8ACAFF"},
    "visualizationColors": ["#0072B2", "#E69F00", "#009E73", "#CC79A7", "#56B4E9", "#D55E00", "#5B3A8C"],
    "widgetHeaderAlignment": "LEFT",
}


def _lines(sql: str) -> list[str]:
    return [line + "\n" for line in sql.strip().splitlines()]


def _fields(names):
    return [{"name": n, "expression": f"`{n}`"} for n in names]


def _pos(x, y, w, h):
    return {"x": x, "y": y, "width": w, "height": h}


def _frame(title, desc=None):
    frame = {"showTitle": True, "title": title}
    if desc:
        frame.update(showDescription=True, description=desc)
    return frame


def text(name, lines, x, y, w, h):
    return {"widget": {"name": name, "multilineTextboxSpec": {"lines": lines}}, "position": _pos(x, y, w, h)}


def counter(name, title, field, expr, x, y, w, h, desc=None):
    return {"widget": {"name": name,
                       "queries": [{"name": "main_query", "query": {"datasetName": "ds_signals",
                                                                    "fields": [{"name": field, "expression": expr}],
                                                                    "disaggregated": False}}],
                       "spec": {"version": 2, "widgetType": "counter",
                                "encodings": {"value": {"fieldName": field, "displayName": title}},
                                "frame": _frame(title, desc)}},
            "position": _pos(x, y, w, h)}


def table(name, title, dataset, cols, x, y, w, h, desc=None):
    return {"widget": {"name": name,
                       "queries": [{"name": "main_query", "query": {"datasetName": dataset,
                                                                    "fields": _fields(c for c, _ in cols),
                                                                    "disaggregated": True}}],
                       "spec": {"version": 2, "widgetType": "table",
                                "encodings": {"columns": [{"fieldName": c, "displayName": d} for c, d in cols]},
                                "frame": _frame(title, desc)}},
            "position": _pos(x, y, w, h)}


def _family_color():
    return {"fieldName": "family", "displayName": "Rule type",
            "scale": {"type": "categorical",
                      "mappings": [{"value": k, "color": v} for k, v in FAMILY_COLORS.items()]}}


def stage_bar(x, y, w, h):
    return {"widget": {"name": "signals_per_stage",
                       "queries": [{"name": "main_query", "query": {
                           "datasetName": "ds_signals", "disaggregated": False,
                           "fields": [{"name": "stage", "expression": "`stage`"},
                                      {"name": "family", "expression": "`family`"},
                                      {"name": "count(*)", "expression": "COUNT(`*`)"}]}}],
                       "spec": {"version": 3, "widgetType": "bar",
                                "encodings": {
                                    "x": {"fieldName": "stage", "displayName": "Stage",
                                          "scale": {"type": "categorical",
                                                    "sort": {"by": "custom-order", "orderedValues": STAGES}}},
                                    "y": {"fieldName": "count(*)", "displayName": "Signals",
                                          "scale": {"type": "quantitative"}},
                                    "color": _family_color()},
                                "frame": _frame("Signals per stage",
                                                "Stage rules find one step of the attack; correlation rules "
                                                "join several steps")}},
            "position": _pos(x, y, w, h)}


def contrast_bar(x, y, w, h):
    return {"widget": {"name": "decoy_contrast",
                       "queries": [{"name": "main_query", "query": {
                           "datasetName": "ds_contrast", "disaggregated": False,
                           "fields": [{"name": "grp", "expression": "`grp`"},
                                      {"name": "family", "expression": "`family`"},
                                      {"name": "sum(rules)", "expression": "SUM(`rules`)"}]}}],
                       "spec": {"version": 3, "widgetType": "bar",
                                "encodings": {
                                    "x": {"fieldName": "sum(rules)", "displayName": "Rules that fired",
                                          "scale": {"type": "quantitative"}},
                                    "y": {"fieldName": "grp", "displayName": "Identity",
                                          "scale": {"type": "categorical",
                                                    "sort": {"by": "custom-order", "orderedValues": GROUP_ORDER}}},
                                    "color": _family_color()},
                                "mark": {"layout": "group"},
                                "frame": _frame("Decoys: single-event rules fire, stage rules do not",
                                                "Number of different rules with a signal. Decoys and normal "
                                                "work fire adp_ rules, but only the attacks fire ada_ rules")}},
            "position": _pos(x, y, w, h)}


TIMELINE_FIELDS = ["lane", "lane_kind", "event_time", "stage", "rule", "src_ip", "actor_name", "summary",
                   "lane_order"]
WHEN = "%b %d %H:%M:%S"


def timeline_spec():
    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "width": "container", "height": "container",
        "config": {"autosize": {"type": "fit", "contains": "padding"}},
        "data": {"name": "databricks_query"},
        "mark": {"type": "point", "filled": True, "size": 180, "opacity": 0.9, "stroke": "#11171C",
                 "strokeWidth": 0.5},
        "encoding": {
            "x": {"field": "event_time", "type": "temporal", "title": None, "scale": {"padding": 16},
                  "axis": {"format": "%H:%M", "labelAngle": 0}},
            "y": {"field": "lane", "type": "nominal", "title": None,
                  "sort": {"field": "lane_order", "op": "min"}},
            "color": {"field": "stage", "type": "nominal", "title": "Stage",
                      "scale": {"domain": STAGES, "range": STAGE_COLORS}},
            "shape": {"field": "lane_kind", "type": "nominal", "title": "Lane",
                      "scale": {"domain": ["identity", "shared IP"], "range": ["circle", "diamond"]}},
            "tooltip": [{"field": "rule", "title": "Rule"}, {"field": "stage", "title": "Stage"},
                        {"field": "actor_name", "title": "Identity"}, {"field": "src_ip", "title": "Source IP"},
                        {"field": "event_time", "type": "temporal", "format": WHEN, "title": "Time"},
                        {"field": "summary", "title": "Summary"}],
        },
    }


def timeline(x, y, w, h):
    return {"widget": {"name": "incident_timeline",
                       "queries": [{"name": "main_query", "query": {"datasetName": "ds_timeline",
                                                                    "fields": _fields(TIMELINE_FIELDS),
                                                                    "disaggregated": True}}],
                       "spec": {"version": 1, "widgetType": "custom-vega-viz",
                                "jsonSpec": {"type": "vega-lite", "spec": json.dumps(timeline_spec())},
                                "encodings": {"fields": [{"fieldName": f} for f in TIMELINE_FIELDS]},
                                "data": {"queryName": "main_query"},
                                "frame": _frame("Incident timeline",
                                                "One row per identity; a diamond row is an IP that two or more "
                                                "identities used. Color = attack stage. Times are in your "
                                                "browser's time zone")}},
            "position": _pos(x, y, w, h)}


def actions_bar(x, y, w, h):
    return {"widget": {"name": "actions_over_time",
                       "queries": [{"name": "main_query", "query": {
                           "datasetName": "ds_actions", "disaggregated": False,
                           "fields": [{"name": "ten_minutes", "expression": "`ten_minutes`"},
                                      {"name": "src_ip", "expression": "`src_ip`"},
                                      {"name": "count(*)", "expression": "COUNT(`*`)"}]}}],
                       "spec": {"version": 3, "widgetType": "bar",
                                "encodings": {
                                    "x": {"fieldName": "ten_minutes", "displayName": "Time (10 minutes)",
                                          "scale": {"type": "temporal"}},
                                    "y": {"fieldName": "count(*)", "displayName": "Actions",
                                          "scale": {"type": "quantitative"}},
                                    "color": {"fieldName": "src_ip", "displayName": "Source IP",
                                              "scale": {"type": "categorical"}}},
                                "frame": _frame("Actions per 10 minutes, by source IP",
                                                "A new IP with a burst of actions is the attacker")}},
            "position": _pos(x, y, w, h)}


# Page 2 filters set the dataset parameters (the filter runs inside the SQL, before the cap of the actions).
PARAMS = {"actor": ("ds_identities", "identity", "Identity", DEFAULT_ACTOR),
          "ip": ("ds_ips", "ip", "Source IP", ALL_VALUES)}


def param_datasets(param: str) -> list[str]:
    return [n for n, sql in DATASETS.items() if f":{param}" in sql]


def param_filter(name, param, x, y, w, h):
    values_ds, field, title, default = PARAMS[param]
    queries = [{"name": "q_values", "query": {"datasetName": values_ds, "fields": _fields([field]),
                                              "disaggregated": False}}]
    queries += [{"name": f"q_{ds}", "query": {"datasetName": ds, "parameters": [{"name": param, "keyword": param}],
                                              "disaggregated": False}} for ds in param_datasets(param)]
    fields = [{"fieldName": field, "displayName": title, "queryName": "q_values"}]
    fields += [{"parameterName": param, "queryName": f"q_{ds}"} for ds in param_datasets(param)]
    return {"widget": {"name": name, "queries": queries,
                       "spec": {"version": 2, "widgetType": "filter-single-select", "encodings": {"fields": fields},
                                "selection": {"defaultSelection": {"values": {"dataType": "STRING",
                                                                              "values": [{"value": default}]}}},
                                "frame": _frame(title)}},
            "position": _pos(x, y, w, h)}


def _parameter(param: str) -> dict:
    _, _, title, default = PARAMS[param]
    return {"displayName": title, "keyword": param, "dataType": "STRING",
            "defaultSelection": {"values": {"dataType": "STRING", "values": [{"value": default}]}}}


def build() -> dict:
    overview = [
        text("title", ["## Databricks audit demo: one leaked token, two identities\n", "\n",
                       "An attacker uses a leaked personal access token (PAT) of a data engineer, reads the secret "
                       "of a service principal, and continues as that service principal from the same IP. "
                       "The data is a synthetic copy of `system.access.audit`; the signals are from the last "
                       "reset of the demo."], 0, 0, 12, 2),
        counter("kpi_ada", "Signals from stage rules (ada_)", "sum(is_ada)", "SUM(`is_ada`)", 0, 2, 4, 3,
                "Rules that look for one step of an attack, or for a chain of steps"),
        counter("kpi_adp", "Signals from single-event rules (adp_)", "sum(is_adp)", "SUM(`is_adp`)", 4, 2, 4, 3,
                "Rules from the detection pack. They also fire on normal work"),
        counter("kpi_ids", "Identities with stage-rule signals", "countdistinct(ada_actor)",
                "COUNT(DISTINCT `ada_actor`)", 8, 2, 4, 3),
        timeline(0, 5, 12, 7),
        stage_bar(0, 12, 6, 6),
        contrast_bar(6, 12, 6, 6),
        text("reading", ["**How to read this page.** Start with the top rows of the timeline: the PAT of "
                         "Maria Lopez logs in from a new IP, lists resources and reads secrets. Then sp-etl-prod "
                         "logs in from **the same IP** and creates functions, adds an admin, makes a token and "
                         "exports a notebook. Each step alone looks like normal work; the order and the shared "
                         "IP make it an attack. Open the **Investigate** page to see every action."],
             0, 18, 12, 2),
    ]
    investigate = [
        text("title_2", ["## Investigate an identity or an IP\n", "\n",
                         "Pick an identity or a source IP. The tables show the actions of the last 24 hours of "
                         "the audit table and the signals of the last reset."], 0, 0, 12, 2),
        param_filter("filter_actor", "actor", 0, 2, 4, 2),
        param_filter("filter_ip", "ip", 4, 2, 4, 2),
        text("hint", ["Tip: set Identity to **All** and pick the attacker IP to see **both** identities that "
                      "used it."],
             8, 2, 4, 2),
        table("h6b", "Hunt 6b: secret reads, then a different service principal on the same IP", "ds_h6b_chain",
              [("chain", "Chain"), ("src_ip", "Source IP"), ("first_read_at", "First secret read"),
               ("last_read_at", "Last secret read"), ("secrets_read", "Secrets read"),
               ("denied_reads", "Denied reads"), ("sp_auth_at", "SP login"), ("sp_user_agent", "SP user agent"),
               ("first_priv_at", "First SP action"), ("last_priv_at", "Last SP action"),
               ("sp_actions", "SP actions")],
             0, 4, 12, 4,
             "MATCH_RECOGNIZE over the audit rows of each IP, sorted by time (hunts/h6_staged_intrusion.sql)"),
        actions_bar(0, 8, 12, 5),
        table("actor_signals", "Signals", "ds_actor_signals",
              [("event_time", "Time"), ("rule", "Rule"), ("stage", "Stage"), ("actor_name", "Identity"),
               ("src_ip", "Source IP"), ("summary", "Summary")], 0, 13, 12, 5),
        table("actor_actions", "Actions", "ds_actions",
              [("event_time", "Time"), ("actor_name", "Identity"), ("src_ip", "Source IP"),
               ("service_name", "Service"), ("action_name", "Action"), ("status", "Status"),
               ("user_agent", "User agent"), ("request_params", "Request parameters")], 0, 18, 12, 8,
              f"Newest first, at most {ACTIONS_CAP:,} rows"),
    ]
    datasets = []
    for n, sql in DATASETS.items():
        ds = {"name": n, "displayName": n.removeprefix("ds_"), "queryLines": _lines(sql)}
        params = [_parameter(p) for p in PARAMS if f":{p}" in sql]
        if params:
            ds["parameters"] = params
        datasets.append(ds)
    return {"datasets": datasets,
            "pages": [{"name": "overview", "displayName": "Attack overview", "pageType": "PAGE_TYPE_CANVAS",
                       "layoutVersion": "GRID_V1", "layout": overview},
                      {"name": "investigate", "displayName": "Investigate", "pageType": "PAGE_TYPE_CANVAS",
                       "layoutVersion": "GRID_V1", "layout": investigate}],
            "uiSettings": {"theme": THEME}}


def render() -> str:
    return json.dumps(build(), indent=1) + "\n"


def verify(profile: str, warehouse: str, catalog: str, schema: str) -> int:
    """Run every dataset on the warehouse (parameters at their defaults); fail on an error or no rows."""
    from databricks.sdk import WorkspaceClient
    from databricks.sdk.service.sql import StatementParameterListItem, StatementState
    w = WorkspaceClient(profile=profile)
    bad = 0
    for name, sql in DATASETS.items():
        params = [StatementParameterListItem(name=p, value=d[3]) for p, d in PARAMS.items() if f":{p}" in sql]
        # Count the rows on the warehouse (a dataset can be too large for an inline result).
        r = w.statement_execution.execute_statement(statement=f"SELECT count(*) FROM (\n{sql}\n)",
                                                    warehouse_id=warehouse, catalog=catalog, schema=schema,
                                                    parameters=params, wait_timeout="50s")
        while r.status.state in (StatementState.PENDING, StatementState.RUNNING):
            r = w.statement_execution.get_statement(r.statement_id)
        ok = r.status.state == StatementState.SUCCEEDED
        total = int(r.result.data_array[0][0]) if ok and r.result and r.result.data_array else 0
        print(f"{name}: {r.status.state.value} rows={total}"
              + ("" if ok else f" {r.status.error.message if r.status.error else ''}"))
        bad += 0 if ok and total else 1
    return bad


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail when the committed JSON differs; write nothing")
    ap.add_argument("--verify", action="store_true", help="run each dataset query on the warehouse")
    ap.add_argument("--profile", default="some-profile")
    ap.add_argument("--warehouse-id", default="50868588ed2af545")
    ap.add_argument("--catalog", default="some_catalog")
    ap.add_argument("--schema", default="databricks_audit_demo")
    args = ap.parse_args(argv)
    if args.check:
        current = OUT.read_text() if OUT.exists() else ""
        if current != render():
            print(f"{OUT.name} is out of date: run dashboard/build_dashboard.py")
            return 1
        return 0
    OUT.write_text(render())
    print(f"wrote {OUT}")
    return verify(args.profile, args.warehouse_id, args.catalog, args.schema) if args.verify else 0


if __name__ == "__main__":
    raise SystemExit(main())
