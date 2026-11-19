# /// script
# requires-python = ">=3.10"
# dependencies = ["databricks-sdk>=0.40", "pyyaml>=6"]
# ///
"""Run rules on synthetic audit rows and check what they return (true positives and near misses).

    uv run lakewatch/tools/try_fixtures.py --profile <cli-profile> --warehouse-id <id> [--only NAME,...]

Each lakewatch/tests/fixtures/<rule_name>.yaml has:

    rows:            # synthetic system.access.audit rows; t = minutes relative to the run's end (anchor)
      - {t: -30, action_name: tokenLogin, service_name: accounts, email: a@x.com, ip: 198.51.100.7,
         user_agent: curl/8.4.0, status: 200, request_params: {tokenId: tok1, authenticationMethod: API_EXT_PAT_TOKEN}}
      - {t: -600, action_name: workspaceInHouseOAuthClientAuthentication, email: app-sp, ip: 203.0.113.9,
         repeat: 250}                                     # repeat: N emits the row N times (same timestamp)
    expect:
      hits:   [{actor: a@x.com, src_ip: 198.51.100.7}]   # each must match at least one output row
      misses: [{actor: b@x.com}]                         # none may match an output row

A row matches when every key/value given equals the output column of that name (as strings). The rule
runs as one Lakewatch run ending at the anchor: IN_TIMERANGE(x) becomes (x >= anchor - window AND
x < anchor), half-open like the platform, with window = schedule + extend_lookback, and TIMERANGE_NOW() becomes the anchor, the
same rewrite the demo's `auditdemo try-rule` uses. Nothing is written anywhere; the rows exist only
inside the statement.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parents[1]
RULES = HERE / "rules"
FIXTURES = HERE / "tests" / "fixtures"
ANCHOR = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)


def dur(text: str) -> timedelta:
    units = {"d": "days", "h": "hours", "m": "minutes", "s": "seconds"}
    return sum((timedelta(**{units[u]: int(n)}) for n, u in re.findall(r"(\d+)([dhms])", text)), timedelta())


def ts(t: datetime) -> str:
    return f"TIMESTAMP '{t.strftime('%Y-%m-%d %H:%M:%S')}+00:00'"


def rewrite(sql: str, anchor: datetime, window: timedelta) -> str:
    hi, lo = ts(anchor), ts(anchor - window)
    out, i = [], 0
    pat = re.compile(r"\bIN_TIMERANGE\s*\(", re.I)
    while (m := pat.search(sql, i)) is not None:
        depth, j = 1, m.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(sql[j], 0)
            j += 1
        e = sql[m.end():j - 1].strip()
        out += [sql[i:m.start()], f"({e} >= {lo} AND {e} < {hi})"]
        i = j
    out.append(sql[i:])
    return re.sub(r"\bTIMERANGE_NOW\s*\(\s*\)", hi, "".join(out), flags=re.I)


def lit(v) -> str:
    if v is None:
        return "NULL"
    return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"


def row_sql(r: dict, anchor: datetime) -> str:
    t = anchor + timedelta(minutes=float(r.get("t", -10)))
    params = r.get("request_params") or {}
    pm = ("map(" + ", ".join(f"{lit(k)}, {lit(v)}" for k, v in params.items()) + ")") if params else \
        "CAST(map() AS MAP<STRING, STRING>)"
    status = r.get("status", 200)
    return (
        f"SELECT {ts(t)} AS event_time, CAST({ts(t)} AS DATE) AS event_date, "
        f"{lit(r.get('service_name', 'accounts'))} AS service_name, {lit(r['action_name'])} AS action_name, "
        f"named_struct('email', {lit(r.get('email'))}, 'subject_name', CAST(NULL AS STRING)) AS user_identity, "
        f"{lit(r.get('ip'))} AS source_ip_address, {lit(r.get('user_agent'))} AS user_agent, "
        f"named_struct('status_code', CAST({'NULL' if status is None else int(status)} AS INT), "
        f"'error_message', {lit(r.get('error_message'))}, 'result', CAST({lit(r.get('result'))} AS STRING)) AS response, "
        f"CAST({pm} AS MAP<STRING, STRING>) AS request_params, {lit(r.get('session_id'))} AS session_id, "
        f"CAST({lit(r.get('workspace_id', '1000'))} AS BIGINT) AS workspace_id, "
        f"{lit(r.get('audit_level', 'WORKSPACE_LEVEL'))} AS audit_level, "
        f"named_struct('run_by', CAST(NULL AS STRING), 'run_as', CAST(NULL AS STRING), "
        f"'acting_resource', CAST(NULL AS STRING), 'acting_resource_type', CAST(NULL AS STRING)) AS identity_metadata, "
        f"uuid() AS event_id, {lit(r.get('account_id', 'acct'))} AS account_id, "
        f"{lit(r['request_id']) if r.get('request_id') else 'uuid()'} AS request_id"
        + (f" FROM range({int(r['repeat'])})" if r.get("repeat") else "")
    )


def query_row_sql(r: dict, anchor: datetime) -> str:
    t = anchor + timedelta(minutes=float(r.get("t", -10)))
    return (f"SELECT {lit(r.get('executed_by'))} AS executed_by, {lit(r.get('executed_as', r.get('executed_by')))} AS executed_as, "
            f"{lit(r.get('client_application', 'Databricks SQL Editor'))} AS client_application, {ts(t)} AS start_time, "
            f"{lit(r.get('statement_id', 'stmt'))} AS statement_id, {lit(r.get('statement_text'))} AS statement_text, "
            f"CAST({int(r.get('produced_rows', 1))} AS BIGINT) AS produced_rows, "
            f"CAST({int(r.get('read_bytes', 1000))} AS BIGINT) AS read_bytes, "
            f"named_struct('warehouse_id', {lit(r.get('warehouse_id', 'wh1'))}) AS compute")


def serving_row_sql(r: dict, anchor: datetime) -> str:
    t = anchor + timedelta(minutes=float(r.get("t", -10)))
    return (f"SELECT {lit(r.get('requester'))} AS requester, {ts(t)} AS request_time, "
            f"{lit(r.get('served_entity_id', 'e1'))} AS served_entity_id, CAST(200 AS INT) AS status_code")


def lineage_row_sql(r: dict, anchor: datetime) -> str:
    t = anchor + timedelta(minutes=float(r.get("t", -10)))
    return (f"SELECT {lit(r.get('created_by'))} AS created_by, {lit(r.get('source_table_full_name'))} AS source_table_full_name, "
            f"{ts(t)} AS event_time")


def statement(rule: dict, fixture: dict, anchor: datetime) -> str:
    """The rule query over fixture rows. `rows` stand in for the audit table; optional `query_rows`
    (executed_by, client_application, statement_text, ...) stand in for system.query.history."""
    rows = " UNION ALL ".join(row_sql(r, anchor) for r in fixture.get("rows") or [{"action_name": "none", "t": -99999}])
    query = rule["batch"]["sql"]["query"].replace("{{audit_table}}", "fixture_audit")
    ctes = [f"fixture_audit AS ({rows})"]
    for key, fn, table, name in (("serving_rows", serving_row_sql, r"system\.serving\.endpoint_usage", "fixture_endpoint_usage"),
                                 ("lineage_rows", lineage_row_sql, r"system\.access\.table_lineage", "fixture_table_lineage")):
        if fixture.get(key):
            ctes.append(f"{name} AS (" + " UNION ALL ".join(fn(r, anchor) for r in fixture[key]) + ")")
            query = re.sub(r"\b" + table + r"\b", name, query)
    if fixture.get("query_rows"):
        qrows = " UNION ALL ".join(query_row_sql(r, anchor) for r in fixture["query_rows"])
        ctes.append(f"fixture_query_history AS ({qrows})")
        query = re.sub(r"\bsystem\.query\.history\b", "fixture_query_history", query)
    window = dur(rule["schedule"]["at_least_every"]) + dur(rule["timerange"]["extend_lookback"])
    query = rewrite(query, anchor, window).strip().rstrip(";")
    cte = ",\n".join(ctes)
    if re.match(r"WITH\b", query, re.I):
        return "WITH " + cte + ",\n" + query[4:].lstrip()
    return f"WITH {cte}\nSELECT * FROM (\n{query}\n) AS rule_output"


def matches(row: dict, want: dict) -> bool:
    return all(str(row.get(k)) == str(v) for k, v in want.items())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--warehouse-id", required=True)
    ap.add_argument("--only", default="")
    ap.add_argument("--show-sql", action="store_true")
    a = ap.parse_args()
    from databricks.sdk import WorkspaceClient
    from databricks.sdk.service.sql import StatementState

    w = WorkspaceClient(profile=a.profile)
    only = {x.strip() for x in a.only.split(",") if x.strip()}
    paths = sorted(p for p in FIXTURES.glob("*.yaml") if not only or p.stem in only)
    failed = 0
    for path in paths:
        fixture = yaml.safe_load(path.read_text())
        rule = yaml.safe_load((RULES / f"{path.stem}.yaml").read_text())
        sql = statement(rule, fixture, ANCHOR)
        if a.show_sql:
            print(sql)
        res = w.statement_execution.execute_statement(statement=sql, warehouse_id=a.warehouse_id, wait_timeout="50s")
        while res.status.state in (StatementState.PENDING, StatementState.RUNNING):
            res = w.statement_execution.get_statement(res.statement_id)
        if res.status.state != StatementState.SUCCEEDED:
            failed += 1
            print(f"ERROR {path.stem}: {res.status.error.message[:600] if res.status.error else res.status.state}")
            continue
        cols = [c.name for c in res.manifest.schema.columns]
        out = [dict(zip(cols, r)) for r in (res.result.data_array or [])] if res.result else []
        exp = fixture.get("expect") or {}
        missing = [h for h in exp.get("hits", []) if not any(matches(r, h) for r in out)]
        unwanted = [m for m in exp.get("misses", []) if any(matches(r, m) for r in out)]
        ok = not missing and not unwanted
        failed += 0 if ok else 1
        print(f"{'PASS ' if ok else 'FAIL '} {path.stem}: {len(out)} row(s)"
              + (f"; missing {missing}" if missing else "") + (f"; unwanted {unwanted}" if unwanted else ""))
        if not ok:
            for r in out[:5]:
                print("       ", json.dumps({k: r[k] for k in list(r)[:8]}))
    print(f"{len(paths) - failed}/{len(paths)} fixtures pass")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
