"""Aggregate-only profile of system.access.audit (read-only, run once).

Usage: uv run --frozen python profile/profile.py --profile some-profile --workspaces 2 --days 7

Picks the N workspaces with the widest action mix, then writes profile/profile.json:
rates, hour-of-day shape, status codes, request_params KEY names and user agent
families. No identities, IPs, ids or parameter values are written. Workspace ids
stay in memory only.
"""
from __future__ import annotations

import argparse
import json
import re
import time
from collections import defaultdict
from pathlib import Path

from databricks.sdk import WorkspaceClient

OUT = Path(__file__).resolve().parent / "profile.json"
UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
# Account-level rows carry workspace_id '0'. Unity Catalog ones name the workspace in
# request_params; these actions do not, so they are read account-wide (low volume).
ACCOUNT_WIDE_ACTIONS = ("addPrincipalToGroup", "generateDbToken", "listStorageCredentials")
SCENARIO_ACTIONS = {
    "tokenLogin", "oidcTokenAuthorization", "IpAccessDenied", "addPrincipalToGroup",
    "generateDbToken", "listScopes", "listSecrets", "getSecret", "listCatalogs",
    "listExternalLocations", "listStorageCredentials", "createFunction", "deleteFunction",
    "listRepos", "workspaceExport", "create", "submitRun", "runNow", "startWarehouse",
    "importNotebook",
}
MIN_EVENTS = 20
MIN_UA_SHARE = 0.0005
SAFE_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{0,59}$")
SENSITIVE = re.compile(r"@|[0-9a-f]{8}-[0-9a-f]{4}|\d{1,3}(\.\d{1,3}){3}", re.I)


class Runner:
    def __init__(self, profile: str, warehouse_id: str | None):
        self.w = WorkspaceClient(profile=profile)
        self.wh = warehouse_id or next(
            x.id for x in self.w.warehouses.list() if x.name == "Lakewatch Warehouse"
        )

    def sql(self, statement: str) -> list[list]:
        r = self.w.statement_execution.execute_statement(
            statement=statement, warehouse_id=self.wh, wait_timeout="50s"
        )
        while r.status.state.value in ("PENDING", "RUNNING"):
            time.sleep(15)
            r = self.w.statement_execution.get_statement(r.statement_id)
        if r.status.state.value != "SUCCEEDED":
            raise RuntimeError(str(r.status.error))
        return (r.result.data_array or []) if r.result else []


def pick_workspaces(run: Runner, n: int) -> list[str]:
    rows = run.sql(
        "SELECT workspace_id FROM system.access.audit WHERE event_date = current_date() - 2 "
        "AND workspace_id <> '0' AND service_name <> 'accounts' "
        "GROUP BY workspace_id ORDER BY count(DISTINCT concat(service_name, '.', action_name)) DESC "
        f"LIMIT {n}"
    )
    return [r[0] for r in rows]


def scope(ws: list[str], days: int) -> str:
    ids = ", ".join(f"'{x}'" for x in ws)
    wide = ", ".join(f"'{x}'" for x in ACCOUNT_WIDE_ACTIONS)
    return (
        f"event_date >= current_date() - {days} AND event_date < current_date() AND ("
        f"workspace_id IN ({ids}) OR (workspace_id = '0' AND "
        f"(request_params['workspace_id'] IN ({ids}) OR action_name IN ({wide}))))"
    )


COMBO = (
    "service_name, action_name, audit_level, "
    f"CASE WHEN user_identity.email RLIKE '{UUID}' THEN 'sp' ELSE 'user' END AS actor_kind, "
    "CASE WHEN response.status_code < 300 THEN '2xx' WHEN response.status_code < 500 THEN '4xx' "
    "WHEN response.status_code < 600 THEN '5xx' ELSE 'app_error' END AS status_class"
)


def collect(run: Runner, ws: list[str], days: int) -> dict:
    where = scope(ws, days)
    key = lambda r: tuple(r[:5])  # noqa: E731
    hourly = defaultdict(lambda: [0] * 24)
    for r in run.sql(
        f"SELECT {COMBO}, hour(event_time) h, count(*) c FROM system.access.audit "
        f"WHERE {where} GROUP BY ALL"
    ):
        hourly[key(r)][int(r[5])] += int(r[6])
    actors, keys = {}, {}
    for r in run.sql(
        f"SELECT {COMBO}, count(DISTINCT user_identity.email) a, "
        "array_join(array_sort(array_distinct(flatten(collect_set(map_keys(request_params))))), ',') k "
        f"FROM system.access.audit WHERE {where} GROUP BY ALL"
    ):
        actors[key(r)] = max(int(r[5]), 1)
        keys[key(r)] = [k for k in (r[6] or "").split(",") if SAFE_KEY.match(k) and not SENSITIVE.search(k)]
    codes = defaultdict(dict)
    for r in run.sql(
        f"SELECT {COMBO}, coalesce(cast(response.status_code AS string), 'null') s, count(*) c "
        f"FROM system.access.audit WHERE {where} GROUP BY ALL"
    ):
        codes[key(r)][r[5]] = int(r[6])
    ua = {}
    for r in run.sql(
        "SELECT CASE WHEN user_agent IS NULL OR user_agent = '' THEN 'none' ELSE "
        "coalesce(nullif(regexp_extract(user_agent, '^([A-Za-z@][A-Za-z\\\\-]*)', 1), ''), 'other') END f, "
        f"count(*) c FROM system.access.audit WHERE {where} GROUP BY ALL"
    ):
        ua[r[0]] = int(r[1])
    return {"hourly": hourly, "actors": actors, "keys": keys, "codes": codes, "ua": ua}


def build(data: dict, days: int, n_ws: int) -> dict:
    actions = []
    for k, hours in sorted(data["hourly"].items()):
        total = sum(hours)
        if total < MIN_EVENTS and k[1] not in SCENARIO_ACTIONS:
            continue
        codes = data["codes"][k]
        actions.append({
            "service_name": k[0], "action_name": k[1], "audit_level": k[2],
            "actor_kind": k[3], "status_class": k[4],
            "hourly": [round(h / total, 5) for h in hours],
            "per_actor_per_day": round(total / data["actors"][k] / days, 4),
            "param_keys": data["keys"][k],
            "status_codes": {c: round(v / total, 5) for c, v in sorted(codes.items())},
        })
    ua_total = sum(data["ua"].values())
    ua, other = {}, 0
    for f, c in sorted(data["ua"].items(), key=lambda x: -x[1]):
        if c / ua_total >= MIN_UA_SHARE and not SENSITIVE.search(f):
            ua[f] = round(c / ua_total, 5)
        else:
            other += c
    if other:
        ua["other"] = round(ua.get("other", 0) + other / ua_total, 5)
    return {"window_days": days, "workspaces": n_ws, "actions": actions, "user_agents": ua}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--profile", default="some-profile")
    p.add_argument("--workspaces", type=int, default=2)
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--warehouse-id")
    a = p.parse_args()
    run = Runner(a.profile, a.warehouse_id)
    ws = pick_workspaces(run, a.workspaces)
    result = build(collect(run, ws, a.days), a.days, len(ws))
    OUT.write_text(json.dumps(result, indent=1, sort_keys=False) + "\n")
    print(f"wrote {OUT}: {len(result['actions'])} action rows, {len(result['user_agents'])} user agent families")


if __name__ == "__main__":
    main()
