"""Detection rules: render the rule YAML files, try them on the warehouse, apply them with the rules API.

Adapted from identity-graph-demo/src/igdemo/rules.py. The rules are plain data (`rules/*.yaml`, flat
v2 rule YAML with {{catalog}}, {{schema}}, {{warehouse_id}} and {{audit_table}}). All rule REST calls of
the demo stay in this module.

Rule kinds come from the file names: `adp_*` are ported pack rules, `ada_*` are stage rules, except
the `ada_*` files whose `output.context.stage` is `corr`: they are correlation rules over the signals
view. `deploy` applies stage and ported rules first. When it enables them, it can wait for the signals that the
scenarios expect from them before it applies the correlation rules (a create or PATCH starts one run at once, and that
run must see the signals). The reset waits; the `auditdemo rules` command does not wait unless --wait.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

from .config import DemoConfig

BASE = "/api/2.0/lakewatch"
# The keys of a rule that a PATCH may not change.
IDENTITY = ("catalog_name", "schema_name", "rule_name")


def rules_dir() -> Path:
    """The rule files: inside the wheel, else in the repository."""
    packaged = Path(__file__).resolve().parent / "_data" / "rules"
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[2] / "rules"


def _stage(path: Path) -> str:
    return str((yaml.safe_load(path.read_text()).get("output") or {}).get("context", {}).get("stage", ""))


def _kinds() -> tuple[list[str], list[str], list[str]]:
    stage, ported, corr = [], [], []
    for path in sorted(rules_dir().glob("*.yaml")):
        if path.stem.startswith("adp_"):
            ported.append(path.stem)
        elif _stage(path) == "corr":
            corr.append(path.stem)
        else:
            stage.append(path.stem)
    return stage, ported, corr


STAGE_RULES, PORTED_RULES, CORRELATION_RULES = _kinds()


def quote_table(name: str) -> str:
    """`a.b.c` -> `` `a`.`b`.`c` `` (each part back-quoted once)."""
    return ".".join(f"`{p.strip('`')}`" for p in name.split("."))


def render(path: Path, cfg: DemoConfig, warehouse_id: str) -> dict:
    """The rule of a YAML file with its placeholders filled.

    {{audit_table}} is cfg.table (the demo table, or the audit_table override such as
    system.access.audit), back-quoted."""
    values = {"catalog": cfg.catalog, "schema": cfg.schema, "warehouse_id": warehouse_id,
              "audit_table": quote_table(cfg.table)}
    text = re.sub(r"\{\{\s*(\w+)\s*\}\}", lambda m: values[m.group(1)], Path(path).read_text())
    return yaml.safe_load(text)


def set_enabled(rule: dict, enabled: bool) -> dict:
    return {**rule, "schedule": {**rule["schedule"], "enabled": enabled}}


def set_lookback(rule: dict, lookback: str) -> dict:
    return {**rule, "timerange": {**(rule.get("timerange") or {}), "extend_lookback": lookback}}


# ---- try a rule on the warehouse (IN_TIMERANGE / TIMERANGE_NOW are not real outside Lakewatch)

def parse_duration(text: str) -> timedelta:
    """A compact duration: 8h, 30m, 1h30m, 2d, 45s."""
    parts = re.findall(r"(\d+)([dhms])", text)
    if not parts or "".join(n + u for n, u in parts) != text.strip():
        raise ValueError(f"bad duration {text!r} (use e.g. 8h, 30m, 1h30m, 2d)")
    unit = {"d": "days", "h": "hours", "m": "minutes", "s": "seconds"}
    return sum((timedelta(**{unit[u]: int(n)}) for n, u in parts), timedelta())


def _ts(t: datetime) -> str:
    return f"TIMESTAMP '{t.astimezone(UTC).strftime('%Y-%m-%d %H:%M:%S')}+00:00'"


def rewrite_timerange(sql: str, anchor: datetime, lookback: str) -> str:
    """Replace IN_TIMERANGE(x) with `(x > anchor - lookback AND x <= anchor)` and TIMERANGE_NOW()
    with the anchor, as the rule runtime does for one run that ends at the anchor."""
    hi, lo = _ts(anchor), _ts(anchor - parse_duration(lookback))
    out, i = [], 0
    pat = re.compile(r"\bIN_TIMERANGE\s*\(", re.I)
    while (m := pat.search(sql, i)) is not None:
        depth, j = 1, m.end()
        while depth:
            if j >= len(sql):
                raise ValueError("unbalanced IN_TIMERANGE(")
            depth += {"(": 1, ")": -1}.get(sql[j], 0)
            j += 1
        expr = sql[m.end():j - 1].strip()
        out += [sql[i:m.start()], f"({expr} > {lo} AND {expr} <= {hi})"]
        i = j
    out.append(sql[i:])
    return re.sub(r"\bTIMERANGE_NOW\s*\(\s*\)", hi, "".join(out), flags=re.I)


def try_rule(sql, cfg: DemoConfig, name: str, anchor: datetime, lookback: str = "8h") -> list[list]:
    """Run the SQL of rule `name` on the warehouse for one run window that ends at `anchor`.

    `sql` runs one statement and returns the rows (lists of strings)."""
    rule = render(rules_dir() / f"{name}.yaml", cfg, "")
    return sql(rewrite_timerange(rule["batch"]["sql"]["query"], anchor, lookback))


# ---- REST

def _find(api, rule: dict) -> dict | None:
    token = None
    while True:
        query = {"catalog_name": rule["catalog_name"], "page_size": 100, **({"page_token": token} if token else {})}
        page = api.do("GET", f"{BASE}/rules", query=query) or {}
        for found in page.get("rules", []):
            if (found.get("schema_name"), found.get("rule_name")) == (rule["schema_name"], rule["rule_name"]):
                return found
        token = page.get("next_page_token")
        if not token:
            return None


_LOOKUP = object()


def apply(api, rule: dict, warehouse_id: str, found=_LOOKUP) -> str:
    """Validate the rule (SQL dry run on the warehouse), then create it or PATCH all its fields.

    `found` is the existing rule (or None) when the caller looked it up already."""
    if found is _LOOKUP:
        found = _find(api, rule)
    fields = {k: v for k, v in rule.items() if k not in IDENTITY}
    body = {"rule": rule, "warehouse": warehouse_id}
    if found is not None:
        # An update is validated with its resource name and mask.
        body = {"rule": {**rule, "name": f"rules/{found['rule_id']}"}, "warehouse": warehouse_id,
                "update_mask": ",".join(sorted(fields))}
    api.do("POST", f"{BASE}/rules:validateRule", body=body)
    if found is None:
        api.do("POST", f"{BASE}/rules", body=rule)
        return "created"
    api.do("PATCH", f"{BASE}/rules/{found['rule_id']}", query={"update_mask": ",".join(sorted(fields))},
           body=fields)
    return "updated"


def resolve_open_alerts(api, cfg: DemoConfig, names: list[str] | None = None) -> int:
    """Resolve the OPEN and IN_PROGRESS alerts of the demo rules (default: all). Returns the count.

    Bulk updates take at most 25 alerts."""
    alerts = []
    for rule_name in names if names is not None else STAGE_RULES + PORTED_RULES + CORRELATION_RULES:
        found = _find(api, {"catalog_name": cfg.catalog, "schema_name": cfg.schema, "rule_name": rule_name})
        if found is None:
            continue
        token = None
        while True:
            query = {"catalog_name": cfg.catalog, "parent": f"rules/{found['rule_id']}", "page_size": 1000,
                     **({"page_token": token} if token else {})}
            page = api.do("GET", f"{BASE}/alerts", query=query) or {}
            alerts += [a["name"] for a in page.get("alerts", []) if a.get("alert_state") in ("OPEN", "IN_PROGRESS")]
            token = page.get("next_page_token")
            if not token:
                break
    for i in range(0, len(alerts), 25):
        api.do("POST", f"{BASE}/alerts:bulkUpdate", body={"names": alerts[i:i + 25], "catalog_name": cfg.catalog,
                                                          "alert_state": "RESOLVED", "update_mask": "alert_state"})
    return len(alerts)


def wait_for_signals(sql, cfg: DemoConfig, names: list[str], *, since: datetime | None = None,
                     timeout_s: int = 900, poll_s: int = 20, sleep=time.sleep, now=time.time) -> dict[str, int]:
    """Wait until each rule of `names` has a signal; return the counts.

    `since` (a reset): only the signals created at or after it count; the signals of earlier shows stay
    in the view. Without it, the signals of the last 2 days count."""
    qualified = ", ".join(f"'{cfg.catalog}.{cfg.schema}.{n}'" for n in names)
    when = (f"created_at >= {_ts(since)}" if since is not None
            else "event_time >= current_timestamp() - INTERVAL 2 DAYS")
    statement = (f"SELECT rule_name, count(*) FROM {quote_table(cfg.catalog + '.__lakewatch.signals')} "
                 f"WHERE rule_name IN ({qualified}) AND {when} GROUP BY rule_name")
    start = now()
    while True:
        counts = {row[0].rsplit(".", 1)[-1]: int(row[1]) for row in sql(statement)}
        if all(counts.get(n) for n in names):
            return counts
        if now() - start > timeout_s:
            missing = [n for n in names if not counts.get(n)]
            raise RuntimeError(f"no signals after {timeout_s}s for: {', '.join(missing)}")
        sleep(poll_s)


def deploy(api, sql, cfg: DemoConfig, warehouse_id: str, enabled: bool | None,
           since: datetime | None = None, lookback: str | None = None,
           expect: list[str] | None = None, exclude: list[str] | tuple[str, ...] = (),
           sleep=time.sleep, retry_wait_s: int = 5) -> None:
    """Apply all rules. enabled None keeps the value of the files (disabled).

    Disabling (enabled False) changes only the rules that exist: a rule that was not created yet has
    nothing to disable (and its validation can fail, because the table may not exist yet). It is best
    effort per rule: a failed apply is retried once, the other rules are still disabled, and at the end
    a RuntimeError lists the rules that may still be enabled.

    `exclude` names rules that deploy does not touch (not created, not changed): a rule that exists
    keeps its state.

    `lookback` sets timerange.extend_lookback (a reset scans the planted hours once). When enabling,
    wait for the signals of the `expect` rules (default: the rules that the scenarios expect), created
    at or after `since` (see wait_for_signals): first the stage and ported ones, then, after the
    correlation rules are applied, the correlation ones. Rules that no scenario expects are not waited
    for (they may have no signal at all). `expect=[]` does not wait."""
    everything = STAGE_RULES + PORTED_RULES + CORRELATION_RULES
    unknown = sorted(set(exclude) - set(everything))
    if unknown:
        raise ValueError(f"unknown rule(s) in exclude: {', '.join(unknown)}")
    for name in exclude:
        print(f"rule {name}: excluded, not changed")
    if expect is None:
        from .scenarios import ALL
        expect = sorted({r for s in ALL for r in s.expected_rules})

    def keep(names):
        return [n for n in names if n not in exclude]

    def one(name, disable_only=False):
        rule = render(rules_dir() / f"{name}.yaml", cfg, warehouse_id)
        if enabled is not None:
            rule = set_enabled(rule, enabled)
        if lookback is not None:
            rule = set_lookback(rule, lookback)
        found = _find(api, rule)
        if disable_only and found is None:
            print(f"rule {name}: not created yet, nothing to disable")
            return
        print(f"rule {name}: {apply(api, rule, warehouse_id, found)} "
              f"({'enabled' if rule['schedule']['enabled'] else 'disabled'})")

    def wait(names, what):
        names = [n for n in names if n in expect]
        if not (enabled and names):
            return
        print(f"waiting for the signals of {len(names)} {what} rule(s)")
        for name, n in sorted(wait_for_signals(sql, cfg, names, since=since).items()):
            print(f"  {name}: {n} signal(s)")

    if enabled is False:
        failed = []
        for name in keep(everything):
            for attempt in (1, 2):
                try:
                    one(name, disable_only=True)
                    break
                except Exception as e:   # noqa: BLE001 - disable the other rules first, report at the end
                    print(f"rule {name}: disable attempt {attempt} failed: {e}")
                    if attempt == 1:
                        sleep(retry_wait_s)
                    else:
                        failed.append(name)
        if failed:
            raise RuntimeError(f"could not disable {len(failed)} rule(s), they may still be enabled: "
                               f"{', '.join(failed)}")
        return

    first = keep(STAGE_RULES + PORTED_RULES)
    for name in first:
        one(name)
    wait(first, "stage and ported")
    corr = keep(CORRELATION_RULES)
    for name in corr:
        one(name)
    wait(corr, "correlation")


DEMO_PREFIXES = ("ada_", "adp_")


def teardown(api, cfg: DemoConfig) -> list[str]:
    """Delete the demo rules (`ada_*`, `adp_*`) of this schema; other rules stay. Returns the names."""
    found, token = [], None
    while True:
        query = {"catalog_name": cfg.catalog, "page_size": 100, **({"page_token": token} if token else {})}
        page = api.do("GET", f"{BASE}/rules", query=query) or {}
        found += [r for r in page.get("rules", [])
                  if r.get("catalog_name") == cfg.catalog and r.get("schema_name") == cfg.schema and str(r.get("rule_name", "")).startswith(DEMO_PREFIXES)]
        token = page.get("next_page_token")
        if not token:
            break
    for r in found:
        api.do("DELETE", f"{BASE}/rules/{r['rule_id']}")
        print(f"rule {r['rule_name']}: deleted")
    return [r["rule_name"] for r in found]
