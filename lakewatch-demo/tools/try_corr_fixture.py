"""Pre-live check of the correlation rules: run each one on the warehouse with the signals table replaced
by a VALUES fixture that mimics the ada_ signals of the scenarios (with duplicates, decoys, near misses
and the signals of a previous show).

  uv run --frozen python tools/try_corr_fixture.py --warehouse-id <id> [--profile some-profile]

Expected: ada_identity_pivot_chain -> one row (maria -> sp-etl-prod);
ada_multi_stage_identity -> maria and sp-etl-prod only.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone

from auditdemo import rules
from auditdemo.config import DemoConfig

T = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)
MARIA, TOM = "maria.lopez@corp.example", "tom.becker@corp.example"
SP_ETL, SP_REP, SP_ML = ("6f1c2a9e-3b7d-4c55-9a10-2f8e4d6b7c01", "0b9d8e7f-1a2b-4c3d-8e9f-a0b1c2d3e4f5",
                         "9a8b7c6d-5e4f-4321-8765-43210fedcba9")
IP, IP3, IP2 = "203.0.113.45", "198.51.100.77", "198.51.100.12"

# (schema-qualified rule suffix, actor, kind, ip, stage, time before T)
SIGNALS = [
    ("ada_pat_new_source_ip", MARIA, "user", IP, "1", timedelta(hours=3)),
    ("ada_discovery_api_burst", MARIA, "user", IP, "2", timedelta(hours=2, minutes=59)),
    ("ada_first_secret_enumeration", MARIA, "user", IP, "2", timedelta(hours=2, minutes=55)),
    ("ada_secret_harvest_chain", MARIA, "user", IP, "3", timedelta(hours=2, minutes=52)),
    ("ada_secret_denied_then_read", MARIA, "user", IP, "3", timedelta(hours=2, minutes=51)),
    ("ada_sp_oauth_new_user_agent", SP_ETL, "sp", IP, "1", timedelta(hours=2)),
    ("ada_first_seen_create_function", SP_ETL, "sp", IP, "4", timedelta(hours=1, minutes=55)),
    ("ada_sp_grants_admin", SP_ETL, "sp", IP, "5", timedelta(hours=1, minutes=50)),
    ("ada_token_minted_new_source", SP_ETL, "sp", IP, "5", timedelta(hours=1, minutes=49)),
    ("ada_sensitive_export", SP_ETL, "sp", IP, "6", timedelta(hours=1, minutes=32)),
    ("ada_short_lived_function", SP_ETL, "sp", IP, "6", timedelta(hours=1, minutes=30)),
    ("ada_ip_denied_after_auth", SP_REP, "sp", IP2, "2", timedelta(hours=5)),            # S2
    ("ada_session_reuse_new_ip_ua", TOM, "user", IP3, "1", timedelta(hours=5, minutes=51)),  # S3
    ("ada_sensitive_export", TOM, "user", IP3, "6", timedelta(hours=5, minutes=48)),
    ("ada_compute_fallback", SP_ML, "sp", None, "4", timedelta(hours=4)),               # S4, no IP
    ("ada_compute_fallback", SP_ML, "sp", "", "4", timedelta(hours=3, minutes=50)),
]
# Decoys that must be ignored: a ported adp_ signal and a correlation signal of another identity on the
# attacker IP, and a stage signal of another schema.
DECOYS = [
    ("{c}.{s}.adp_secrets_enumeration", "carl.ng@corp.example", "user", IP, "3", timedelta(hours=2, minutes=40)),
    ("{c}.{s}.ada_multi_stage_identity", "dana.kim@corp.example", "user", IP, "corr", timedelta(hours=2)),
    ("{c}.other_schema.ada_secret_harvest_chain", "eve.ross@corp.example", "user", IP, "3",
     timedelta(hours=2, minutes=30)),
    # shared IP, both stages < 3: no pivot
    ("{c}.{s}.ada_pat_new_source_ip", "fay.lund@corp.example", "user", "198.51.100.200", "1", timedelta(hours=3)),
    ("{c}.{s}.ada_discovery_api_burst", "gus.park@corp.example", "user", "198.51.100.200", "2",
     timedelta(hours=2, minutes=30)),
    # shared IP, one side stage 3, but 4 h 1 min apart: no pivot
    ("{c}.{s}.ada_secret_harvest_chain", "hal.ito@corp.example", "user", "198.51.100.201", "3", timedelta(hours=7)),
    ("{c}.{s}.ada_pat_new_source_ip", "ida.moss@corp.example", "user", "198.51.100.201", "1",
     timedelta(hours=2, minutes=59)),
]
# A previous show (rehearsal) of S1: same identities, a disjoint attacker IP, event times inside the run
# window, but created 3 h before T. Must not make a second pivot or change the multi-stage rows.
OLD_IP = "203.0.113.99"
PREVIOUS = [(f"{{c}}.{{s}}.{r}", a, k, OLD_IP, st, ago + timedelta(hours=1))
            for r, a, k, ip, st, ago in SIGNALS if ip == IP]
CREATED = timedelta(minutes=10)            # a reset's correlation run comes minutes after the stage signals
OLD_CREATED = timedelta(hours=3)


def _lit(v: str | None) -> str:
    return "NULL" if v is None else "'" + v.replace("'", "''") + "'"


def _ts(t: datetime) -> str:
    return f"TIMESTAMP '{t.strftime('%Y-%m-%d %H:%M:%S')}+00:00'"


def fixture(cfg: DemoConfig) -> str:
    rows = [(f"{{c}}.{{s}}.{r}", *rest, CREATED) for r, *rest in SIGNALS] * 2  # *2: repeated runs
    rows += [(*d, CREATED) for d in DECOYS] + [(*p, OLD_CREATED) for p in PREVIOUS]
    values = []
    for rule, actor, kind, ip, stage, ago, created in rows:
        ctx = {"actor": actor, "actor_kind": kind, "stage": stage, **({} if ip is None else {"src_ip": ip})}
        values.append(f"({_lit(rule.format(c=cfg.catalog, s=cfg.schema))}, {_lit(json.dumps(ctx))}, "
                      f"{_ts(T - ago)}, {_ts(T - created)})")
    return "fixture_signals AS (SELECT * FROM VALUES\n  " + ",\n  ".join(values) + \
        "\n  AS t(rule_name, context, event_time, created_at))"


def query(name: str, cfg: DemoConfig, lookback: str) -> str:
    sql = rules.render(rules.rules_dir() / f"{name}.yaml", cfg, "")["batch"]["sql"]["query"]
    table = rules.quote_table(f"{cfg.catalog}.__lakewatch.signals")
    assert table in sql, table
    sql = sql.replace(table, "fixture_signals")
    head, sep, tail = sql.partition("WITH ")
    assert sep and "fixture_signals" not in head
    return rules.rewrite_timerange(f"{head}WITH {fixture(cfg)},\n{tail}", T, lookback)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--profile", default="some-profile")
    p.add_argument("--catalog", default="some_catalog")
    p.add_argument("--schema", default="databricks_audit_demo")
    p.add_argument("--warehouse-id", required=True)
    p.add_argument("--lookback", default="8h")
    a = p.parse_args()
    from auditdemo.lakewatch import SdkApi
    api, cfg = SdkApi(a.profile), DemoConfig(a.catalog, a.schema)
    for name in rules.CORRELATION_RULES:
        rows = api.sql(query(name, cfg, a.lookback), a.warehouse_id)
        print(f"== {name}: {len(rows)} row(s)")
        for row in rows:
            print("  " + " | ".join("" if v is None else str(v) for v in row))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
