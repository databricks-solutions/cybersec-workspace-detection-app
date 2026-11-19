"""auditdemo command line: generate | load | rules | try-rule | check | reset | teardown."""

from __future__ import annotations

import argparse
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .build import default_anchor, generate, write_parquet
from .config import DemoConfig


def _anchor(text: str | None) -> datetime:
    if not text:
        return default_anchor()
    a = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return a.replace(tzinfo=timezone.utc) if a.tzinfo is None else a.astimezone(timezone.utc)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="auditdemo")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, seed=True):
        sp.add_argument("--anchor", help="ISO time of T (default: now, UTC, to the minute)")
        sp.add_argument("--days", type=int, default=14)
        if seed:
            sp.add_argument("--seed", type=int, default=1337)
        sp.add_argument("--scale", type=float, default=1.0)
        sp.add_argument("--background-only", action="store_true", help="skip the scenarios")

    g = sub.add_parser("generate", help="write parquet files")
    common(g)
    g.add_argument("--out", required=True, type=Path)

    # No --seed for load: check and reset always use the default seed, so a loaded table with another
    # seed would make every expected rule look missing.
    ld = sub.add_parser("load", help="generate and load into Unity Catalog (default seed)")
    common(ld, seed=False)
    ld.add_argument("--profile", default="some-profile")
    ld.add_argument("--catalog", default="some_catalog")
    ld.add_argument("--schema", default="databricks_audit_demo")
    ld.add_argument("--warehouse-id", required=True)

    def target(sp):
        sp.add_argument("--profile", default="some-profile")
        sp.add_argument("--catalog", default="some_catalog")
        sp.add_argument("--schema", default="databricks_audit_demo")
        sp.add_argument("--warehouse-id", required=True)
        sp.add_argument("--audit-table", default=None,
                        help="table the rules read (default: <catalog>.<schema>.audit), e.g. system.access.audit")

    r = sub.add_parser("rules", help="apply the detection rules (disabled unless --enable)")
    target(r)
    state = r.add_mutually_exclusive_group()
    state.add_argument("--enable", dest="enabled", action="store_const", const=True, default=None)
    state.add_argument("--disable", dest="enabled", action="store_const", const=False)
    r.add_argument("--lookback", default=None, help="set timerange.extend_lookback, e.g. 30h")
    r.add_argument("--exclude", default="", metavar="NAME[,NAME]",
                   help="rules to leave as they are (not created, not changed), e.g. ada_sp_oauth_new_user_agent")
    r.add_argument("--wait", action="store_true",
                   help="with --enable: wait for the signals that the scenarios expect (demo table only)")

    t = sub.add_parser("try-rule", help="run one rule's SQL on the warehouse for a window ending at --anchor")
    target(t)
    t.add_argument("name")
    t.add_argument("--anchor", required=True, help="ISO time of the end of the window (the load anchor)")
    t.add_argument("--lookback", default="8h", help="window length (default 8h)")

    c = sub.add_parser("check", help="scenario x rule matrix of the signals created since --since")
    target(c)
    c.add_argument("--since", required=True, help="ISO time (the reset start / load anchor)")

    rs = sub.add_parser("reset", help="the reset job flow, run from here (load, rules once, check, disable)")
    target(rs)

    td = sub.add_parser("teardown", help="delete the ada_*/adp_* rules of the schema (then: bundle destroy)")
    target(td)
    return p


def _rules(a) -> int:
    from . import rules
    from .lakewatch import SdkApi

    api = SdkApi(a.profile)
    cfg = DemoConfig(a.catalog, a.schema, a.audit_table)

    def sql(statement):
        return api.sql(statement, a.warehouse_id)

    if a.cmd == "rules":
        if a.wait and (a.enabled is not True or a.audit_table):
            print("--wait needs --enable and the demo table (no --audit-table)")
            return 2
        exclude = [n.strip() for n in a.exclude.split(",") if n.strip()]
        rules.deploy(api, sql, cfg, a.warehouse_id, a.enabled, lookback=a.lookback,
                     expect=None if a.wait else [], exclude=exclude)
        return 0
    if a.cmd == "teardown":
        print(f"deleted {len(rules.teardown(api, cfg))} rule(s)")
        return 0
    rows = rules.try_rule(sql, cfg, a.name, _anchor(a.anchor), a.lookback)
    for row in rows:
        print("\t".join("" if v is None else str(v) for v in row))
    print(f"{len(rows)} row(s)")
    return 0


def _jobs(a) -> int:
    from . import jobs
    cfg = DemoConfig(a.catalog, a.schema, a.audit_table)
    if a.cmd == "reset":
        jobs.install_sigterm_handler()
        jobs.reset(jobs.LiveOps(cfg, a.warehouse_id, a.profile))
        return 0
    try:
        jobs.LiveOps(cfg, a.warehouse_id, a.profile).check(_anchor(a.since))
    except RuntimeError as e:
        print(e)
        return 1
    return 0


def run(argv: list[str] | None = None) -> int:
    a = _parser().parse_args(argv)
    if a.cmd in ("rules", "try-rule", "teardown"):
        return _rules(a)
    if a.cmd in ("check", "reset"):
        return _jobs(a)
    anchor = _anchor(a.anchor)
    print(f"anchor: {anchor.isoformat()}")
    seed = getattr(a, "seed", 1337)   # load has no --seed
    rows = generate(anchor, a.days, seed, a.scale, scenarios=not a.background_only)
    if a.cmd == "generate":
        files = write_parquet(rows, a.out)
        print(f"wrote {len(files)} files to {a.out}")
        return 0
    from .lakewatch import SdkApi
    from .load import load

    cfg = DemoConfig(a.catalog, a.schema)
    with tempfile.TemporaryDirectory() as tmp:
        t0 = time.time()
        files = write_parquet(rows, Path(tmp))
        t1 = time.time()
        print(f"generated {len(files)} files in {t1 - t0:.0f}s")
        api = SdkApi(a.profile)
        load(api, cfg, files, a.warehouse_id)
        print(f"loaded {cfg.table} in {time.time() - t1:.0f}s")
    print(f"anchor: {anchor.isoformat()}  (use with try-rule --anchor)")
    return 0
