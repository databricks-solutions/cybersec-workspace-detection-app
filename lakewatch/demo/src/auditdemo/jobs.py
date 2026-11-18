"""Reset job (`auditdemo-reset`; python_wheel_task on serverless, or `auditdemo reset` from a laptop).

A reset gives each run of the demo a clean state with the anchor = now (to the minute):

  disable rules -> resolve the open alerts of the demo rules -> generate and load (anchor = start) ->
  enable the stage and ported rules with extend_lookback 8h -> wait for the expected signals ->
  enable the correlation rules -> wait for their expected signals -> matrix check of the signals
  created since the start -> disable rules (always, also when a step fails: Review Focus 3)

The correlation rules only read signals created in the last 90 minutes, so a reset less than 90
minutes after the previous one can emit the previous run's pivot again. The reset prints a warning
then; it does not stop.

There is no dashboard step: the bundle has no cache refresh API for a dashboard. Refresh the
published dashboard by hand after a reset (README.md).

All SQL runs on the warehouse (no Spark session is needed). All Lakewatch REST calls stay in
auditdemo/rules.py; this module only orders the steps.
"""

from __future__ import annotations

import argparse
import signal
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from .build import generate as _generate
from .build import write_parquet as _write_parquet
from .config import DemoConfig
from .load import load as _load

# The rules' timerange.extend_lookback during a reset: the planted events (T-6h .. T) are inside it.
LOOKBACK = "8h"
# The correlation rules read only the signals created in the last 90 minutes.
CORRELATION_WINDOW_MIN = 90


def anchor_for(now: datetime) -> datetime:
    """The anchor of a reset: now (UTC), to the minute. Each reset gets new event times and new
    attacker IPs, so the new signals are not merged into an earlier show's alerts."""
    return now.astimezone(UTC).replace(second=0, microsecond=0)


def reset(ops, now=lambda: datetime.now(UTC)) -> None:
    start = anchor_for(now())
    try:
        ops.warn_recent_show(start)
    except Exception as e:   # noqa: BLE001 - the warning is advisory, the reset goes on
        print(f"WARNING: could not check the time of the last demo signal ({e}). Make sure that the last "
              f"reset was at least {CORRELATION_WINDOW_MIN} minutes ago.")
    try:
        ops.disable_rules()
        ops.resolve_alerts()
        ops.load(anchor=start)
        ops.enable_rules(since=start, lookback=LOOKBACK)
        ops.check(since=start)
    finally:
        # Enabled rules run every hour and open alerts; disable them also when a step fails.
        ops.disable_rules()


def _ts(t: datetime) -> str:
    return f"TIMESTAMP '{t.astimezone(UTC).strftime('%Y-%m-%d %H:%M:%S')}+00:00'"


class LiveOps:
    """The steps against a workspace: Lakewatch REST, the Files API and the SQL warehouse."""

    def __init__(self, cfg: DemoConfig, warehouse_id: str, profile: str | None = None, *,
                 seed: int = 1337, days: int = 14, scale: float = 1.0):
        from .lakewatch import SdkApi
        self.cfg, self.warehouse_id = cfg, warehouse_id
        self.seed, self.days, self.scale = seed, days, scale
        self.api = SdkApi(profile)   # profile None: default auth (the job's identity)

    def sql(self, statement: str) -> list[list]:
        return self.api.sql(statement, self.warehouse_id)

    @property
    def _signals(self) -> str:
        from .rules import quote_table
        return quote_table(f"{self.cfg.catalog}.__lakewatch.signals")

    @property
    def _mine(self) -> str:
        return f"startswith(rule_name, '{self.cfg.catalog}.{self.cfg.schema}.')"

    def warn_recent_show(self, since: datetime) -> None:
        rows = self.sql(f"SELECT timestampdiff(MINUTE, max(created_at), current_timestamp()) "
                        f"FROM {self._signals} WHERE {self._mine}")
        age = rows[0][0] if rows and rows[0] else None
        if age is not None and int(age) < CORRELATION_WINDOW_MIN:
            print(f"WARNING: the last demo signal was created {int(age)} min ago (< {CORRELATION_WINDOW_MIN} "
                  f"min). The correlation rules can show the previous show's pivot again as an extra alert.")

    def _deploy(self, enabled: bool, since: datetime | None = None, lookback: str | None = None) -> None:
        from . import check, rules
        from .scenarios import ALL
        rules.deploy(self.api, self.sql, self.cfg, self.warehouse_id, enabled, since=since, lookback=lookback,
                     expect=check.expected_rules(ALL))

    def disable_rules(self) -> None:
        self._deploy(False)

    def enable_rules(self, since: datetime, lookback: str) -> None:
        self._deploy(True, since, lookback)

    def resolve_alerts(self) -> None:
        from . import rules
        print(f"resolved {rules.resolve_open_alerts(self.api, self.cfg)} open alert(s) of the demo rules")

    def load(self, anchor: datetime) -> None:
        """Generate the rows, write parquet to a local temporary folder, upload and load it. The load
        always writes the demo table, also when the rules read an audit_table override."""
        target = DemoConfig(self.cfg.catalog, self.cfg.schema)
        print(f"anchor: {anchor.isoformat()}")
        with tempfile.TemporaryDirectory(prefix="auditdemo-") as tmp:
            t0 = time.time()
            files = _write_parquet(_generate(anchor, self.days, self.seed, self.scale), Path(tmp))
            print(f"generated {len(files)} file(s) in {time.time() - t0:.0f}s")
            t1 = time.time()
            _load(self.api, target, files, self.warehouse_id, self.seed)
            print(f"loaded {target.demo_table} in {time.time() - t1:.0f}s")

    def signals_since(self, since: datetime) -> list[tuple[str, str]]:
        """Distinct (rule, actor) of the demo signals created at or after `since`. For correlation
        rules the actor is the `actors` list when the context has one."""
        rows = self.sql(
            f"SELECT DISTINCT rule_name, coalesce(get_json_object(context, '$.actors'), "
            f"get_json_object(context, '$.actor')) FROM {self._signals} "
            f"WHERE {self._mine} AND created_at >= {_ts(since)}")
        return [(r[0].rsplit(".", 1)[-1], r[1] or "") for r in rows]

    def check(self, since: datetime) -> None:
        from . import check
        from .scenarios import ALL
        from .world import World
        world = World(self.seed)
        signals = self.signals_since(since)
        print("signals since the reset (scenario, rule, distinct actors):")
        for key, rule, n in check.table(signals, ALL, world):
            print(f"  {key:10} {rule:40} {n}")
        problems = check.matrix(signals, ALL, world)
        for p in problems:
            print(f"MATRIX PROBLEM: {p}")
        if problems:
            raise RuntimeError(f"matrix check: {len(problems)} problem(s)")
        print("matrix check: no problems")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="auditdemo-reset", description=__doc__.splitlines()[0])
    p.add_argument("--catalog", required=True)
    p.add_argument("--schema", required=True)
    p.add_argument("--warehouse-id", required=True)
    p.add_argument("--audit-table", default="",
                   help="table the rules read (empty: <catalog>.<schema>.audit); the load always writes the demo table")
    p.add_argument("--profile", default=None, help="CLI profile (local runs; the job uses its identity)")
    return p


class Terminated(SystemExit):
    """SIGTERM (job cancel or timeout) as an exception, so that the reset's `finally` disables the rules."""


def _on_sigterm(signum, frame):
    raise Terminated(128 + signum)


def install_sigterm_handler() -> None:
    signal.signal(signal.SIGTERM, _on_sigterm)


def reset_main(argv: list[str] | None = None) -> None:
    a = _parser().parse_args(argv)
    install_sigterm_handler()
    cfg = DemoConfig(a.catalog, a.schema, a.audit_table or None)
    t0 = time.time()
    reset(LiveOps(cfg, a.warehouse_id, a.profile))
    print(f"reset done in {time.time() - t0:.0f}s")
