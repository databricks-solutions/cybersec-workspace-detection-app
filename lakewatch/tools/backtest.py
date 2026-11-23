# /// script
# requires-python = ">=3.10"
# dependencies = ["databricks-sdk>=0.40", "pyyaml>=6"]
# ///
"""Back-test rules on your real audit table: rows each rule would have returned in its last N runs.

    uv run lakewatch/tools/backtest.py --profile <cli-profile> --warehouse-id <id> [--only NAME,...] \\
        [--windows 7] [--audit-table system.access.audit]

For each rule, run k = 0..N-1 ends at (now rounded to the hour) - k * schedule, and covers schedule +
extend_lookback, the same window a Lakewatch run uses. Read-only: nothing is created or written.
Use it before enabling a rule (SETUP.md step 9) and after changing one.
"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from try_fixtures import RULES, dur, rewrite  # noqa: E402

EMPTY_ALLOWLIST = ("(SELECT CAST(NULL AS STRING) AS rule, CAST(NULL AS STRING) AS principal, "
                   "CAST(NULL AS STRING) AS src_ip, CAST(NULL AS TIMESTAMP) AS expires_at WHERE 1 = 0)")


def quote_table(name: str) -> str:
    return ".".join(f"`{p.strip('`')}`" for p in name.split("."))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--warehouse-id", required=True)
    ap.add_argument("--only", default="")
    ap.add_argument("--windows", type=int, default=7)
    ap.add_argument("--audit-table", default="system.access.audit")
    ap.add_argument("--allowlist-table", default="", help="allow-list table to apply (default: none)")
    ap.add_argument("--runner-principal", default="", help="identity the rules run as (see deploy.py)")
    ap.add_argument("--show", type=int, default=0, help="print up to this many rows of each run that has rows")
    a = ap.parse_args()
    from databricks.sdk import WorkspaceClient
    from databricks.sdk.service.sql import StatementState

    w = WorkspaceClient(profile=a.profile)
    only = {x.strip() for x in a.only.split(",") if x.strip()}
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    errors = 0
    for path in sorted(RULES.glob("*.yaml")):
        if only and path.stem not in only:
            continue
        rule = yaml.safe_load(path.read_text())
        step = dur(rule["schedule"]["at_least_every"])
        window = step + dur(rule["timerange"]["extend_lookback"])
        query = (rule["batch"]["sql"]["query"].replace("{{audit_table}}", quote_table(a.audit_table))
                 .replace("{{allowlist_table}}", quote_table(a.allowlist_table) if a.allowlist_table else EMPTY_ALLOWLIST)
                 .replace("{{runner_principal}}", a.runner_principal.replace("'", "''")))
        counts, err = [], None
        for k in range(a.windows):
            sql = f"SELECT count(*) FROM (\n{rewrite(query, now - step * k, window)}\n) AS r"
            res = w.statement_execution.execute_statement(statement=sql, warehouse_id=a.warehouse_id,
                                                          wait_timeout="50s")
            while res.status.state in (StatementState.PENDING, StatementState.RUNNING):
                res = w.statement_execution.get_statement(res.statement_id)
            if res.status.state != StatementState.SUCCEEDED:
                err = res.status.error.message[:300] if res.status.error else str(res.status.state)
                break
            counts.append(int(res.result.data_array[0][0]))
            if a.show and counts[-1]:
                shown = w.statement_execution.execute_statement(
                    statement=f"SELECT * FROM (\n{rewrite(query, now - step * k, window)}\n) AS r LIMIT {a.show}",
                    warehouse_id=a.warehouse_id, wait_timeout="50s")
                while shown.status.state in (StatementState.PENDING, StatementState.RUNNING):
                    shown = w.statement_execution.get_statement(shown.statement_id)
                if shown.status.state == StatementState.SUCCEEDED and shown.result:
                    cols = [c.name for c in shown.manifest.schema.columns]
                    for r in shown.result.data_array or []:
                        print(f"  run -{k}: " + ", ".join(f"{c}={v}" for c, v in zip(cols, r) if v not in (None, ""))[:400])
        errors += 1 if err else 0
        label = f"every {rule['schedule']['at_least_every']}"
        print(f"{path.stem:55} {label:9} " + (f"ERROR {err}" if err else
              f"rows per run (newest first) {counts}  total {sum(counts)}"))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
