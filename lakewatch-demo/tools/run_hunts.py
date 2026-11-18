"""Run the query cells of the hunt notebooks on a SQL warehouse and check the planted entity.

Each query runs with the named parameters :catalog and :schema (the notebook widgets). The last
query of a hunt has a `-- EXPECT: <text>` line: a hunt passes when that query returns rows and one
row contains the text.

    uv run python tools/run_hunts.py --profile P --catalog C [--schema soc_demo] --warehouse-id W [hunt ...]
    uv run python tools/run_hunts.py ... --sql -     # run one ad hoc query from stdin
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

HUNTS = Path(__file__).resolve().parents[1] / "hunts"
SEP = "-- COMMAND ----------"


def queries(path: Path) -> list[str]:
    return [c.strip() for c in path.read_text().split(SEP)
            if c.strip() and "-- MAGIC" not in c and "-- Databricks notebook source" not in c.strip()[:30]]


def run(w, warehouse_id: str, statement: str, params: dict[str, str]) -> list[list]:
    from databricks.sdk.service.sql import StatementParameterListItem, StatementState
    resp = w.statement_execution.execute_statement(
        statement=statement, warehouse_id=warehouse_id, wait_timeout="50s",
        parameters=[StatementParameterListItem(name=k, value=v) for k, v in params.items()])
    while resp.status.state in (StatementState.PENDING, StatementState.RUNNING):
        time.sleep(2)
        resp = w.statement_execution.get_statement(resp.statement_id)
    if resp.status.state != StatementState.SUCCEEDED:
        raise RuntimeError(resp.status.error.message if resp.status.error else str(resp.status.state))
    cols = [c.name for c in resp.manifest.schema.columns]
    return [cols] + ((resp.result.data_array or []) if resp.result else [])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--profile")
    ap.add_argument("--catalog", required=True)
    ap.add_argument("--schema", default="databricks_audit_demo")
    ap.add_argument("--warehouse-id", required=True)
    ap.add_argument("--sql", help="'-': run one query from stdin and print the rows")
    ap.add_argument("--show", type=int, default=0, help="print the first N rows of each query")
    ap.add_argument("hunts", nargs="*", help="hunt file stems (default: all)")
    args = ap.parse_args()
    from databricks.sdk import WorkspaceClient
    w = WorkspaceClient(profile=args.profile)
    params = {"catalog": args.catalog, "schema": args.schema}
    if args.sql == "-":
        for row in run(w, args.warehouse_id, sys.stdin.read(), params)[: 1 + (args.show or 30)]:
            print(" | ".join(str(x) for x in row))
        return 0
    failed = 0
    for path in sorted(HUNTS.glob("*.sql")):
        if args.hunts and path.stem not in args.hunts:
            continue
        cells = queries(path)
        try:
            checks: list[bool] = []
            for i, q in enumerate(cells, 1):
                rows = run(w, args.warehouse_id, q, params)
                print(f"{path.stem} query {i}: {len(rows) - 1} row(s)")
                for row in rows[: 1 + args.show] if args.show else []:
                    print("    " + " | ".join(str(x) for x in row))
                expect = next((line.split("-- EXPECT:", 1)[1].strip() for line in q.splitlines()
                               if "-- EXPECT:" in line), None)
                if expect is not None:
                    hit = len(rows) > 1 and any(expect in " ".join(str(x) for x in r) for r in rows[1:])
                    print(f"{path.stem} query {i}: EXPECT {expect!r} {'ok' if hit else 'MISSING'}")
                    checks.append(hit)
            if not cells or "-- EXPECT:" not in cells[-1]:
                raise RuntimeError("the last query has no -- EXPECT: line")
            ok = all(checks)
        except RuntimeError as exc:
            print(f"{path.stem}: ERROR {exc}")
            ok = False
        print(f"{path.stem}: {'PASS' if ok else 'FAIL'}")
        failed += not ok
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
