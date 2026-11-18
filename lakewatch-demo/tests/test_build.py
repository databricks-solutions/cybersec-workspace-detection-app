from datetime import datetime, timezone

import pyarrow.parquet as pq

from auditdemo.build import generate, write_parquet
from auditdemo.schema import arrow_schema

ANCHOR = datetime(2026, 11, 12, 9, 30, tzinfo=timezone.utc)


def _rows(**kw):
    return list(generate(ANCHOR, days=2, scale=0.02, **kw))


def test_generate_sorted_and_has_scenarios():
    rows = _rows()
    times = [r["event_time"] for r in rows]
    assert times == sorted(times)
    assert any(r["request_params"].get("targetUserName") == "svc-backup@corp.example" for r in rows)


def test_background_only_is_smaller():
    assert len(_rows(scenarios=False)) < len(_rows())


def test_write_parquet_roundtrip(tmp_path):
    rows = _rows()
    files = write_parquet(iter(rows), tmp_path, rows_per_file=1000)
    assert len(files) == -(-len(rows) // 1000)
    total = 0
    for f in files:
        t = pq.read_table(f)
        assert t.schema.equals(arrow_schema())
        total += t.num_rows
    assert total == len(rows)
