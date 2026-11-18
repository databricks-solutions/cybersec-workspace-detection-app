"""Build the dataset: background + scenario rows, sorted by time, written as parquet."""

from __future__ import annotations

import heapq
import json
from datetime import datetime, timedelta, timezone
from itertools import islice
from pathlib import Path
from typing import Iterable, Iterator

import pyarrow as pa
import pyarrow.parquet as pq

from .background import background
from .scenarios import ALL
from .schema import arrow_schema
from .world import World

_ROOT = Path(__file__).resolve().parents[2]


def _data(*parts: str) -> Path:
    """Run-time data file: the repo copy, else the one packaged under auditdemo/_data."""
    repo = _ROOT.joinpath(*parts)
    packed = parts[1:] if parts[0] == "profile" else parts
    return repo if repo.exists() else Path(__file__).parent.joinpath("_data", *packed)


def load_profile() -> dict:
    return json.loads(_data("profile", "profile.json").read_text())


def default_anchor() -> datetime:
    return datetime.now(timezone.utc).replace(second=0, microsecond=0)


def generate(anchor: datetime, days: int = 14, seed: int = 1337, scale: float = 1.0,
             scenarios: bool = True) -> Iterator[dict]:
    """Rows for [anchor - days, anchor], sorted by event_time.

    The background streams day by day in time order; the scenario rows (a few hundred)
    are sorted in memory and merged in, so memory stays small.
    """
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    anchor = anchor.astimezone(timezone.utc)
    world = World(seed)
    bg = background(world, load_profile(), anchor - timedelta(days=days), anchor, seed, scale)
    if not scenarios:
        yield from bg
        return
    extra = sorted((r for s in ALL for r in s.rows(world, anchor)), key=lambda r: r["event_time"])
    yield from heapq.merge(bg, extra, key=lambda r: r["event_time"])


def write_parquet(rows: Iterable[dict], out_dir: Path, rows_per_file: int = 200_000) -> list[Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    schema = arrow_schema()
    it = iter(rows)
    files: list[Path] = []
    while chunk := list(islice(it, rows_per_file)):
        for r in chunk:  # pyarrow wants map values as (key, value) pairs
            r["request_params"] = list((r["request_params"] or {}).items())
        path = out_dir / f"audit-{len(files):05d}.parquet"
        pq.write_table(pa.Table.from_pylist(chunk, schema=schema), path, compression="zstd")
        files.append(path)
    return files
