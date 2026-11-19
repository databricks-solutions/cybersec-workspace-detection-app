"""Load the generated parquet files into the audit table, then the principals table and views."""

from __future__ import annotations

from pathlib import Path

from .build import _data
from .config import DemoConfig
from .rules import quote_table
from .schema import COLUMNS, ddl
from .world import World

EXTRA_PRINCIPALS = [("svc-backup@corp.example", "svc-backup", "user", "unknown")]


def _lit(v: str) -> str:
    return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"


def principals_sql(cfg: DemoConfig, seed: int = 1337) -> str:
    world = World(seed)
    rows = [(p.email, p.display_name, p.kind, p.role) for p in world.principals] + EXTRA_PRINCIPALS
    values = ",\n  ".join("(" + ", ".join(_lit(v) for v in r) + ")" for r in rows)
    return (f"CREATE OR REPLACE TABLE {quote_table(cfg.catalog + '.' + cfg.schema + '.principals')} AS\n"
            f"SELECT * FROM VALUES\n  {values}\nAS t(email, display_name, kind, role)")


def views_sql(cfg: DemoConfig) -> str:
    """The demo_signals view. views.sql back-quotes {{catalog}} and {{schema}} in the names, so a catalog
    such as `my-catalog` works."""
    text = _data("sql", "views.sql").read_text()
    return text.replace("{{catalog}}", cfg.catalog).replace("{{schema}}", cfg.schema)


def load(api, cfg: DemoConfig, files: list[Path], warehouse_id: str, seed: int = 1337) -> None:
    if cfg.audit_table and cfg.audit_table != cfg.demo_table:
        raise ValueError(f"load only writes {cfg.demo_table}, not audit_table={cfg.audit_table}")

    def sql(s: str):
        return api.sql(s, warehouse_id)

    schema = quote_table(f"{cfg.catalog}.{cfg.schema}")
    table = quote_table(cfg.demo_table)
    sql(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    sql(f"CREATE VOLUME IF NOT EXISTS {schema}.`raw`")
    sql(ddl(table))
    folder = f"{cfg.volume_root}/audit"
    api.mkdirs(folder)
    api.delete_dir(folder)
    for f in files:
        api.upload(f"{folder}/{Path(f).name}", Path(f))
    cols = ", ".join(n for n, _ in COLUMNS)
    sql(f"INSERT OVERWRITE {table} ({cols}) "
        f"SELECT {cols} FROM read_files('{folder}/', format => 'parquet')")
    sql(principals_sql(cfg, seed))
    sql(views_sql(cfg))
