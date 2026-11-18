"""Schema of the demo audit table: the columns of system.access.audit (captured 2026-11-12)."""

from __future__ import annotations

import pyarrow as pa

_IDENTITY_METADATA = (
    "struct<run_by:string,run_as:string,acting_resource:string,"
    "run_by_display_name:string,run_as_display_name:string,"
    "acting_resource_display_name:string,acting_resource_type:string>"
)

COLUMNS: list[tuple[str, str]] = [
    ("account_id", "string"),
    ("workspace_id", "string"),
    ("version", "string"),
    ("event_time", "timestamp"),
    ("event_date", "date"),
    ("source_ip_address", "string"),
    ("user_agent", "string"),
    ("session_id", "string"),
    ("user_identity", "struct<email:string,subject_name:string>"),
    ("service_name", "string"),
    ("action_name", "string"),
    ("request_id", "string"),
    ("request_params", "map<string,string>"),
    ("response", "struct<status_code:int,error_message:string,result:string>"),
    ("audit_level", "string"),
    ("event_id", "string"),
    ("identity_metadata", _IDENTITY_METADATA),
]


def arrow_schema() -> pa.Schema:
    s = pa.string()
    return pa.schema([
        ("account_id", s),
        ("workspace_id", s),
        ("version", s),
        ("event_time", pa.timestamp("us", tz="UTC")),
        ("event_date", pa.date32()),
        ("source_ip_address", s),
        ("user_agent", s),
        ("session_id", s),
        ("user_identity", pa.struct([("email", s), ("subject_name", s)])),
        ("service_name", s),
        ("action_name", s),
        ("request_id", s),
        ("request_params", pa.map_(s, s)),
        ("response", pa.struct([("status_code", pa.int32()), ("error_message", s), ("result", s)])),
        ("audit_level", s),
        ("event_id", s),
        ("identity_metadata", pa.struct([
            ("run_by", s), ("run_as", s), ("acting_resource", s),
            ("run_by_display_name", s), ("run_as_display_name", s),
            ("acting_resource_display_name", s), ("acting_resource_type", s),
        ])),
    ])


def ddl(table: str) -> str:
    cols = ",\n  ".join(f"{n} {t}" for n, t in COLUMNS)
    return f"CREATE TABLE IF NOT EXISTS {table} (\n  {cols}\n) USING DELTA"
