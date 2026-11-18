import pyarrow as pa

from auditdemo import schema
from auditdemo.config import DemoConfig

EXPECTED = [
    ("account_id", "string"), ("workspace_id", "string"), ("version", "string"),
    ("event_time", "timestamp"), ("event_date", "date"), ("source_ip_address", "string"),
    ("user_agent", "string"), ("session_id", "string"),
    ("user_identity", "struct<email:string,subject_name:string>"),
    ("service_name", "string"), ("action_name", "string"), ("request_id", "string"),
    ("request_params", "map<string,string>"),
    ("response", "struct<status_code:int,error_message:string,result:string>"),
    ("audit_level", "string"), ("event_id", "string"),
    ("identity_metadata", "struct<run_by:string,run_as:string,acting_resource:string,"
     "run_by_display_name:string,run_as_display_name:string,"
     "acting_resource_display_name:string,acting_resource_type:string>"),
]


def test_columns_match_system_table():
    assert schema.COLUMNS == EXPECTED


def test_arrow_schema_types():
    s = schema.arrow_schema()
    assert s.names == [n for n, _ in EXPECTED]
    assert s.field("request_params").type == pa.map_(pa.string(), pa.string())
    assert s.field("event_time").type == pa.timestamp("us", tz="UTC")
    assert s.field("event_date").type == pa.date32()
    assert s.field("response").type.field("status_code").type == pa.int32()


def test_ddl_has_every_column():
    ddl = schema.ddl("c.s.audit")
    assert ddl.startswith("CREATE TABLE IF NOT EXISTS c.s.audit")
    assert ddl.rstrip().endswith("USING DELTA")
    for name, typ in EXPECTED:
        assert f"{name} {typ}" in ddl


def test_config_table_and_volume():
    c = DemoConfig("cat", "sch")
    assert c.table == "cat.sch.audit"
    assert c.volume_root == "/Volumes/cat/sch/raw"
    assert DemoConfig("cat", "sch", "system.access.audit").table == "system.access.audit"
