from auditdemo.config import DemoConfig
from auditdemo.lakewatch import SdkApi
from auditdemo.load import load
from auditdemo.schema import COLUMNS


class FakeApi:
    def __init__(self):
        self.calls = []

    def sql(self, statement, warehouse_id):
        self.calls.append(("sql", statement))
        return []

    def upload(self, volume_path, local_path):
        self.calls.append(("upload", volume_path))

    def mkdirs(self, p):
        self.calls.append(("mkdirs", p))

    def delete_dir(self, p):
        self.calls.append(("delete_dir", p))


def test_load_statements(tmp_path):
    f = tmp_path / "part-0.parquet"
    f.write_bytes(b"x")
    api = FakeApi()
    load(api, DemoConfig("c", "s"), [f], "wh")
    up = ("upload", "/Volumes/c/s/raw/audit/part-0.parquet")
    assert ("delete_dir", "/Volumes/c/s/raw/audit") in api.calls
    assert api.calls.index(("delete_dir", "/Volumes/c/s/raw/audit")) < api.calls.index(up)
    sqls = [c[1] for c in api.calls if c[0] == "sql"]
    ins = next(s for s in sqls if s.startswith("INSERT OVERWRITE"))
    cols = ", ".join(n for n, _ in COLUMNS)
    assert f"SELECT {cols} FROM read_files('/Volumes/c/s/raw/audit/', format => 'parquet')" in ins
    assert api.calls.index(up) < api.calls.index(("sql", ins))
    assert any("CREATE SCHEMA IF NOT EXISTS `c`.`s`" in s for s in sqls)
    assert any("CREATE VOLUME IF NOT EXISTS `c`.`s`.`raw`" in s for s in sqls)
    pr = next(s for s in sqls if s.startswith("CREATE OR REPLACE TABLE `c`.`s`.`principals`"))
    assert "svc-backup@corp.example" in pr
    view = next(s for s in sqls if "demo_signals" in s)
    assert "{{" not in view and "`c`.`s`.`demo_signals`" in view


def test_sdkapi_delete_dir_removes_files():
    class Entry:
        def __init__(self, p, d=False):
            self.path, self.is_directory = p, d

    class Files:
        deleted = []

        def list_directory_contents(self, p):
            return [Entry(p + "/a"), Entry(p + "/b")]

        def delete(self, p):
            self.deleted.append(p)

    api = SdkApi.__new__(SdkApi)
    api.w = type("W", (), {"files": Files()})()
    api.delete_dir("/Volumes/c/s/raw/audit/")
    assert Files.deleted == ["/Volumes/c/s/raw/audit/a", "/Volumes/c/s/raw/audit/b"]


def test_load_refuses_real_audit_table(tmp_path):
    import pytest
    api = FakeApi()
    with pytest.raises(ValueError):
        load(api, DemoConfig("c", "s", audit_table="system.access.audit"), [], "wh")
    assert api.calls == []


def test_load_quotes_hyphenated_catalog(tmp_path):
    """A catalog such as `my-catalog` must be back-quoted in every statement and in the view."""
    import re
    f = tmp_path / "part-0.parquet"
    f.write_bytes(b"x")
    api = FakeApi()
    load(api, DemoConfig("my-catalog", "my-schema"), [f], "wh")
    sqls = [c[1] for c in api.calls if c[0] == "sql"]
    assert len(sqls) == 6
    for s in sqls:
        # every name part is back-quoted; only the string literals keep the plain catalog name
        plain = re.sub(r"'[^']*'", "''", s)
        assert "my-catalog" not in plain.replace("`my-catalog`", "")
        assert "my-schema" not in plain.replace("`my-schema`", "")
    assert sqls[2].startswith("CREATE TABLE IF NOT EXISTS `my-catalog`.`my-schema`.`audit`")
    assert sqls[3].startswith("INSERT OVERWRITE `my-catalog`.`my-schema`.`audit` ")
    view = sqls[5]
    assert "`my-catalog`.`__lakewatch`.`signals`" in view
    assert "`my-catalog`.`my-schema`.`principals`" in view
    assert "startswith(s.rule_name, 'my-catalog.my-schema.')" in view
