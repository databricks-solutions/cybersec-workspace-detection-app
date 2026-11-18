"""The reset flow with fake ops (order, and rules disabled on failure: Review Focus 3)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from auditdemo import jobs
from auditdemo.config import DemoConfig

NOW = datetime(2026, 11, 12, 10, 7, 31, 123456, tzinfo=UTC)
START = datetime(2026, 11, 12, 10, 7, tzinfo=UTC)


class FakeOps:
    def __init__(self, fail_at=None):
        self.calls, self.fail_at = [], fail_at

    def _rec(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        if name == self.fail_at:
            raise RuntimeError(f"{name} failed")

    def warn_recent_show(self, since):
        self._rec("warn_recent_show", since)

    def disable_rules(self):
        self._rec("disable_rules")

    def resolve_alerts(self):
        self._rec("resolve_alerts")

    def load(self, anchor):
        self._rec("load", anchor=anchor)

    def enable_rules(self, since, lookback):
        self._rec("enable_rules", since=since, lookback=lookback)

    def check(self, since):
        self._rec("check", since=since)


def test_reset_order():
    ops = FakeOps()
    jobs.reset(ops, now=lambda: NOW)
    assert [c[0] for c in ops.calls] == ["warn_recent_show", "disable_rules", "resolve_alerts", "load",
                                         "enable_rules", "check", "disable_rules"]
    by = {c[0]: c for c in ops.calls}
    assert by["load"][2] == {"anchor": START}
    assert by["enable_rules"][2] == {"since": START, "lookback": "8h"}
    assert by["check"][2] == {"since": START}


@pytest.mark.parametrize("step", ["load", "enable_rules", "check"])
def test_reset_disables_rules_on_failure(step):
    ops = FakeOps(fail_at=step)
    with pytest.raises(RuntimeError):
        jobs.reset(ops, now=lambda: NOW)
    assert ops.calls[-1][0] == "disable_rules"
    assert [c[0] for c in ops.calls].count("disable_rules") == 2


def test_reset_goes_on_when_warn_recent_show_fails(capsys):
    ops = FakeOps(fail_at="warn_recent_show")
    jobs.reset(ops, now=lambda: NOW)
    assert [c[0] for c in ops.calls] == ["warn_recent_show", "disable_rules", "resolve_alerts", "load",
                                         "enable_rules", "check", "disable_rules"]
    out = capsys.readouterr().out
    assert "WARNING: could not check the time of the last demo signal" in out
    assert "warn_recent_show failed" in out


def test_anchor_for_truncates_to_minute():
    assert jobs.anchor_for(NOW) == START


# ---- LiveOps with a fake api (no workspace)

class FakeApi:
    def __init__(self, rows=None):
        self.statements, self.rows = [], rows or []

    def sql(self, statement, warehouse_id):
        self.statements.append(statement)
        return self.rows


def _live(rows=None, audit_table=None):
    ops = jobs.LiveOps.__new__(jobs.LiveOps)
    ops.cfg, ops.warehouse_id, ops.api = DemoConfig("cat", "sch", audit_table), "wh", FakeApi(rows)
    ops.seed, ops.days, ops.scale = 1337, 14, 1.0
    return ops


def test_signals_since_query():
    ops = _live([["cat.sch.ada_one", "a@x"], ["cat.sch.ada_pivot", "a@x, b@x"]])
    assert ops.signals_since(START) == [("ada_one", "a@x"), ("ada_pivot", "a@x, b@x")]
    q = ops.api.statements[0]
    assert "`cat`.`__lakewatch`.`signals`" in q and "startswith(rule_name, 'cat.sch.')" in q
    assert "created_at >= TIMESTAMP '2026-11-12 10:07:00+00:00'" in q and "$.actors" in q


def test_check_raises_on_problems(monkeypatch):
    ops = _live([["cat.sch.ada_pat_new_source_ip", "bg@corp.example"]])
    with pytest.raises(RuntimeError, match="matrix"):
        ops.check(START)


def test_warn_recent_show_prints_warning(capsys):
    _live([["12"]]).warn_recent_show(START)
    assert "WARNING" in capsys.readouterr().out
    _live([["240"]]).warn_recent_show(START)
    _live([[None]]).warn_recent_show(START)
    assert "WARNING" not in capsys.readouterr().out


def test_load_uses_demo_table_even_with_audit_table_override(monkeypatch):
    seen = {}

    def fake_load(api, cfg, files, warehouse_id, seed):
        seen["cfg"], seen["files"] = cfg, list(files)

    monkeypatch.setattr(jobs, "_load", fake_load)
    monkeypatch.setattr(jobs, "_generate", lambda anchor, days, seed, scale: iter([]))
    monkeypatch.setattr(jobs, "_write_parquet", lambda rows, out: [out / "part-0.parquet"])
    _live(audit_table="system.access.audit").load(START)
    assert seen["cfg"].audit_table is None and seen["cfg"].table == "cat.sch.audit"


def test_reset_main_parses_args(monkeypatch):
    seen = {}

    class Ops:
        def __init__(self, cfg, warehouse_id, profile=None):
            seen.update(cfg=cfg, wh=warehouse_id, profile=profile)

    monkeypatch.setattr(jobs, "LiveOps", Ops)
    monkeypatch.setattr(jobs, "reset", lambda ops: seen.setdefault("ran", True))
    jobs.reset_main(["--catalog", "cat", "--schema", "sch", "--warehouse-id", "wh", "--audit-table="])
    assert seen == {"cfg": DemoConfig("cat", "sch", None), "wh": "wh", "profile": None, "ran": True}


# ---- teardown deletes only this schema's demo rules

class FakeRulesApi:
    def __init__(self, existing):
        self.existing, self.deleted = existing, []

    def do(self, method, path, *, query=None, body=None):
        if method == "GET":
            return {"rules": self.existing}
        if method == "DELETE":
            self.deleted.append(path)
            return {}
        raise AssertionError((method, path))


def test_teardown_deletes_only_demo_rules_of_schema():
    from auditdemo import rules
    api = FakeRulesApi([
        {"catalog_name": "cat", "schema_name": "sch", "rule_name": "ada_one", "rule_id": "1"},
        {"catalog_name": "cat", "schema_name": "sch", "rule_name": "adp_two", "rule_id": "2"},
        {"catalog_name": "cat", "schema_name": "sch", "rule_name": "other_rule", "rule_id": "3"},
        {"catalog_name": "cat", "schema_name": "other", "rule_name": "ada_one", "rule_id": "4"},
        {"catalog_name": "cat", "schema_name": "sch", "rule_name": "adax_lookalike", "rule_id": "5"},
        {"catalog_name": "cat2", "schema_name": "sch", "rule_name": "ada_one", "rule_id": "6"},
    ])
    assert rules.teardown(api, DemoConfig("cat", "sch")) == ["ada_one", "adp_two"]
    assert api.deleted == ["/api/2.0/lakewatch/rules/1", "/api/2.0/lakewatch/rules/2"]


# ---- SIGTERM (job cancel / timeout) runs the finally

def test_reset_main_installs_sigterm_handler(monkeypatch):
    import signal
    seen = {}
    monkeypatch.setattr(signal, "signal", lambda sig, handler: seen.setdefault(sig, handler))

    class Ops:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(jobs, "LiveOps", Ops)
    monkeypatch.setattr(jobs, "reset", lambda ops: None)
    jobs.reset_main(["--catalog", "c", "--schema", "s", "--warehouse-id", "w"])
    assert seen[signal.SIGTERM] is jobs._on_sigterm
    with pytest.raises(SystemExit):
        jobs._on_sigterm(signal.SIGTERM, None)


def test_sigterm_during_reset_still_disables():
    import signal

    class Ops(FakeOps):
        def enable_rules(self, since, lookback):
            self._rec("enable_rules")
            jobs._on_sigterm(signal.SIGTERM, None)

    ops = Ops()
    with pytest.raises(jobs.Terminated):
        jobs.reset(ops, now=lambda: NOW)
    assert ops.calls[-1][0] == "disable_rules"
