"""Rules: lint over rules/*.yaml, rendering, the try_rule rewrite, and apply/deploy with a fake api."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from auditdemo import rules
from auditdemo.config import DemoConfig

BASE = "/api/2.0/lakewatch"
CFG = DemoConfig("cat", "sch")
RULE_FILES = sorted(rules.rules_dir().glob("*.yaml"))
STAGE_1_3 = {"ada_pat_new_source_ip", "ada_sp_oauth_new_user_agent", "ada_session_reuse_new_ip_ua",
             "ada_discovery_api_burst", "ada_first_secret_enumeration", "ada_ip_denied_after_auth",
             "ada_secret_harvest_chain", "ada_secret_denied_then_read"}
STAGE_4_6 = {"ada_first_seen_create_function": "4", "ada_compute_fallback": "4", "ada_sp_grants_admin": "5",
             "ada_token_minted_new_source": "5", "ada_sensitive_export": "6", "ada_short_lived_function": "6"}
FLAT_KEYS = {"catalog_name", "schema_name", "rule_name", "description", "severity", "category", "fidelity",
             "objective", "references", "mitre", "deduplication", "deduplication_time_window", "schedule",
             "batch", "output", "timerange", "runbook", "annotations", "suppress_until_time"}
REQUIRED = {"catalog_name", "schema_name", "rule_name", "severity", "fidelity", "schedule", "batch", "output"}
SEVERITIES = {"Informational", "Low", "Medium", "High", "Critical"}
FIDELITIES = {"FIDELITY_DEVELOPMENT", "FIDELITY_INVESTIGATIVE", "FIDELITY_MEDIUM", "FIDELITY_HIGH"}
STAGES = {"1", "2", "3", "4", "5", "6", "corr"}
CORRELATION = {"ada_identity_pivot_chain": "Critical", "ada_multi_stage_identity": "High"}
SIGNALS = "`{{catalog}}`.`__lakewatch`.`signals`"


def _raw(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _query(path: Path) -> str:
    return _raw(path)["batch"]["sql"]["query"]


def _no_comments(sql: str) -> str:
    return re.sub(r"--[^\n]*", "", sql)


def test_stage_1_3_rules_exist():
    names = {p.stem for p in RULE_FILES}
    assert STAGE_1_3 <= names
    assert STAGE_1_3 <= set(rules.STAGE_RULES)
    assert not set(rules.STAGE_RULES) & set(rules.CORRELATION_RULES)
    assert all(n.startswith("adp_") for n in rules.PORTED_RULES)


def test_stage_4_6_rules_exist():
    names = {p.stem for p in RULE_FILES}
    assert set(STAGE_4_6) <= names
    assert set(STAGE_4_6) <= set(rules.STAGE_RULES)
    for name, stage in STAGE_4_6.items():
        assert str(_raw(rules.rules_dir() / f"{name}.yaml")["output"]["context"]["stage"]) == stage


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_fields(path: Path):
    r = _raw(path)
    assert set(r) <= FLAT_KEYS, set(r) - FLAT_KEYS
    assert REQUIRED <= set(r)
    assert "compute_mode" not in r and "compute_group" not in r["schedule"]
    assert r["catalog_name"] == "{{catalog}}" and r["schema_name"] == "{{schema}}"
    assert r["rule_name"] == path.stem and re.fullmatch(r"(ada|adp)_\w+", r["rule_name"])
    assert r["schedule"] == {"at_least_every": "1h", "enabled": False}
    assert r["batch"]["warehouse_id"] == "{{warehouse_id}}"
    assert r["severity"] in SEVERITIES and r["fidelity"] in FIDELITIES
    out = r["output"]
    assert out["event_time_column"] and out["default_context"] is False
    # the summary names the entity, never a time or a count
    assert not re.search(r"\{(event_time|time|first_time|last_time|n_\w+|\w*count\w*)\}", out["summary"])
    assert "IN_TIMERANGE(" in _query(path)
    # explicit, so that re-applying the file restores it after a reset's long lookback; the correlation
    # rules read signals that arrive up to a schedule interval after their event time
    assert r["timerange"]["extend_lookback"] == ("8h" if r["rule_name"] in CORRELATION else "15m")


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_no_match_recognize(path: Path):
    assert "MATCH_RECOGNIZE" not in _query(path).upper()


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_frames_are_explicit(path: Path):
    sql = _no_comments(_query(path)).upper()
    for m in re.finditer(r"\b(ROWS|RANGE)\s+(\w+)", sql):
        assert m.group(2) == "BETWEEN", m.group(0)


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_context_keys(path: Path):
    ctx = _raw(path)["output"]["context"]
    assert {"actor", "actor_kind", "src_ip", "stage"} <= set(ctx)
    assert str(ctx["stage"]) in STAGES
    sql = _query(path)
    for key in ("token_id", "session_id"):
        if re.search(rf"\bAS {key}\b", sql):
            assert key in ctx, f"{key} is an output column but not in the context"
    # every {placeholder} of summary and context is an output column alias of the SQL
    out = _raw(path)["output"]
    for text in [out["summary"], *map(str, ctx.values())]:
        for col in re.findall(r"\{(\w+)\}", text):
            assert re.search(rf"\b{col}\b", sql), col


def _sources(sql: str) -> set[str]:
    sql = _no_comments(sql)
    ctes = set(re.findall(r"(?:\bWITH|,)\s*(\w+)\s+AS\s*\(", sql, flags=re.I))
    targets = set(re.findall(r"\b(?:FROM|JOIN)\s+([^\s(),|]+)", sql, flags=re.I))
    return targets - ctes


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_sources_only_audit_table(path: Path):
    # Review Focus 4: pointed at system.access.audit, a rule may read nothing else.
    sql = _query(path)
    # the demo's principals table, as a name (pack SQL has addPrincipalsToGroup and "service principals"
    # in comments)
    assert not re.search(r"\bprincipals\b", _no_comments(sql), flags=re.I)
    stage = str(_raw(path)["output"]["context"]["stage"])
    allowed = {SIGNALS} if stage == "corr" else {"{{audit_table}}"}
    assert _sources(sql) and _sources(sql) <= allowed, _sources(sql)
    if stage == "corr":
        # the schema only in the rule-name literals that pick this demo's signals
        sql = re.sub(r"'\{\{catalog\}\}\.\{\{schema\}\}\.ada_\w*'", "''", sql)
    assert "{{schema}}" not in sql


def test_correlation_rules_exist():
    assert set(rules.CORRELATION_RULES) == set(CORRELATION)
    for name, severity in CORRELATION.items():
        r = _raw(rules.rules_dir() / f"{name}.yaml")
        assert r["severity"] == severity and str(r["output"]["context"]["stage"]) == "corr"


@pytest.mark.parametrize("name", sorted(CORRELATION))
def test_correlation_rules_read_only_stage_signals(name):
    sql = _no_comments(_query(rules.rules_dir() / f"{name}.yaml"))
    # only the ada_ stage signals of this schema, never the correlation rules themselves (adp_ = noise)
    assert "startswith(rule_name, '{{catalog}}.{{schema}}.ada_')" in sql
    for other in CORRELATION:
        assert "'{{catalog}}.{{schema}}.%s'" % other in sql
    assert "SELECT DISTINCT" in sql  # repeated runs create identical signals
    # signals of earlier shows stay in the table: every signals read takes only recent ones
    assert sql.count("FROM `{{catalog}}`.`__lakewatch`.`signals`") == 1
    assert "created_at >= TIMERANGE_NOW() - INTERVAL 90 MINUTES" in sql
    assert "IN_TIMERANGE(" in sql
    # element_at on an empty array fails the run (identity-graph lesson)
    assert not re.search(r"(?<!try_)element_at\(", sql)


def test_try_rule_rewrites_created_at_guard():
    q = rules.render(rules.rules_dir() / "ada_multi_stage_identity.yaml", CFG, "")["batch"]["sql"]["query"]
    out = rules.rewrite_timerange(q, ANCHOR, "8h")
    assert "created_at >= TIMESTAMP '2026-11-12 09:54:00+00:00' - INTERVAL 90 MINUTES" in out
    assert "TIMERANGE" not in out.upper()


def test_pivot_chain_summary():
    out = _raw(rules.rules_dir() / "ada_identity_pivot_chain.yaml")["output"]
    assert out["summary"] == "One intrusion, two identities: {actor_a} → {actor_b} via {src_ip}"
    assert {"actor_a", "actors"} <= set(out["context"]) and out["context"]["actor"] == "{actor_b}"


def test_sources_parser_sees_ctes_and_joins():
    sql = "WITH a AS (FROM {{audit_table}} |> WHERE x), b AS (SELECT 1 FROM a)\nFROM b |> JOIN other.t ON 1"
    assert _sources(sql) == {"{{audit_table}}", "other.t"}


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_mitre_present(path: Path):
    mitre = _raw(path)["mitre"]
    assert mitre
    for m in mitre:
        assert m["taxonomy"] == "Enterprise" and m["tactic"] and m["technique"]
        assert re.fullmatch(r"T\d{4}", m["technique_id"])
        if "sub_technique_id" in m:
            assert m["sub_technique_id"].startswith(m["technique_id"] + ".") and m["sub_technique"]


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_render_fills_placeholders(path: Path):
    rule = rules.render(path, CFG, "wh123")
    text = yaml.safe_dump(rule)
    assert "{{" not in text and "}}" not in text
    assert rule["catalog_name"] == "cat" and rule["schema_name"] == "sch"
    assert rule["batch"]["warehouse_id"] == "wh123"


def test_render_audit_table_override():
    path = rules.rules_dir() / "ada_first_secret_enumeration.yaml"
    q = rules.render(path, DemoConfig("cat", "sch", audit_table="system.access.audit"), "wh")["batch"]["sql"]["query"]
    assert "`system`.`access`.`audit`" in q and "`cat`.`sch`.`audit`" not in q
    q = rules.render(path, CFG, "wh")["batch"]["sql"]["query"]
    assert "`cat`.`sch`.`audit`" in q


@pytest.mark.parametrize("name,guard", [
    ("ada_sp_oauth_new_user_agent", "src_ip IS NOT NULL"),
    ("ada_session_reuse_new_ip_ua", "source_ip_address IS NOT NULL"),
    ("ada_token_minted_new_source", "src_ip IS NOT NULL"),
])
def test_new_ip_rules_drop_null_ips(name, guard):
    # A NULL source IP never matches a baseline (or is skipped by concat_ws) and would look new.
    assert guard in _no_comments(_query(rules.rules_dir() / f"{name}.yaml"))


# ---- try_rule rewrite

ANCHOR = datetime(2026, 11, 12, 9, 54, tzinfo=timezone.utc)


def test_try_rule_rewrites_timerange():
    sql = ("SELECT * FROM t WHERE IN_TIMERANGE(event_time) AND NOT in_timerange(coalesce(a.t, b.t)) "
           "AND x >= TIMERANGE_NOW() - INTERVAL 14 DAYS AND y <= timerange_now()")
    out = rules.rewrite_timerange(sql, ANCHOR, "8h")
    lo, hi = "TIMESTAMP '2026-11-12 01:54:00+00:00'", "TIMESTAMP '2026-11-12 09:54:00+00:00'"
    assert out == (f"SELECT * FROM t WHERE (event_time > {lo} AND event_time <= {hi}) "
                   f"AND NOT (coalesce(a.t, b.t) > {lo} AND coalesce(a.t, b.t) <= {hi}) "
                   f"AND x >= {hi} - INTERVAL 14 DAYS AND y <= {hi}")
    assert "TIMERANGE" not in out.upper()


@pytest.mark.parametrize("text,seconds", [("8h", 8 * 3600), ("30m", 1800), ("1h30m", 5400), ("2d", 172800),
                                          ("45s", 45)])
def test_lookback_durations(text, seconds):
    assert rules.parse_duration(text).total_seconds() == seconds


def test_lookback_bad_duration():
    with pytest.raises(ValueError):
        rules.parse_duration("8 hours")


def test_try_rule_runs_rendered_sql():
    seen = []

    def sql(statement):
        seen.append(statement)
        return [["2026-11-12T07:00:00Z", "a@corp.example"]]

    rows = rules.try_rule(sql, CFG, "ada_first_secret_enumeration", ANCHOR, lookback="2h")
    assert rows == [["2026-11-12T07:00:00Z", "a@corp.example"]]
    assert "`cat`.`sch`.`audit`" in seen[0] and "TIMERANGE" not in seen[0].upper()
    assert "TIMESTAMP '2026-11-12 07:54:00+00:00'" in seen[0]


# ---- apply / deploy against a fake api

class FakeApi:
    def __init__(self, existing=None):
        self.calls, self.rules = [], dict(existing or {})

    def do(self, method, path, *, query=None, body=None):
        self.calls.append((method, path, query, body))
        if method == "GET" and path == f"{BASE}/rules":
            return {"rules": list(self.rules.values())}
        if method == "POST" and path == f"{BASE}/rules:validateRule":
            return {}
        if method == "POST" and path == f"{BASE}/rules":
            made = {**body, "rule_id": f"r-{body['rule_name']}"}
            self.rules[body["rule_name"]] = made
            return made
        if method == "PATCH":
            rule = next(r for r in self.rules.values() if path.endswith(r["rule_id"]))
            rule.update(body)
            return rule
        raise AssertionError((method, path))


def _rule(name="ada_x", enabled=False):
    return {"catalog_name": "cat", "schema_name": "sch", "rule_name": name, "severity": "High",
            "schedule": {"at_least_every": "1h", "enabled": enabled},
            "batch": {"warehouse_id": "wh", "sql": {"query": "SELECT 1"}}}


def test_apply_creates_after_validate():
    api = FakeApi()
    assert rules.apply(api, _rule(), "wh") == "created"
    methods = [(m, p) for m, p, _, _ in api.calls]
    assert methods.index(("POST", f"{BASE}/rules:validateRule")) < methods.index(("POST", f"{BASE}/rules"))


def test_apply_patches_existing_rule():
    api = FakeApi({"ada_x": {**_rule(), "rule_id": "r1"}})
    assert rules.apply(api, _rule(enabled=True), "wh") == "updated"
    patch = next(c for c in api.calls if c[0] == "PATCH")
    assert patch[1] == f"{BASE}/rules/r1" and "rule_name" not in patch[3]
    validate = next(b for m, p, _, b in api.calls if p.endswith(":validateRule"))
    assert validate["rule"]["name"] == "rules/r1" and validate["update_mask"]


def test_deploy_disabled_applies_all_rules_with_lookback():
    api = FakeApi()
    rules.deploy(api, lambda s: [], CFG, "wh", enabled=None, lookback="30h")
    created = [b for m, p, _, b in api.calls if m == "POST" and p == f"{BASE}/rules"]
    assert [b["rule_name"] for b in created] == rules.STAGE_RULES + rules.PORTED_RULES + rules.CORRELATION_RULES
    assert all(b["schedule"]["enabled"] is False for b in created)
    assert all(b["timerange"]["extend_lookback"] == "30h" for b in created)


def test_wait_for_signals_counts_since():
    statements = []

    def sql(s):
        statements.append(s)
        return [["cat.sch.ada_a", "2"], ["cat.sch.ada_b", "1"]]

    since = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)
    assert rules.wait_for_signals(sql, CFG, ["ada_a", "ada_b"], since=since) == {"ada_a": 2, "ada_b": 1}
    assert "created_at >= TIMESTAMP '2026-11-12 10:00:00+00:00'" in statements[0]
    assert "`cat`.`__lakewatch`.`signals`" in statements[0]


def test_deploy_enabled_waits_only_for_expected_rules(monkeypatch):
    waits = []

    def fake_wait(sql, cfg, names, *, since=None, **kw):
        n_created = len([c for c in api.calls if c[0] == "POST" and c[1] == f"{BASE}/rules"])
        waits.append((list(names), since, n_created))
        return {n: 1 for n in names}

    monkeypatch.setattr(rules, "wait_for_signals", fake_wait)
    api = FakeApi()
    since = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)
    expect = ["ada_pat_new_source_ip", "adp_secrets_enumeration", "ada_identity_pivot_chain"]
    rules.deploy(api, lambda s: [], CFG, "wh", enabled=True, since=since, lookback="8h", expect=expect)
    n_first = len(rules.STAGE_RULES + rules.PORTED_RULES)
    # stage + ported applied, wait for their expected signals, then the corr rules, then wait for theirs
    assert waits == [(["ada_pat_new_source_ip", "adp_secrets_enumeration"], since, n_first),
                     (["ada_identity_pivot_chain"], since, n_first + len(rules.CORRELATION_RULES))]


def test_deploy_enabled_default_expect_is_scenarios(monkeypatch):
    from auditdemo.scenarios import ALL
    waits = []
    monkeypatch.setattr(rules, "wait_for_signals",
                        lambda sql, cfg, names, **kw: waits.append(list(names)) or {n: 1 for n in names})
    rules.deploy(FakeApi(), lambda s: [], CFG, "wh", enabled=True)
    assert set(waits[0]) | set(waits[1]) == {r for s in ALL for r in s.expected_rules}
    assert "ada_compute_fallback" in waits[0] and set(waits[1]) <= set(rules.CORRELATION_RULES)



def _all_existing(enabled=True):
    """Every demo rule as it exists after a reset (enabled: as during a reset)."""
    everything = rules.STAGE_RULES + rules.PORTED_RULES + rules.CORRELATION_RULES
    return {n: {**_rule(n, enabled), "catalog_name": CFG.catalog, "schema_name": CFG.schema, "rule_id": f"r-{n}"}
            for n in everything}


def test_deploy_disable_is_best_effort_per_rule():
    class Flaky(FakeApi):
        def do(self, method, path, *, query=None, body=None):
            if method == "PATCH" and path == f"{BASE}/rules/r-{bad}":
                raise RuntimeError("503 Service Unavailable")
            return super().do(method, path, query=query, body=body)

    bad = rules.STAGE_RULES[1]
    api, sleeps = Flaky(_all_existing()), []
    with pytest.raises(RuntimeError, match=bad) as err:
        rules.deploy(api, lambda s: [], CFG, "wh", enabled=False, sleep=sleeps.append)
    assert {n for n, r in api.rules.items() if r["schedule"]["enabled"]} == {bad}
    assert sleeps == [5] and "1 rule(s)" in str(err.value)


def test_deploy_disable_retries_once():
    class OnceFlaky(FakeApi):
        failed = False

        def do(self, method, path, *, query=None, body=None):
            if method == "PATCH" and not self.failed:
                self.failed = True
                raise RuntimeError("429 Too Many Requests")
            return super().do(method, path, query=query, body=body)

    api = OnceFlaky(_all_existing())
    rules.deploy(api, lambda s: [], CFG, "wh", enabled=False, sleep=lambda s: None)
    assert not any(r["schedule"]["enabled"] for r in api.rules.values())


def test_deploy_disable_skips_rules_not_created_yet(capsys):
    """First reset on a fresh target: no rule exists and validation would fail (no audit table yet)."""
    class NoTable(FakeApi):
        def do(self, method, path, *, query=None, body=None):
            if method == "POST" and path == f"{BASE}/rules:validateRule":
                raise RuntimeError("TABLE_OR_VIEW_NOT_FOUND")
            return super().do(method, path, query=query, body=body)

    api, sleeps = NoTable(), []
    rules.deploy(api, lambda s: [], CFG, "wh", enabled=False, sleep=sleeps.append)
    assert {(m, p) for m, p, _, _ in api.calls} == {("GET", f"{BASE}/rules")}
    assert sleeps == [] and api.rules == {}
    assert capsys.readouterr().out.count("not created yet") == len(_all_existing())


def test_deploy_disable_only_existing_rules():
    name = rules.STAGE_RULES[0]
    api = FakeApi({name: _all_existing()[name]})
    rules.deploy(api, lambda s: [], CFG, "wh", enabled=False, sleep=lambda s: None)
    assert [c[1] for c in api.calls if c[0] in ("PATCH", "POST") and not c[1].endswith(":validateRule")] == \
        [f"{BASE}/rules/r-{name}"]
    assert api.rules[name]["schedule"]["enabled"] is False


def test_deploy_expect_empty_does_not_wait(monkeypatch):
    monkeypatch.setattr(rules, "wait_for_signals", lambda *a, **k: pytest.fail("waited"))
    api = FakeApi()
    rules.deploy(api, lambda s: [], CFG, "wh", enabled=True, expect=[])
    assert len([c for c in api.calls if c[0] == "POST" and c[1] == f"{BASE}/rules"]) == len(_all_existing())


def test_deploy_exclude_skips_rule():
    api = FakeApi()
    rules.deploy(api, lambda s: [], CFG, "wh", enabled=True, expect=[], exclude=["ada_sp_oauth_new_user_agent"])
    assert set(api.rules) == set(_all_existing()) - {"ada_sp_oauth_new_user_agent"}
    assert all(r["schedule"]["enabled"] for r in api.rules.values())


def test_deploy_exclude_keeps_existing_rule_unchanged():
    existing = _all_existing(enabled=False)
    api = FakeApi(existing)
    rules.deploy(api, lambda s: [], CFG, "wh", enabled=True, expect=[], exclude=["ada_sp_oauth_new_user_agent"])
    assert api.rules["ada_sp_oauth_new_user_agent"]["schedule"]["enabled"] is False
    assert not any(c[1].endswith("r-ada_sp_oauth_new_user_agent") for c in api.calls)


def test_deploy_exclude_unknown_rule():
    with pytest.raises(ValueError, match="ada_nope"):
        rules.deploy(FakeApi(), lambda s: [], CFG, "wh", enabled=True, expect=[], exclude=["ada_nope"])
