"""Checks for the production Lakewatch rules in lakewatch/rules/.

    uv run --with pytest --with pyyaml pytest lakewatch/tests -q
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
RULES = sorted((ROOT / "lakewatch" / "rules").glob("*.yaml"))
PLACEHOLDERS = {"catalog", "schema", "warehouse_id", "audit_table"}
SEVERITIES = {"Informational", "Low", "Medium", "High", "Critical"}
FIDELITIES = {"FIDELITY_DEVELOPMENT", "FIDELITY_INVESTIGATIVE", "FIDELITY_MEDIUM", "FIDELITY_HIGH"}
TACTICS = {"Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
           "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
           "Collection", "Command and Control", "Exfiltration", "Impact"}


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def test_there_are_rules():
    assert RULES, "no rule files in lakewatch/rules/"


def test_generated_rules_are_current():
    """cwda_* files are generated from genie-agent/functions + the notebooks; they must not drift."""
    res = subprocess.run([sys.executable, str(ROOT / "lakewatch/tools/build_rules.py"), "--check"],
                         capture_output=True, text=True)
    assert res.returncode == 0, "run `uv run lakewatch/tools/build_rules.py`:\n" + res.stdout + res.stderr


def test_rule_names_unique_and_match_file():
    names = [load(p)["rule_name"] for p in RULES]
    assert len(names) == len(set(names))
    for p in RULES:
        assert load(p)["rule_name"] == p.stem


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.stem)
def test_rule_shape(path: Path):
    rule = load(path)
    text = path.read_text()
    assert set(re.findall(r"\{\{\s*(\w+)\s*\}\}", text)) <= PLACEHOLDERS
    assert rule["catalog_name"] == "{{catalog}}" and rule["schema_name"] == "{{schema}}"
    assert rule["batch"]["warehouse_id"] == "{{warehouse_id}}"
    assert rule["severity"] in SEVERITIES
    assert rule["fidelity"] in FIDELITIES
    assert rule["description"].strip() and rule["objective"].strip()
    assert rule["schedule"]["enabled"] is False, "ship rules disabled; deploy.py --enable turns them on"
    assert re.fullmatch(r"\d+[mhd]", rule["schedule"]["at_least_every"])
    assert re.fullmatch(r"\d+[mhd]", rule["timerange"]["extend_lookback"])


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.stem)
def test_query_uses_the_run_window(path: Path):
    """Every rule scopes its scan with IN_TIMERANGE (backfill, the Query page and late events all
    depend on it) and never anchors on the wall clock."""
    query = load(path)["batch"]["sql"]["query"]
    assert "IN_TIMERANGE(" in query
    assert not re.search(r"\bcurrent_(timestamp|date)\s*\(", query, re.I), "use TIMERANGE_NOW(), not now()"
    assert ":start_time" not in query and ":end_time" not in query
    assert not re.search(r"\b(FROM|JOIN)\s+system\.access\.audit\b", query, re.I), \
        "read {{audit_table}} so the rule can run on a test table"


def test_setup_grants_every_system_table_the_rules_read():
    """SETUP.md step 7.6 grants the run-as service principal SELECT on each system table a rule reads;
    a rule that reads one more would fail at run time under the service principal."""
    read = set()
    for p in RULES:
        query = load(p)["batch"]["sql"]["query"]
        read |= {m.lower() for m in re.findall(r"\b(?:FROM|JOIN)\s+(system\.\w+\.\w+)", query, re.I)}
    read.add("system.access.audit")  # every rule reads it through {{audit_table}}
    setup = (ROOT / "lakewatch" / "SETUP.md").read_text()
    granted = {m.lower() for m in re.findall(r"GRANT SELECT\s+ON TABLE\s+(system\.\w+\.\w+)", setup)}
    assert read <= granted, f"add GRANTs to SETUP.md step 7.6 for: {sorted(read - granted)}"


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.stem)
def test_mitre_mapping(path: Path):
    for m in load(path).get("mitre") or []:
        assert m["taxonomy"] == "Enterprise"
        assert m["tactic"] in TACTICS, m
        assert re.fullmatch(r"T\d{4}", m["technique_id"]), m
        assert m["technique"].strip()
        if "sub_technique_id" in m:
            assert re.fullmatch(r"T\d{4}\.\d{3}", m["sub_technique_id"]), m


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.stem)
def test_output_context(path: Path):
    """Signals carry the same keys across rules, so correlation and triage can join on them."""
    out = load(path)["output"]
    assert out["event_time_column"]
    assert "actor" in out["context"], "every signal names the identity in context.actor"
    for key in re.findall(r"\{(\w+)\}", out["summary"]):
        assert key in {v.strip("{}") for v in out["context"].values()} | set(out["context"]), key


def test_deploy_hash_ignores_enabled_state_and_run_as():
    import importlib.util
    spec = importlib.util.spec_from_file_location("lw_deploy", Path(__file__).resolve().parents[1] / "deploy.py")
    deploy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deploy)
    rule = {"rule_name": "r", "schedule": {"at_least_every": "1h", "enabled": False}, "batch": {"sql": {"query": "x"}}}
    moved = {**rule, "schedule": {**rule["schedule"], "enabled": True}, "run_as_principal": "sp-app-id"}
    assert deploy.content_hash(rule) == deploy.content_hash(moved)
    assert deploy.content_hash(rule) != deploy.content_hash({**rule, "batch": {"sql": {"query": "y"}}})


def test_prune_disables_by_default_and_documents_alert_loss():
    text = (Path(__file__).resolve().parents[1] / "deploy.py").read_text()
    assert '"--prune-delete"' in text and "deletes their alerts" in text
    prune_block = text[text.index("if a.prune or a.prune_delete:"):]
    assert prune_block.index('"enabled": False') > 0 and "if a.prune_delete:" in prune_block
