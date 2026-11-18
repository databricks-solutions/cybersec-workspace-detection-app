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
    assert "system.access.audit" not in query, "read {{audit_table}} so the rule can run on a test table"


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
