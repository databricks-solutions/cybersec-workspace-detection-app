"""The Genie space file built from the detection app's Genie Agent (genie-agent/ at the repository root)."""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

DEMO = Path(__file__).resolve().parents[1]
SPACE_FILE = DEMO / "genie" / "databricks_audit.geniespace.json"
HEX32 = re.compile(r"^[0-9a-f]{32}$")
PLACEHOLDER = "audit_demo_catalog.audit_demo."


@pytest.fixture(scope="module")
def space() -> dict:
    return json.loads(SPACE_FILE.read_text())


def _sqls(space: dict) -> list[str]:
    return ["".join(e["sql"]) for e in space["instructions"]["example_question_sqls"]]


def test_space_has_no_system_audit(space):
    text = json.dumps(space)
    assert "system.access.audit" not in text
    assert "system.query.history" not in text
    for sql in _sqls(space):
        assert "query.history" not in sql


def test_examples_sorted_ids(space):
    ids = [e["id"] for e in space["instructions"]["example_question_sqls"]]
    assert ids == sorted(ids)
    assert all(HEX32.match(i) for i in ids)
    all_ids = ids + [t["id"] for t in space["instructions"]["text_instructions"]]
    assert len(all_ids) == len(set(all_ids))
    assert len(space["instructions"]["text_instructions"]) == 1
    samples = [q["id"] for q in space.get("config", {}).get("sample_questions", [])]
    assert samples == sorted(samples) and all(HEX32.match(i) for i in samples)


def test_space_up_to_date():
    r = subprocess.run([sys.executable, str(DEMO / "genie" / "build_space.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_tables_are_demo_placeholders(space):
    ids = [t["identifier"] for t in space["data_sources"]["tables"]]
    assert ids == sorted(ids)
    assert ids == [PLACEHOLDER + t for t in ("audit", "demo_signals", "principals")]
    for t in space["data_sources"]["tables"]:
        cols = [c["column_name"] for c in t.get("column_configs", [])]
        assert cols == sorted(cols)


def test_sql_uses_quoted_placeholder(space):
    for sql in _sqls(space):
        assert "`audit_demo_catalog`.`audit_demo`." in sql, sql[:200]
        assert "${catalog}" not in sql and "${schema}" not in sql


def test_demo_examples_present(space):
    sql = "\n".join(_sqls(space))
    assert "demo_signals" in sql and "principals" in sql
    names = {e["question"][0] for e in space["instructions"]["example_question_sqls"]}
    assert any("shared" in n for n in names)
    assert any("after reading secrets" in n for n in names)
    text = "".join(space["instructions"]["text_instructions"][0]["content"])
    assert "demo_signals" in text and "principals" in text


def test_space_keeps_app_detections(space):
    names = {e["question"][0] for e in space["instructions"]["example_question_sqls"]}
    assert "detect_investigation_triage" in names and "detect_secrets_discovery" in names
    # these two read system.query.history, which the demo does not have
    assert not names & {"detect_data_movement_sql_queries", "detect_encoded_command_execution"}
    assert len(names) >= 30


def test_eval_set():
    items = yaml.safe_load((DEMO / "genie" / "eval.yaml").read_text())["questions"]
    assert 13 <= len(items) <= 18
    first = items[0]
    assert first["question"] == "Were we compromised in the last 90 days?"
    flat = {a.lower() for e in first["expect"] for a in ([e] if isinstance(e, str) else e)}
    assert {"maria.lopez", "sp-etl-prod"} <= flat
    for item in items:
        assert item["question"].strip() and item["expect"], item
        for e in item["expect"]:
            assert isinstance(e, str) or (isinstance(e, list) and e and all(isinstance(a, str) for a in e))


def test_retarget_rewrites_every_placeholder(space):
    sys.path.insert(0, str(DEMO))
    from genie_agent_retarget import parse_rules, retarget_space

    out, renamed = retarget_space(space, parse_rules({"audit_demo_catalog.audit_demo": "my-cat.demo"}))
    text = json.dumps(out)
    assert "audit_demo_catalog" not in text
    assert len(renamed) == 3
    sql = "".join("".join(e["sql"]) for e in out["instructions"]["example_question_sqls"])
    assert "`my-cat`.`demo`.`audit`" in sql and "`my-cat`.`demo`.`demo_signals`" in sql
