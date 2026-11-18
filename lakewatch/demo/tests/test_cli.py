"""The auditdemo command line: options and how they reach rules.deploy and load."""

from __future__ import annotations

import pytest

from auditdemo import cli, rules


@pytest.fixture
def deploy_calls(monkeypatch):
    calls = []

    class Api:
        def __init__(self, profile):
            pass

    monkeypatch.setattr("auditdemo.lakewatch.SdkApi", Api)
    monkeypatch.setattr(rules, "deploy", lambda api, sql, cfg, wh, enabled, **kw: calls.append((cfg, enabled, kw)))
    return calls


def test_rules_enable_does_not_wait_by_default(deploy_calls):
    assert cli.run(["rules", "--audit-table", "system.access.audit", "--enable", "--warehouse-id", "wh"]) == 0
    cfg, enabled, kw = deploy_calls[0]
    assert enabled is True and kw["expect"] == [] and kw["exclude"] == []
    assert cfg.table == "system.access.audit"


def test_rules_wait_uses_scenario_expectations(deploy_calls):
    assert cli.run(["rules", "--enable", "--wait", "--warehouse-id", "wh"]) == 0
    assert deploy_calls[0][2]["expect"] is None


@pytest.mark.parametrize("argv", [["--enable", "--wait", "--audit-table", "system.access.audit"],
                                  ["--wait"], ["--disable", "--wait"]])
def test_rules_wait_needs_enable_and_demo_table(deploy_calls, argv):
    assert cli.run(["rules", *argv, "--warehouse-id", "wh"]) == 2
    assert deploy_calls == []


def test_rules_exclude(deploy_calls):
    cli.run(["rules", "--enable", "--warehouse-id", "wh",
             "--exclude", "ada_sp_oauth_new_user_agent, adp_secrets_enumeration"])
    assert deploy_calls[0][2]["exclude"] == ["ada_sp_oauth_new_user_agent", "adp_secrets_enumeration"]


def test_load_has_no_seed_option():
    """check and reset always use the default seed, so load must too."""
    with pytest.raises(SystemExit):
        cli._parser().parse_args(["load", "--warehouse-id", "wh", "--seed", "7"])
    assert cli._parser().parse_args(["generate", "--out", "x", "--seed", "7"]).seed == 7


def test_load_uses_default_seed(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(cli, "generate", lambda anchor, days, seed, scale, scenarios: seen.setdefault("seed", seed) and iter([]))
    monkeypatch.setattr(cli, "write_parquet", lambda rows, d: [])
    monkeypatch.setattr("auditdemo.lakewatch.SdkApi", lambda profile: object())
    monkeypatch.setattr("auditdemo.load.load", lambda api, cfg, files, wh, seed=1337: seen.setdefault("load_seed", seed))
    assert cli.run(["load", "--warehouse-id", "wh"]) == 0
    assert seen == {"seed": 1337, "load_seed": 1337}
