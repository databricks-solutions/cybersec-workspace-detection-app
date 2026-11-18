import json
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

from auditdemo import scenarios
from auditdemo.world import World

ANCHOR = datetime(2026, 11, 12, 9, 30, tzinfo=timezone.utc)
MARIA = "maria.lopez@corp.example"
UA = "python-requests/2.32.3"


@pytest.fixture(scope="module")
def world():
    return World(7)


@pytest.fixture(scope="module")
def s1(world):
    return scenarios.ALL[0]


@pytest.fixture(scope="module")
def rows(world, s1):
    return s1.rows(world, ANCHOR)


def act(r):
    return f"{r['service_name']}.{r['action_name']}"


def first(rows, name):
    for r in rows:
        if act(r) == name:
            return r
    raise AssertionError(name)


def test_framework(world, s1):
    assert s1.key == "S1" and [s.key for s in scenarios.ALL][0] == "S1"
    sp = world.get("sp-etl-prod")
    assert s1.actors(world) == {MARIA, sp.email}
    assert s1.forbidden_rules == set()
    assert {"ada_pat_new_source_ip", "ada_short_lived_function", "ada_identity_pivot_chain",
            "ada_multi_stage_identity", "ada_sp_grants_admin"} <= s1.expected_rules
    assert len({r for r in s1.expected_rules if r.startswith("ada_")}) == 13
    assert {r for r in s1.expected_rules if r.startswith("adp_")} == {
        "adp_secrets_enumeration", "adp_workspace_content_exported", "adp_user_admin_account_change"}


def test_deterministic(world, s1, rows):
    assert s1.rows(world, ANCHOR) == rows


def test_s1_order(world, rows):
    sp = world.get("sp-etl-prod").email
    order = [
        first(rows, "accounts.tokenLogin"),
        first(rows, "secrets.listScopes"),
        first(rows, "secrets.getSecret"),
        first(rows, "accounts.oidcTokenAuthorization"),
        first(rows, "unityCatalog.createFunction"),
        first(rows, "accounts.addPrincipalToGroup"),
        first(rows, "accounts.generateDbToken"),
        first(rows, "workspace.workspaceExport"),
        first(rows, "unityCatalog.deleteFunction"),
    ]
    times = [r["event_time"] for r in order]
    assert times == sorted(times) and len(set(times)) == len(times)
    assert all(ANCHOR - timedelta(hours=3) <= r["event_time"] <= ANCHOR - timedelta(hours=1, minutes=30) for r in rows)
    assert {r["user_identity"]["email"] for r in rows} == {MARIA, sp}
    assert first(rows, "accounts.tokenLogin")["event_time"] == ANCHOR - timedelta(hours=3)
    assert first(rows, "accounts.oidcTokenAuthorization")["event_time"] == ANCHOR - timedelta(hours=2)
    assert first(rows, "accounts.addPrincipalToGroup")["event_time"] == ANCHOR - timedelta(hours=1, minutes=50)


def test_s1_access(world, rows):
    maria = world.get(MARIA)
    ip = world.attacker_ips(ANCHOR)[0]
    logins = [r for r in rows if act(r) == "accounts.tokenLogin"]
    assert len(logins) >= 2
    for r in logins:
        p = r["request_params"]
        assert p["authenticationMethod"] == "API_EXT_PAT_TOKEN"
        assert p["tokenId"] == maria.pat_ids[0] and p["user"] == MARIA
        assert r["source_ip_address"] == ip and r["user_agent"] == UA and r["session_id"] is None


def test_s1_discovery_burst(rows):
    disc = {"secrets.listScopes", "unityCatalog.listCatalogs", "unityCatalog.listExternalLocations",
            "unityCatalog.listStorageCredentials", "repos.listRepos", "unityCatalog.listSchemas"}
    mine = [r for r in rows if r["user_identity"]["email"] == MARIA and act(r) in disc]
    t0 = first(rows, "secrets.listScopes")["event_time"]
    win = {act(r) for r in mine if t0 <= r["event_time"] < t0 + timedelta(seconds=60)}
    assert len(win) >= 5


def test_s1_harvest(rows):
    maria = [r for r in rows if r["user_identity"]["email"] == MARIA]
    gets = [r for r in maria if act(r) == "secrets.getSecret"]
    assert len({r["request_params"]["scope"] for r in gets}) == 3
    lists = [r for r in maria if act(r) == "secrets.listSecrets"]
    assert len({r["request_params"]["scope"] for r in lists}) == 3
    assert max(r["event_time"] for r in gets) - first(rows, "secrets.listScopes")["event_time"] <= timedelta(minutes=15)
    denied = [r for r in gets if r["response"]["status_code"] == 1004]
    assert len(denied) == 1
    d = denied[0]
    assert d["request_params"]["use_simplified_error_handling"] == "true"
    key = d["request_params"]["key"]
    ok = [r for r in gets if r["response"]["status_code"] == 200 and r["request_params"]["key"] == key
          and r["request_params"]["scope"] != d["request_params"]["scope"] and r["event_time"] > d["event_time"]]
    assert ok
    assert all(r["session_id"] is None for r in maria)


def test_s1_harvest_is_per_scope(rows):
    # listScopes, then for each scope: listSecrets(scope) -> getSecret(scope). Not all lists before all reads.
    harvest_start = [r for r in rows if act(r) == "secrets.listScopes"][-1]["event_time"]
    calls = [(r["action_name"], r["request_params"]["scope"]) for r in rows
             if r["user_identity"]["email"] == MARIA and r["event_time"] > harvest_start
             and act(r) in ("secrets.listSecrets", "secrets.getSecret")]
    assert calls == [("listSecrets", "ci-deploy"), ("getSecret", "ci-deploy"),
                     ("listSecrets", "shared-infra"), ("getSecret", "shared-infra"),
                     ("listSecrets", "etl-prod"), ("getSecret", "etl-prod")]


def test_s1_shared_ip(world, rows):
    sp = world.get("sp-etl-prod").email
    ip = world.attacker_ips(ANCHOR)[0]
    assert {r["source_ip_address"] for r in rows} == {ip}
    sp_rows = [r for r in rows if r["user_identity"]["email"] == sp]
    assert sp_rows
    oidc = first(rows, "accounts.oidcTokenAuthorization")
    assert oidc["user_agent"] == "curl/8.7.1" and oidc["request_params"]["authenticationMethod"] == "API_OIDC_TOKEN"
    after = [r for r in sp_rows if timedelta(0) < r["event_time"] - oidc["event_time"] <= timedelta(seconds=60)]
    assert after


def test_s1_function_rows_account_level(world, rows):
    creates = [r for r in rows if act(r) == "unityCatalog.createFunction"]
    assert len(creates) == 3
    assert max(r["event_time"] for r in creates) - min(r["event_time"] for r in creates) < timedelta(hours=1)
    names = []
    for r in creates + [first(rows, "unityCatalog.deleteFunction")]:
        assert r["audit_level"] == "ACCOUNT_LEVEL" and r["workspace_id"] == "0"
        assert r["request_params"]["workspace_id"] in world.workspaces.values()
        assert r["request_params"]["metastore_id"]
        assert r["session_id"] is None
    for r in creates:
        info = json.loads(r["request_params"]["function_info"])
        assert info["name"] and info["catalog_name"] and info["schema_name"] and info["routine_definition"]
        names.append(f'{info["catalog_name"]}.{info["schema_name"]}.{info["name"]}')
    assert len(set(names)) == 3
    assert first(rows, "unityCatalog.deleteFunction")["request_params"]["full_name_arg"] in names


def test_s1_persistence(world, rows):
    g = first(rows, "accounts.addPrincipalToGroup")["request_params"]
    assert g["targetGroupName"] == "admins" and g["targetUserName"] == "svc-backup@corp.example"
    assert all(p.email != g["targetUserName"] for p in world.principals)
    assert first(rows, "accounts.addPrincipalToGroup")["audit_level"] == "ACCOUNT_LEVEL"
    assert first(rows, "accounts.generateDbToken")["user_identity"]["email"] == world.get("sp-etl-prod").email


def test_s1_export_init_script(rows):
    r = first(rows, "workspace.workspaceExport")
    p = r["request_params"]
    assert p["notebookFullPath"].startswith("/Workspace/init-scripts/")
    assert p["workspaceExportFormat"] == "SOURCE" and p["workspaceExportDirectDownload"] == "true"


# ---- Task 6: S2, S3, S4, D1, D2
from auditdemo.background import BROWSERS, background, ci_nightly_calls  # noqa: E402

PROFILE = json.loads((Path(__file__).resolve().parents[1] / "profile" / "profile.json").read_text())
KEYS = {s.key: s for s in scenarios.ALL}
ADA_ALL = {r for r in KEYS["S1"].expected_rules if r.startswith("ada_")} | {"ada_ip_denied_after_auth", "ada_session_reuse_new_ip_ua",
                                            "ada_compute_fallback"}


def test_all_order():
    assert [s.key for s in scenarios.ALL] == ["S1", "S2", "S3", "S4", "D1", "D2"]
    assert len(ADA_ALL) == 16


def test_expected_and_forbidden_sets():
    assert KEYS["S2"].expected_rules == {"ada_ip_denied_after_auth", "adp_attempted_login_from_denied_ip"}
    assert KEYS["S3"].expected_rules == {"ada_session_reuse_new_ip_ua", "ada_sensitive_export",
                                         "adp_workspace_content_exported"}
    assert KEYS["S4"].expected_rules == {"ada_compute_fallback"}
    for k in ("S2", "S3", "S4"):
        assert KEYS[k].forbidden_rules == set()
    assert KEYS["D1"].expected_rules == {"adp_secrets_enumeration"}
    assert KEYS["D1"].forbidden_rules == ADA_ALL
    assert KEYS["D2"].expected_rules == set() and KEYS["D2"].forbidden_rules == ADA_ALL


def test_expected_ported_rules_exist():
    from auditdemo import rules
    ported = {r for s in scenarios.ALL for r in s.expected_rules if r.startswith("adp_")}
    assert ported and ported <= set(rules.PORTED_RULES)
    assert all(not r.startswith("adp_") for s in scenarios.ALL for r in s.forbidden_rules)


def test_all_deterministic_and_sorted(world):
    for s in scenarios.ALL:
        a = s.rows(world, ANCHOR)
        assert a == s.rows(world, ANCHOR) and a
        assert [r["event_time"] for r in a] == sorted(r["event_time"] for r in a)


def test_s2_replay(world):
    s = KEYS["S2"]
    sp = world.get("sp-reporting")
    assert s.actors(world) == {sp.email}
    rows = s.rows(world, ANCHOR)
    ip = world.attacker_ips(ANCHOR)[1]
    assert {r["source_ip_address"] for r in rows} == {ip}
    assert {r["user_identity"]["email"] for r in rows} == {sp.email}
    oidc = first(rows, "accounts.oidcTokenAuthorization")
    assert oidc["request_params"]["authenticationMethod"] == "API_OIDC_TOKEN"
    assert oidc["response"]["status_code"] == 200
    assert oidc["event_time"] == ANCHOR - timedelta(hours=5)
    denied = [r for r in rows if act(r) == "accounts.IpAccessDenied"]
    assert {r["workspace_id"] for r in denied} == {world.workspaces["prod"], world.workspaces["analytics"]}
    for r in denied:
        assert r["response"]["status_code"] == 403 and r["audit_level"] == "WORKSPACE_LEVEL"
        assert set(r["request_params"]) == {"path", "user", "userId"} and r["request_params"]["user"] == sp.email
        assert timedelta(0) < r["event_time"] - oidc["event_time"] <= timedelta(minutes=10)


def test_s3_hijack(world):
    s = KEYS["S3"]
    tom = world.get("tom.becker@corp.example")
    assert s.actors(world) == {tom.email}
    rows = s.rows(world, ANCHOR)
    atk = world.attacker_ips(ANCHOR)[2]
    sess = {r["session_id"] for r in rows}
    assert len(sess) == 1 and None not in sess
    assert len({(r["source_ip_address"], r["user_agent"]) for r in rows}) == 2
    home = [r for r in rows if r["source_ip_address"] != atk]
    bad = [r for r in rows if r["source_ip_address"] == atk]
    assert home and bad and {r["source_ip_address"] for r in home} <= set(tom.home_ips)
    assert len({r["user_agent"] for r in rows}) == 2
    assert min(r["event_time"] for r in bad) - min(r["event_time"] for r in home) <= timedelta(minutes=20)
    assert min(r["event_time"] for r in home) == ANCHOR - timedelta(hours=6)
    assert max(r["event_time"] for r in home) < min(r["event_time"] for r in bad)
    exports = [r for r in rows if act(r) == "workspace.workspaceExport"]
    assert len(exports) == 4 and all(r["source_ip_address"] == atk for r in exports)
    for r in exports:
        p = r["request_params"]
        assert p["workspaceExportFormat"] == "SOURCE" and p["workspaceExportDirectDownload"] == "true"
    paths = [r["request_params"]["notebookFullPath"] for r in exports]
    assert any(p.startswith("/Workspace/Users/tom.becker@corp.example/") for p in paths)
    assert any(p.startswith("/Workspace/Shared/finance/") for p in paths)
    assert not [r for r in home if act(r) == "workspace.workspaceExport"]
    assert all(r["user_agent"] in BROWSERS for r in rows)


def test_s4_fallback(world):
    s = KEYS["S4"]
    sp = world.get("sp-ml-batch")
    assert s.actors(world) == {sp.email}
    rows = s.rows(world, ANCHOR)
    create, submit = first(rows, "clusters.create"), first(rows, "jobs.submitRun")
    wh, run = first(rows, "databrickssql.startWarehouse"), first(rows, "jobs.runNow")
    assert create["response"]["status_code"] == 500
    assert "REQUEST_LIMIT_EXCEEDED" in create["response"]["error_message"]
    assert submit["response"]["status_code"] == 1004
    assert wh["response"]["status_code"] == 200 and run["response"]["status_code"] == 200
    assert set(wh["request_params"]) == {"id"} and set(run["request_params"]) == {"job_id", "job_parameters"}
    assert "serverless" in run["request_params"]["job_parameters"]
    assert max(create["event_time"], submit["event_time"]) < wh["event_time"] < run["event_time"]
    assert run["event_time"] - create["event_time"] <= timedelta(minutes=10)
    assert create["event_time"] == ANCHOR - timedelta(hours=4)
    allowed = set()
    for a in PROFILE["actions"]:
        if (a["service_name"], a["action_name"]) == ("clusters", "create"):
            allowed |= set(a["param_keys"])
    assert create["request_params"] and set(create["request_params"]) <= allowed


def test_d1_matches_nightly_background(world):
    ci = world.get("sp-ci-deploy")
    d1 = KEYS["D1"]
    assert d1.actors(world) == {ci.email}
    rows = d1.rows(world, ANCHOR)
    t0 = ANCHOR - timedelta(hours=4)
    assert [(r["event_time"] - t0).total_seconds() for r in rows] == [o for o, *_ in ci_nightly_calls()]
    assert [(r["service_name"], r["action_name"], r["request_params"]) for r in rows] == \
        [(s, a, p) for _, s, a, p in ci_nightly_calls()]
    assert not [r for r in rows if r["action_name"] == "getSecret"]
    bg = [r for r in background(world, PROFILE, ANCHOR - timedelta(days=3), ANCHOR, seed=1, scale=0.02)
          if r["user_identity"]["email"] == ci.email and r["action_name"] == "listScopes"]
    assert bg
    for r in rows:
        assert (r["source_ip_address"], r["workspace_id"], r["user_agent"]) == \
            (bg[0]["source_ip_address"], bg[0]["workspace_id"], bg[0]["user_agent"])
        assert r["session_id"] is None


def test_d2_onboarding(world):
    ana = world.get("ana.silva@corp.example")
    d2 = KEYS["D2"]
    assert ana.kind == "user" and d2.actors(world) == {ana.email}
    rows = d2.rows(world, ANCHOR)
    assert len(rows) == 5 and all(act(r) == "accounts.addPrincipalToGroup" for r in rows)
    assert {r["request_params"]["targetGroupName"] for r in rows} == {"data-eng"}
    assert all(r["request_params"]["targetUserName"].endswith("@corp.example") for r in rows)
    assert len({r["request_params"]["targetUserName"] for r in rows}) == 5
    assert rows[-1]["event_time"] - rows[0]["event_time"] <= timedelta(minutes=4)
    assert rows[0]["event_time"] == ANCHOR - timedelta(hours=2, minutes=30)
    assert all(r["audit_level"] == "ACCOUNT_LEVEL" and r["workspace_id"] == "0" for r in rows)


def test_scenarios_disjoint_actors(world):
    seen: dict[str, str] = {}
    for s in scenarios.ALL:
        for a in s.actors(world):
            assert a not in seen, (a, s.key, seen.get(a))
            seen[a] = s.key


def test_decoys_below_thresholds(world):
    assert world.get("ana.silva@corp.example").kind == "user"
    ci = world.get("sp-ci-deploy")
    nights = {r["event_time"].date() for r in background(world, PROFILE, ANCHOR - timedelta(days=14), ANCHOR,
                                                         seed=1, scale=0.02)
              if r["user_identity"]["email"] == ci.email and r["action_name"] == "listScopes"}
    assert len(nights) >= 13


def test_tom_never_exports_in_background():
    for seed in (7, 42, 3):
        w = World(seed)
        tom = w.get("tom.becker@corp.example").email
        rows = background(w, PROFILE, ANCHOR - timedelta(days=14), ANCHOR, seed=seed, scale=0.02)
        assert not [r for r in rows if r["user_identity"]["email"] == tom and r["action_name"] == "workspaceExport"]
