import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from auditdemo.background import SECRET_SCOPES, background
from auditdemo.rows import event
from auditdemo.schema import COLUMNS
from auditdemo.world import World

PROFILE = json.loads((Path(__file__).resolve().parents[1] / "profile" / "profile.json").read_text())
START = datetime(2026, 11, 2, 9, 30, tzinfo=timezone.utc)  # a Monday
END = START + timedelta(days=8)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SENSITIVE = {
    ("secrets", "listScopes"), ("secrets", "listSecrets"), ("secrets", "getSecret"),
    ("unityCatalog", "createFunction"), ("unityCatalog", "deleteFunction"),
    ("workspace", "workspaceExport"), ("accounts", "generateDbToken"),
    ("accounts", "addPrincipalToGroup"), ("accounts", "IpAccessDenied"),
    ("clusters", "create"), ("jobs", "submitRun"), ("databrickssql", "startWarehouse"),
}
DISCOVERY = {
    ("secrets", "listScopes"), ("secrets", "listSecrets"), ("unityCatalog", "listMetastores"),
    ("unityCatalog", "listCatalogs"), ("unityCatalog", "listSchemas"), ("unityCatalog", "listExternalLocations"),
    ("unityCatalog", "listStorageCredentials"), ("repos", "listRepos"),
    ("accountsManager", "listWorkspaceConfigurations"), ("accountsManager", "listNetworkConfigurations"),
    ("accountsManager", "listStorageConfigurations"),
}
SENSITIVE |= DISCOVERY


@pytest.fixture(scope="module", params=[(42, 1), (7, 2), (3, 3)], ids=lambda p: f"world{p[0]}")
def world_seed(request):
    return request.param


@pytest.fixture(scope="module")
def world(world_seed):
    return World(world_seed[0])


@pytest.fixture(scope="module")
def rows(world, world_seed):
    return list(background(world, PROFILE, START, END, seed=world_seed[1], scale=0.03))


def _who(world):
    return {p.email: p for p in world.principals}


def test_event_row_has_all_columns():
    w = World(1)
    row = event(w, w.principals[0], START, "secrets", "listScopes", {},
                ip="10.20.0.1", user_agent="x", workspace=next(iter(w.workspaces.values())))
    assert list(row) == [n for n, _ in COLUMNS]
    assert row["user_identity"]["email"] == w.principals[0].email
    assert row["account_id"] == w.account_id
    assert UUID_RE.match(row["event_id"]) and UUID_RE.match(row["request_id"])


def test_event_date_is_utc_date():
    w = World(1)
    p = w.principals[0]
    ws = next(iter(w.workspaces.values()))
    a = event(w, p, datetime(2026, 11, 11, 23, 59, 59, tzinfo=timezone.utc), "s", "a", {},
              ip="192.0.2.1", user_agent="", workspace=ws)
    b = event(w, p, datetime(2026, 11, 12, 0, 0, 0, tzinfo=timezone.utc), "s", "a", {},
              ip="192.0.2.1", user_agent="", workspace=ws)
    assert str(a["event_date"]) == "2026-11-11"
    assert str(b["event_date"]) == "2026-11-12"


def test_background_volume(world):
    n = sum(1 for _ in background(world, PROFILE, datetime(2026, 11, 3, tzinfo=timezone.utc),
                                  datetime(2026, 11, 4, tzinfo=timezone.utc), seed=1))
    assert 100_000 <= n <= 150_000


def test_background_deterministic(world):
    s, e = START, START + timedelta(days=2)
    a = list(background(world, PROFILE, s, e, seed=5, scale=0.02))
    b = list(background(world, PROFILE, s, e, seed=5, scale=0.02))
    c = list(background(world, PROFILE, s, e, seed=6, scale=0.02))
    assert a == b
    assert a != c


def test_background_only_profile_actions(rows):
    known = {(a["service_name"], a["action_name"]) for a in PROFILE["actions"]}
    assert {(r["service_name"], r["action_name"]) for r in rows} <= known
    assert all(START <= r["event_time"] < END for r in rows)


def test_background_hours(rows, world):
    who = _who(world)
    day = Counter(r["event_time"].hour for r in rows if who[r["user_identity"]["email"]].kind == "user")
    assert sum(day[h] for h in range(8, 19)) > 2 * sum(day[h] for h in range(0, 6))


def test_background_has_no_attacker_ips(rows):
    for r in rows:
        ip = r["source_ip_address"]
        assert not (ip.startswith("203.0.113.") or ip.startswith("198.51.100."))


def test_param_keys_follow_profile(rows):
    allowed = defaultdict(set)
    for a in PROFILE["actions"]:
        allowed[(a["service_name"], a["action_name"])] |= set(a["param_keys"])
    for r in rows:
        assert set(r["request_params"]) <= allowed[(r["service_name"], r["action_name"])], r["action_name"]


def test_no_first_seen_sensitive_after_day0(rows):
    first = {}
    for r in sorted(rows, key=lambda r: r["event_time"]):
        k = (r["user_identity"]["email"], r["service_name"], r["action_name"])
        first.setdefault(k, r["event_time"])
    seen = {k[1:] for k in first}
    in_profile = {(a["service_name"], a["action_name"]) for a in PROFILE["actions"]}
    assert (SENSITIVE - {("accounts", "IpAccessDenied")}) & in_profile <= seen
    limit = datetime.combine(START.date() + timedelta(days=2), datetime.min.time(), tzinfo=timezone.utc)
    for (actor, svc, act), t in first.items():
        if (svc, act) in SENSITIVE:
            assert t < limit, (actor, svc, act, t)


def test_no_ip_access_denied_in_background(rows):
    assert not [r for r in rows if r["action_name"] == "IpAccessDenied"]


def test_no_discovery_burst(world):
    rs = list(background(world, PROFILE, START, START + timedelta(days=1), seed=3, scale=0.5))
    by = defaultdict(list)
    for r in rs:
        if (r["service_name"], r["action_name"]) in DISCOVERY:
            by[r["user_identity"]["email"]].append((r["event_time"], r["service_name"] + "." + r["action_name"]))
    assert by
    for actor, ev in by.items():
        ev.sort()
        j = 0
        for i in range(len(ev)):
            while ev[i][0] - ev[j][0] > timedelta(seconds=60):
                j += 1
            assert len({n for _, n in ev[j:i + 1]}) < 5, actor


def test_pat_only_from_home_ips(rows, world):
    owner = {t: p for p in world.principals for t in p.pat_ids}
    n = 0
    for r in rows:
        if r["action_name"] == "tokenLogin":
            p = owner[r["request_params"]["tokenId"]]
            assert r["user_identity"]["email"] == p.email
            assert r["source_ip_address"] in p.home_ips
            n += 1
    assert n > 0
    # every (pat, home ip) pair is seen on day 0
    day0 = {(r["request_params"]["tokenId"], r["source_ip_address"]) for r in rows
            if r["action_name"] == "tokenLogin" and r["event_date"] == START.date()}
    assert {(t, ip) for t, p in owner.items() for ip in p.home_ips} <= day0
    # SP and user OAuth sign-ins also come from home IPs
    who = _who(world)
    for r in rows:
        if r["action_name"] == "oidcTokenAuthorization":
            assert r["source_ip_address"] in who[r["user_identity"]["email"]].home_ips


def test_sp_single_oauth_user_agent(rows, world):
    who = _who(world)
    uas = defaultdict(set)
    for r in rows:
        if who[r["user_identity"]["email"]].kind == "sp":
            uas[r["user_identity"]["email"]].add(r["user_agent"])
    assert uas and all(len(v) == 1 for v in uas.values())


def test_no_function_create_delete_same_name_2h(rows):
    creates = defaultdict(list)
    per_hour = Counter()
    for r in rows:
        if r["action_name"] == "createFunction":
            info = json.loads(r["request_params"]["function_info"])
            full = f'{info["catalog_name"]}.{info["schema_name"]}.{info["name"]}'
            creates[full].append(r["event_time"])
            per_hour[(r["user_identity"]["email"], r["event_time"].replace(minute=0, second=0, microsecond=0))] += 1
            assert r["audit_level"] == "ACCOUNT_LEVEL" and r["workspace_id"] == "0"
            assert {"workspace_id", "metastore_id"} <= set(r["request_params"])
    assert creates and max(per_hour.values()) <= 2
    n_del = 0
    for r in rows:
        if r["action_name"] == "deleteFunction":
            n_del += 1
            assert r["audit_level"] == "ACCOUNT_LEVEL"
            for t in creates.get(r["request_params"]["full_name_arg"], []):
                assert not (timedelta(0) <= r["event_time"] - t < timedelta(hours=2))
    assert n_del > 0


def test_no_sensitive_export_paths(rows):
    bad = re.compile(r"(?i)/(init[-_]?scripts?|config|secrets?)/")
    paths = [r["request_params"]["notebookFullPath"] for r in rows if r["action_name"] == "workspaceExport"]
    assert paths and not [p for p in paths if bad.search(p + "/")]


def test_session_id_single_ip_ua(rows, world):
    who = _who(world)
    pairs = defaultdict(set)
    users = defaultdict(set)
    for r in rows:
        sid = r["session_id"]
        if sid:
            pairs[sid].add((r["source_ip_address"], r["user_agent"]))
            users[sid].add((r["user_identity"]["email"], r["event_date"]))
            assert who[r["user_identity"]["email"]].kind == "user"
            assert r["user_agent"].startswith("Mozilla")
            assert r["audit_level"] == "WORKSPACE_LEVEL"
            assert r["action_name"] not in ("tokenLogin", "oidcTokenAuthorization")
    assert pairs
    assert all(len(v) == 1 for v in pairs.values())
    assert all(len(v) == 1 for v in users.values())


def test_secrets_habits(rows, world):
    scopes = defaultdict(set)
    for r in rows:
        if r["service_name"] == "secrets":
            assert r["response"]["status_code"] in (200, 3002)
            if "scope" in r["request_params"]:
                scopes[r["user_identity"]["email"]].add(r["request_params"]["scope"])
    ci = world.get("sp-ci-deploy").email
    for actor, s in scopes.items():
        if actor != ci:
            assert len(s) <= 1, actor
    assert scopes[ci] == set(SECRET_SCOPES)


def test_ci_nightly_scope_listing(rows, world):
    ci = world.get("sp-ci-deploy").email
    runs = [r["event_time"] for r in rows if r["user_identity"]["email"] == ci and r["action_name"] == "listScopes"]
    assert len(runs) >= 7
    tod = (END - timedelta(hours=4))
    assert {(t.hour, t.minute) for t in runs} == {(tod.hour, tod.minute)}
    assert not [t for t in runs if t >= END - timedelta(hours=4)]  # the last run belongs to decoy D1
    assert START.date() + timedelta(days=1) >= min(runs).date()


def test_named_principals(rows, world):
    maria, etl, rep = (world.get(n).email for n in ("maria.lopez@corp.example", "sp-etl-prod", "sp-reporting"))
    for r in rows:
        a, e = r["action_name"], r["user_identity"]["email"]
        if e == maria:
            assert a not in ("listScopes", "listSecrets", "createFunction", "deleteFunction", "workspaceExport")
        if e == etl:
            assert a not in ("createFunction", "addPrincipalToGroup")
        assert a not in ("setAdmin", "updatePermissionAssignment")
    assert any(r["user_identity"]["email"] == world.get("tom.becker@corp.example").email for r in rows)


def test_group_changes_only_admin_users(rows, world):
    admins = {p.email for p in world.principals if p.kind == "user" and p.role == "admin"}
    n = 0
    for r in rows:
        if r["action_name"] == "addPrincipalToGroup":
            n += 1
            assert r["user_identity"]["email"] in admins
            assert r["request_params"]["targetGroupName"] not in ("admins", "workspace-admins")
            assert r["audit_level"] == "ACCOUNT_LEVEL" and r["workspace_id"] == "0"
    assert n > 0


def test_generate_token_from_home_ips(rows, world):
    who = _who(world)
    n = 0
    for r in rows:
        if r["action_name"] == "generateDbToken":
            n += 1
            assert r["source_ip_address"] in who[r["user_identity"]["email"]].home_ips
    assert n > 0


def test_no_failed_compute_creation(rows):
    for r in rows:
        if r["action_name"] in ("create", "submitRun") and r["service_name"] in ("clusters", "jobs"):
            assert r["response"]["status_code"] == 200


def test_auth_method_values_and_day0_coverage(rows):
    allowed = {"tokenLogin": {"API_INT_PAT_TOKEN", "API_EXT_PAT_TOKEN"}, "oidcTokenAuthorization": {"API_OIDC_TOKEN"}}
    day0, later = set(), set()
    for r in rows:
        a = r["action_name"]
        if a in allowed:
            m = r["request_params"]["authenticationMethod"]
            assert m in allowed[a]
            pair = (r["request_params"]["tokenId"], r["source_ip_address"], m)
            (day0 if r["event_date"] == START.date() else later).add(pair)
    assert {m for _, _, m in day0 | later} >= {"API_INT_PAT_TOKEN", "API_EXT_PAT_TOKEN", "API_OIDC_TOKEN"}
    assert later <= day0  # each (token, source) keeps one method, all seen on day 0
    by = defaultdict(set)
    for t, ip, m in day0 | later:
        by[(t, ip)].add(m)
    assert all(len(v) == 1 for v in by.values())
