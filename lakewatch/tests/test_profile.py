import json
import re
from pathlib import Path

PROFILE = Path(__file__).resolve().parents[1] / "profile" / "profile.json"

TOP_KEYS = {"window_days", "workspaces", "actions", "user_agents"}
ACTION_KEYS = {
    "service_name", "action_name", "audit_level", "actor_kind", "status_class",
    "hourly", "per_actor_per_day", "param_keys", "status_codes",
}
EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[a-z]{2,}", re.I)
IPV4 = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

SCENARIO_ACTIONS = [
    ("accounts", "tokenLogin"),
    ("accounts", "oidcTokenAuthorization"),
    ("accounts", "IpAccessDenied"),
    ("accounts", "addPrincipalToGroup"),
    ("accounts", "generateDbToken"),
    ("secrets", "listScopes"),
    ("secrets", "listSecrets"),
    ("secrets", "getSecret"),
    ("unityCatalog", "listCatalogs"),
    ("unityCatalog", "listExternalLocations"),
    ("unityCatalog", "listStorageCredentials"),
    ("unityCatalog", "createFunction"),
    ("unityCatalog", "deleteFunction"),
    ("repos", "listRepos"),
    ("workspace", "workspaceExport"),
    ("clusters", "create"),
    ("jobs", "submitRun"),
    ("jobs", "runNow"),
    ("databrickssql", "startWarehouse"),  # real service/action name, see facts.md
    ("notebook", "importNotebook"),
]


def _strings(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)
    elif isinstance(node, str):
        yield node


def _load():
    return json.loads(PROFILE.read_text())


def test_profile_has_no_identities():
    data = _load()
    assert set(data) == TOP_KEYS
    assert isinstance(data["window_days"], int) and isinstance(data["workspaces"], int)
    for a in data["actions"]:
        assert set(a) == ACTION_KEYS
        assert len(a["hourly"]) == 24
        assert abs(sum(a["hourly"]) - 1.0) < 0.01
        assert a["actor_kind"] in ("user", "sp")
    for s in _strings(data):
        assert not EMAIL.search(s), s
        assert not IPV4.search(s), s
        assert not UUID.search(s), s


def test_profile_covers_scenario_actions():
    have = {(a["service_name"], a["action_name"]) for a in _load()["actions"]}
    missing = [x for x in SCENARIO_ACTIONS if x not in have]
    assert not missing, missing
