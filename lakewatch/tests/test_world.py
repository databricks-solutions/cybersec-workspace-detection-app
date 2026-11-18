import ipaddress
import re
from datetime import datetime, timedelta, timezone

import pytest

from auditdemo.world import World

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ANCHOR = datetime(2026, 11, 12, 9, 30, tzinfo=timezone.utc)


def test_world_is_deterministic():
    a, b = World(7), World(7)
    assert a.account_id == b.account_id
    assert a.workspaces == b.workspaces
    assert a.principals == b.principals
    assert World(8).principals != a.principals


def test_counts():
    w = World(1)
    users = [p for p in w.principals if p.kind == "user"]
    sps = [p for p in w.principals if p.kind == "sp"]
    assert 35 <= len(users) <= 45
    assert len(sps) == 8
    assert set(w.workspaces) == {"prod", "dev", "analytics"}
    assert all(re.fullmatch(r"\d{16}", v) for v in w.workspaces.values())
    assert len(set(w.workspaces.values())) == 3
    assert UUID_RE.match(w.account_id)
    assert len({p.email for p in w.principals}) == len(w.principals)


def test_sp_identity_form():
    w = World(1)
    for p in w.principals:
        if p.kind == "sp":
            assert UUID_RE.match(p.email)
            assert p.display_name.startswith("sp-")
        else:
            assert p.email.endswith("@corp.example")
            assert not UUID_RE.match(p.email)


def test_named_principals_exist():
    w = World(1)
    assert w.get("sp-etl-prod").role == "etl"
    assert w.get("sp-reporting").role == "reporting"
    assert w.get("sp-ci-deploy").role == "ci"
    assert w.get("sp-ml-batch").role == "ml"
    assert w.get("maria.lopez@corp.example").role == "data_engineer"
    assert w.get("Maria Lopez").email == "maria.lopez@corp.example"
    assert w.get("tom.becker@corp.example").role == "analyst"
    assert w.get("ana.silva@corp.example").role == "admin"
    assert {p.role for p in w.principals if p.kind == "sp"} >= {"ci", "etl", "bi", "ml", "reporting"}
    assert w.by_role("admin")
    with pytest.raises(KeyError):
        w.get("nobody")


def test_home_ips_and_tokens():
    w = World(1)
    nets = {k: ipaddress.ip_network(v) for k, v in w.ip_ranges.items()}
    assert set(nets) == {"corp", "vpn", "ci", "cloud"}
    for p in w.principals:
        assert p.home_ips and p.workspaces
        assert set(p.workspaces) <= set(w.workspaces.values())
        for ip in p.home_ips:
            addr = ipaddress.ip_address(ip)
            if p.kind == "user":
                assert addr in nets["corp"] or addr in nets["vpn"]
            elif p.role == "ci":
                assert addr in nets["ci"]
            else:
                assert addr in nets["cloud"]
        for t in p.pat_ids:
            assert re.fullmatch(r"[0-9a-f]{32}", t)
    assert all(1 <= len(p.pat_ids) <= 2 for p in w.principals if p.kind == "sp")
    assert all(p.pat_ids for p in w.by_role("data_engineer") + w.by_role("admin"))


def test_attacker_ips_rotate_per_anchor():
    w = World(1)
    a = w.attacker_ips(ANCHOR)
    assert a == w.attacker_ips(ANCHOR + timedelta(minutes=20))  # same hour
    assert len(set(a)) == 4
    t1, t2 = ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("198.51.100.0/24")
    assert any(ipaddress.ip_address(x) in t1 for x in a)
    assert any(ipaddress.ip_address(x) in t2 for x in a)
    assert all(not x.endswith((".0", ".255")) for x in a)
    for h in range(1, 48):
        assert not set(a) & set(w.attacker_ips(ANCHOR + timedelta(hours=h)))
    homes = {ip for p in w.principals for ip in p.home_ips}
    nets = [ipaddress.ip_network(v) for v in w.ip_ranges.values()]
    for h in range(0, 48):
        for ip in w.attacker_ips(ANCHOR + timedelta(hours=h)):
            assert ip not in homes
            assert not any(ipaddress.ip_address(ip) in n for n in nets)
