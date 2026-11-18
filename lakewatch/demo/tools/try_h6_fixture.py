"""Offline guard for hunt 6 (hunts/h6_staged_intrusion.sql): run the 6a and 6b queries on the warehouse with
the audit and principals tables replaced by VALUES fixtures, and check which actors match.

  uv run --frozen python tools/try_h6_fixture.py --warehouse-id <id> [--profile some-profile]

6a must match the three harvest shapes (batched, interleaved per scope, re-listing the scopes in the middle)
and must not match the three near misses (5 x listCatalogs only, no successful read, reads 31 minutes
after the login: the pattern allows 30). 6b must match the
interleaved reader and the service principal on the same IP. Exit code 1 when a check fails.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

HUNT6 = Path(__file__).resolve().parents[1] / "hunts" / "h6_staged_intrusion.sql"
_IDENTIFIER = re.compile(r"IDENTIFIER\('`' \|\| :catalog \|\| '`\.`' \|\| :schema \|\| '`\.`(\w+)`'\)")
T = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)
UA = "python-requests/2.32.3"
SP = "6f1c2a9e-3b7d-4c55-9a10-2f8e4d6b7c01"
DISCOVERY = ["listScopes", "listCatalogs", "listExternalLocations", "listStorageCredentials", "listRepos",
             "listSchemas"]

# 6a cases: actor -> (expected match, ip)
CASES_6A = {
    "batched@corp.example": (True, "203.0.113.11"),
    "interleaved@corp.example": (True, "203.0.113.12"),
    "relisting@corp.example": (True, "203.0.113.13"),
    "same-discovery@corp.example": (False, "203.0.113.14"),
    "no-good-read@corp.example": (False, "203.0.113.15"),
    "late-reads@corp.example": (False, "203.0.113.16"),
}
IP_6B = "203.0.113.20"
READER_6B = "reader@corp.example"


def _rows() -> list[tuple]:
    """(seconds after T, actor, ip, action, scope, key, auth_method, token_id, status, acting_resource_type)."""
    rows: list[tuple] = []

    def add(s, actor, ip, action, scope=None, key=None, status=200, auth=None, token=None, kind=None):
        rows.append((s, actor, ip, action, scope, key, auth, token, status, kind))

    def login(s, actor, ip):
        add(s, actor, ip, "tokenLogin", auth="API_EXT_PAT_TOKEN", token=f"tok-{actor.split('@')[0]}")

    def burst(s, actor, ip, actions):
        for i, a in enumerate(actions):
            add(s + 7 * i, actor, ip, a)

    a, ip = "batched@corp.example", CASES_6A["batched@corp.example"][1]
    login(0, a, ip); burst(60, a, ip, DISCOVERY)
    add(300, a, ip, "listScopes")
    for i, sc in enumerate(("s1", "s2", "s3")):
        add(320 + 15 * i, a, ip, "listSecrets", sc)
    add(420, a, ip, "getSecret", "s1", "k1")
    add(460, a, ip, "getSecret", "s2", "k2", status=1004)
    add(495, a, ip, "getSecret", "s3", "k2")

    a, ip = "interleaved@corp.example", CASES_6A["interleaved@corp.example"][1]
    login(0, a, ip); burst(60, a, ip, DISCOVERY)
    add(300, a, ip, "listScopes")
    for i, (sc, k, st) in enumerate((("s1", "k1", 200), ("s2", "k2", 1004), ("s3", "k2", 200))):
        add(320 + 60 * i, a, ip, "listSecrets", sc)
        add(350 + 60 * i, a, ip, "getSecret", sc, k, status=st)

    a, ip = "relisting@corp.example", CASES_6A["relisting@corp.example"][1]
    login(0, a, ip); burst(60, a, ip, DISCOVERY)
    add(300, a, ip, "listScopes")
    add(320, a, ip, "listSecrets", "s1"); add(350, a, ip, "getSecret", "s1", "k1")
    add(380, a, ip, "listScopes"); add(390, a, ip, "listCatalogs")     # re-list and more discovery mid-harvest
    add(410, a, ip, "listSecrets", "s2"); add(440, a, ip, "getSecret", "s2", "k2")

    a, ip = "same-discovery@corp.example", CASES_6A["same-discovery@corp.example"][1]
    login(0, a, ip); burst(60, a, ip, ["listCatalogs"] * 5)            # 5 calls, but one kind only
    add(300, a, ip, "listScopes")
    for i, sc in enumerate(("s1", "s2")):
        add(320 + 60 * i, a, ip, "listSecrets", sc); add(350 + 60 * i, a, ip, "getSecret", sc, "k1")

    a, ip = "no-good-read@corp.example", CASES_6A["no-good-read@corp.example"][1]
    login(0, a, ip); burst(60, a, ip, DISCOVERY)
    add(300, a, ip, "listScopes")
    for i, sc in enumerate(("s1", "s2")):                               # every read is denied
        add(320 + 60 * i, a, ip, "listSecrets", sc); add(350 + 60 * i, a, ip, "getSecret", sc, "k1", status=1004)

    a, ip = "late-reads@corp.example", CASES_6A["late-reads@corp.example"][1]
    login(0, a, ip); burst(60, a, ip, DISCOVERY)
    add(300, a, ip, "listScopes")
    add(320, a, ip, "listSecrets", "s1"); add(335, a, ip, "listSecrets", "s2")
    add(31 * 60, a, ip, "getSecret", "s1", "k1"); add(31 * 60 + 30, a, ip, "getSecret", "s2", "k2")   # > 30 min

    # 6b: the reader lists and reads one scope at a time and re-lists the scopes, then a service principal
    # logs in from the same IP and creates a function.
    r = READER_6B
    login(0, r, IP_6B); add(60, r, IP_6B, "listScopes")
    add(80, r, IP_6B, "listSecrets", "s1"); add(100, r, IP_6B, "getSecret", "s1", "k1")
    add(120, r, IP_6B, "listScopes")
    add(140, r, IP_6B, "listSecrets", "s2"); add(160, r, IP_6B, "getSecret", "s2", "k2", status=1004)
    add(180, r, IP_6B, "listSecrets", "s3"); add(200, r, IP_6B, "getSecret", "s3", "k2")
    add(3600, SP, IP_6B, "oidcTokenAuthorization", auth="API_OIDC_TOKEN", token="sp-tok", kind="Service Principal")
    add(3620, SP, IP_6B, "listCatalogs", kind="Service Principal")
    add(3900, SP, IP_6B, "createFunction", kind="Service Principal")
    return rows


def _lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, int):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def fixture_ctes() -> str:
    values = []
    for s, actor, ip, action, scope, key, auth, token, status, kind in _rows():
        t = T + timedelta(seconds=s)
        values.append(f"(TIMESTAMP '{t.strftime('%Y-%m-%d %H:%M:%S')}+00:00', "
                      + ", ".join(_lit(v) for v in (actor, ip, action, scope, key, auth, token, status, kind)) + ")")
    principals = [(a, a.split("@")[0]) for a in CASES_6A] + [(READER_6B, "reader"), (SP, "sp-fixture")]
    return (
        "audit AS (\n  SELECT event_time, named_struct('email', email) AS user_identity, ip AS source_ip_address,\n"
        f"         '{UA}' AS user_agent, 'fixture' AS service_name, action_name,\n"
        "         map('scope', scope, 'key', key, 'authenticationMethod', auth_method, 'tokenId', token_id)\n"
        "           AS request_params,\n"
        "         named_struct('status_code', status) AS response,\n"
        "         named_struct('acting_resource_type', kind) AS identity_metadata\n"
        "  FROM VALUES\n  " + ",\n  ".join(values) +
        "\n  AS t(event_time, email, ip, action_name, scope, key, auth_method, token_id, status, kind)\n),\n"
        "principals AS (SELECT * FROM VALUES\n  "
        + ",\n  ".join(f"({_lit(e)}, {_lit(n)})" for e, n in principals) + "\n  AS t(email, display_name))"
    )


def hunt_query(part: str) -> str:
    """The 6a or 6b query of the hunt, reading the fixture CTEs instead of the demo tables."""
    cell = next(c for c in HUNT6.read_text().split("-- COMMAND ----------") if c.lstrip().startswith(f"-- {part}."))
    sql = _IDENTIFIER.sub(r"\1", cell[cell.index("WITH ev AS"):].strip())
    if ":catalog" in sql or ":schema" in sql or "IDENTIFIER" in sql:
        raise RuntimeError(f"hunt {part}: unexpected table reference left after the rewrite")
    return "WITH " + fixture_ctes() + ",\n" + sql[len("WITH "):]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--profile", default="some-profile")
    p.add_argument("--warehouse-id", required=True)
    a = p.parse_args()
    from auditdemo.lakewatch import SdkApi
    api = SdkApi(a.profile)
    ok = True

    rows = api.sql(hunt_query("6a"), a.warehouse_id)
    got = {r[0] for r in rows}
    print(f"== 6a: {len(rows)} row(s)")
    for r in rows:
        print("  " + " | ".join("" if v is None else str(v) for v in r))
    for actor, (want, _ip) in CASES_6A.items():
        hit = actor in got
        ok &= hit == want
        print(f"  {actor:30s} expected {'match' if want else 'no match':9s} -> {'ok' if hit == want else 'WRONG'}")

    rows = api.sql(hunt_query("6b"), a.warehouse_id)
    print(f"== 6b: {len(rows)} row(s)")
    for r in rows:
        print("  " + " | ".join("" if v is None else str(v) for v in r))
    hit = len(rows) == 1 and rows[0][0] == "reader -> sp-fixture"
    ok &= hit
    print(f"  interleaved reader -> sp on one IP: {'ok' if hit else 'WRONG'}")
    print("ALL OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
