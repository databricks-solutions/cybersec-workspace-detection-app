"""S2: blocked replay. A stolen SP credential is used from an attacker IP.

OIDC authorization works, then the IP access list blocks the calls in two workspaces.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from ..rows import event
from ..world import World

SP_NAME = "sp-reporting"
UA = "python-requests/2.32.3"


class S2:
    key = "S2"
    expected_rules = {"ada_ip_denied_after_auth", "adp_attempted_login_from_denied_ip"}
    forbidden_rules: set[str] = set()

    def actors(self, world: World) -> set[str]:
        return {world.get(SP_NAME).email}

    def rows(self, world: World, anchor: datetime) -> list[dict]:
        T = anchor.replace(tzinfo=timezone.utc) if anchor.tzinfo is None else anchor.astimezone(timezone.utc)
        t0 = T - timedelta(hours=5)
        sp = world.get(SP_NAME)
        ip = world.attacker_ips(T)[1]
        uid = str(int(hashlib.md5(sp.email.encode()).hexdigest()[:15], 16))
        token = hashlib.sha256(f"{world.seed}|{sp.email}|s2|{T.isoformat()}".encode()).hexdigest()[:32]
        out = [event(world, sp, t0, "accounts", "oidcTokenAuthorization",
                     {"authenticationMethod": "API_OIDC_TOKEN", "tokenId": token, "user": sp.email},
                     ip=ip, user_agent=UA, workspace=world.workspaces["analytics"])]
        for i, name in enumerate(("analytics", "prod")):
            out.append(event(world, sp, t0 + timedelta(minutes=2 + i), "accounts", "IpAccessDenied",
                             {"path": "/api/2.0/clusters/list", "user": sp.email, "userId": uid},
                             ip=ip, user_agent=UA, workspace=world.workspaces[name], status=403,
                             error="Source IP address is blocked by the workspace IP access list."))
        return out
