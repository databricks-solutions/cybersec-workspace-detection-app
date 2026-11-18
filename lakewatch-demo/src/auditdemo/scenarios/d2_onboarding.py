"""D2 (decoy): an admin adds five new team members to a group within a few minutes."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from ..background import stable_uas
from ..rows import event
from ..world import World
from .d1_ci_scopes import ADA_RULES

USER = "ana.silva@corp.example"
GROUP = "data-eng"
NEW_MEMBERS = ["lena.hartmann@corp.example", "yusuf.demir@corp.example", "clara.nguyen@corp.example",
               "mateo.alvarez@corp.example", "sara.lindgren@corp.example"]


class D2:
    key = "D2"
    expected_rules: set[str] = set()
    forbidden_rules = set(ADA_RULES)

    def actors(self, world: World) -> set[str]:
        return {world.get(USER).email}

    def rows(self, world: World, anchor: datetime) -> list[dict]:
        T = anchor.replace(tzinfo=timezone.utc) if anchor.tzinfo is None else anchor.astimezone(timezone.utc)
        t0 = T - timedelta(hours=2, minutes=30)
        ana = world.get(USER)
        ua = stable_uas(world.seed, ana)[1][0]
        gid = str(int(hashlib.md5(GROUP.encode()).hexdigest()[:10], 16))
        return [
            event(world, ana, t0 + timedelta(seconds=55 * i), "accounts", "addPrincipalToGroup",
                  {"endpoint": f"/api/2.0/accounts/{world.account_id}/scim/v2/Groups/{GROUP}",
                   "targetGroupId": gid, "targetGroupName": GROUP,
                   "targetUserId": str(int(hashlib.md5(m.encode()).hexdigest()[:15], 16)),
                   "targetUserName": m},
                  ip=ana.home_ips[0], user_agent=ua, workspace=None, audit_level="ACCOUNT_LEVEL")
            for i, m in enumerate(NEW_MEMBERS)
        ]
