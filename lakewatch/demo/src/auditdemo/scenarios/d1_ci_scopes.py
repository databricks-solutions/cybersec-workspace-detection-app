"""D1 (decoy): the nightly secret scope listing of the CI service principal.

It is the run of tonight at T-4h, which the background leaves out. The shape comes from
`ci_nightly_calls()`, the same helper the background uses.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..background import ci_nightly_calls, stable_uas
from ..rows import event
from ..world import World
from .s1_main import S1
from .s2_replay import S2
from .s3_hijack import S3
from .s4_fallback import S4

SP_NAME = "sp-ci-deploy"
# every ada_* rule: S1's chain plus the rules that S2, S3 and S4 fire (the ported adp_* rules may fire
# on the decoys: that single-event noise is the contrast of the story)
ADA_RULES = {r for s in (S1, S2, S3, S4) for r in s.expected_rules if r.startswith("ada_")}


class D1:
    key = "D1"
    expected_rules = {"adp_secrets_enumeration"}
    forbidden_rules = set(ADA_RULES)

    def actors(self, world: World) -> set[str]:
        return {world.get(SP_NAME).email}

    def rows(self, world: World, anchor: datetime) -> list[dict]:
        T = anchor.replace(tzinfo=timezone.utc) if anchor.tzinfo is None else anchor.astimezone(timezone.utc)
        t0 = T - timedelta(hours=4)
        sp = world.get(SP_NAME)
        ua = stable_uas(world.seed, sp)[1][0]
        return [event(world, sp, t0 + timedelta(seconds=off), svc, act, params, ip=sp.home_ips[0],
                      user_agent=ua, workspace=sp.workspaces[0])
                for off, svc, act, params in ci_nightly_calls()]
