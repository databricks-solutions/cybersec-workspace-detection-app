"""S4: compute fallback. Cluster and job creation fail, then the actor tries other compute."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..background import stable_uas
from ..rows import event
from ..world import World

SP_NAME = "sp-ml-batch"


class S4:
    key = "S4"
    expected_rules = {"ada_compute_fallback"}
    forbidden_rules: set[str] = set()

    def actors(self, world: World) -> set[str]:
        return {world.get(SP_NAME).email}

    def rows(self, world: World, anchor: datetime) -> list[dict]:
        T = anchor.replace(tzinfo=timezone.utc) if anchor.tzinfo is None else anchor.astimezone(timezone.utc)
        t0 = T - timedelta(hours=4)
        sp = world.get(SP_NAME)
        ws = sp.workspaces[0]
        ip, ua = sp.home_ips[0], stable_uas(world.seed, sp)[1][0]

        def ev(minutes, service, action, params, **kw):
            return event(world, sp, t0 + timedelta(minutes=minutes), service, action, params,
                         ip=ip, user_agent=ua, workspace=ws, **kw)

        return [
            ev(0, "clusters", "create",
               {"cluster_creator": "SINGLE_USER", "autotermination_minutes": "60", "kind": "CLASSIC_PREVIEW",
                "data_security_mode": "SINGLE_USER", "enable_serverless_compute": "false"},
               status=500, error="REQUEST_LIMIT_EXCEEDED: too many cluster create requests, try again later"),
            ev(1, "jobs", "submitRun", {"run_name": "ml-batch-scoring", "timeout_seconds": "3600"},
               status=1004, error="PERMISSION_DENIED: not authorized to create a run on this compute"),
            ev(4, "databrickssql", "startWarehouse", {"id": "b2f6c1d49e07a135"}),
            ev(6, "jobs", "runNow", {"job_id": "482913", "job_parameters": '{"compute": "serverless"}'}),
        ]
