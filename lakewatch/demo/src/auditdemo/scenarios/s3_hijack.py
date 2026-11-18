"""S3: session hijack and export. Another user, another attacker.

A browser session of tom.becker shows up from an attacker IP with a different browser,
then the attacker exports notebooks. Tom has no export history in the background.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from ..background import BROWSERS, stable_uas
from ..rows import event
from ..world import World

USER = "tom.becker@corp.example"
OWN_ACTIONS = ["openNotebook", "modifyNotebook", "openNotebook"]
PATHS = [
    "/Workspace/Users/tom.becker@corp.example/q3_forecast",
    "/Workspace/Users/tom.becker@corp.example/cohort_analysis",
    "/Workspace/Shared/finance/budget_2027",
    "/Workspace/Shared/finance/revenue_model",
]


class S3:
    key = "S3"
    expected_rules = {"ada_session_reuse_new_ip_ua", "ada_sensitive_export", "adp_workspace_content_exported"}
    forbidden_rules: set[str] = set()

    def actors(self, world: World) -> set[str]:
        return {world.get(USER).email}

    def rows(self, world: World, anchor: datetime) -> list[dict]:
        T = anchor.replace(tzinfo=timezone.utc) if anchor.tzinfo is None else anchor.astimezone(timezone.utc)
        t0 = T - timedelta(hours=6)
        tom = world.get(USER)
        ws = world.workspaces["analytics"]
        atk_ip = world.attacker_ips(T)[2]
        own_ua = stable_uas(world.seed, tom)[0]
        atk_ua = next(b for b in BROWSERS if b != own_ua)
        sid = str(uuid.UUID(bytes=hashlib.sha256(f"{world.seed}|s3|{T.isoformat()}".encode()).digest()[:16],
                            version=4))
        out: list[dict] = []

        def ev(t, service, action, params, ip, ua):
            out.append(event(world, tom, t, service, action, params, ip=ip, user_agent=ua, workspace=ws,
                             session_id=sid))

        for i, action in enumerate(OWN_ACTIONS):  # Tom's own session at his corporate IP
            ev(t0 + timedelta(minutes=i), "notebook", action,
               {"assetType": "NOTEBOOK", "notebookId": str(1000 + i), "path": PATHS[i % 2]},
               tom.home_ips[0], own_ua)
        for i in range(2):  # same session id, new IP and browser, inside 20 minutes
            ev(t0 + timedelta(minutes=9 + i), "notebook", "openNotebook",
               {"assetType": "NOTEBOOK", "notebookId": str(2000 + i), "path": PATHS[2 + i]}, atk_ip, atk_ua)
        for i, path in enumerate(PATHS):
            ev(t0 + timedelta(minutes=12 + i), "workspace", "workspaceExport",
               {"notebookFullPath": path, "workspaceExportFormat": "SOURCE",
                "workspaceExportDirectDownload": "true"}, atk_ip, atk_ua)
        out.sort(key=lambda r: r["event_time"])
        return out
