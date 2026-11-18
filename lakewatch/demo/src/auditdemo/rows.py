"""One audit row builder, shared by the background and the scenarios."""

from __future__ import annotations

import hashlib
import random
import uuid
from datetime import datetime, timezone

from .world import Principal, World

LOGIN_ACTIONS = ("tokenLogin", "oidcTokenAuthorization")
SP_RESOURCE_TYPE = "Application Service Principal"


def _uuid(rng: random.Random | None, key: str) -> str:
    if rng is not None:
        return str(uuid.UUID(int=rng.getrandbits(128), version=4))
    return str(uuid.UUID(bytes=hashlib.sha256(key.encode()).digest()[:16], version=4))


def event(
    world: World,
    principal: Principal,
    when: datetime,
    service: str,
    action: str,
    params: dict[str, str],
    *,
    ip: str,
    user_agent: str,
    workspace: str | None,
    status: int = 200,
    error: str | None = None,
    session_id: str | None = None,
    audit_level: str = "WORKSPACE_LEVEL",
    rng: random.Random | None = None,
) -> dict:
    """Build one row with every column of system.access.audit.

    ACCOUNT_LEVEL rows always get workspace_id '0'. Ids come from `rng` when given,
    otherwise from a hash of the row content (same input, same ids).
    """
    if when.tzinfo is not timezone.utc:
        when = when.astimezone(timezone.utc) if when.tzinfo else when.replace(tzinfo=timezone.utc)
    ws = "0" if audit_level == "ACCOUNT_LEVEL" else workspace
    if ws is None:
        raise ValueError("workspace is required for WORKSPACE_LEVEL rows")
    seed_key = f"{world.seed}|{when.isoformat()}|{principal.email}|{service}.{action}|{sorted(params.items())}|{ip}"
    email = principal.email
    if action in LOGIN_ACTIONS:
        meta = {"run_by": None, "run_as": email, "acting_resource": None, "run_by_display_name": None,
                "run_as_display_name": None, "acting_resource_display_name": None, "acting_resource_type": None}
    else:
        is_sp = principal.kind == "sp"
        meta = {"run_by": email, "run_as": email,
                "acting_resource": email if is_sp else None,
                "run_by_display_name": principal.display_name,
                "run_as_display_name": principal.display_name,
                "acting_resource_display_name": principal.display_name if is_sp else None,
                "acting_resource_type": SP_RESOURCE_TYPE if is_sp else None}
    return {
        "account_id": world.account_id,
        "workspace_id": ws,
        "version": "2.0",
        "event_time": when,
        "event_date": when.date(),
        "source_ip_address": ip,
        "user_agent": user_agent,
        "session_id": session_id,
        "user_identity": {"email": email, "subject_name": None},
        "service_name": service,
        "action_name": action,
        "request_id": _uuid(rng, "req|" + seed_key),
        "request_params": params,
        "response": {"status_code": status, "error_message": error, "result": None},
        "audit_level": audit_level,
        "event_id": _uuid(rng, "evt|" + seed_key),
        "identity_metadata": meta,
    }
