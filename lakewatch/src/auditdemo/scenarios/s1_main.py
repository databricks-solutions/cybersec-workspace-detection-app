"""S1: the main incident (spec section 3). T = anchor.

A leaked PAT of a data engineer reads the client secret of a service principal.
The service principal then runs the rest of the chain from the same attacker IP.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from ..rows import event
from ..world import Principal, World

ACC = "ACCOUNT_LEVEL"
MARIA = "maria.lopez@corp.example"
SP_NAME = "sp-etl-prod"
ATTACKER_UA = "python-requests/2.32.3"
SP_UA = "curl/8.7.1"
NEW_ADMIN = "svc-backup@corp.example"
SECRET_KEY = "sp-etl-prod-client-secret"
# Restricted scope (denied), then the less restricted scope that holds the same key.
RESTRICTED_SCOPE = "shared-infra"
OPEN_SCOPE = "etl-prod"
THIRD_SCOPE = "ci-deploy"
LISTED = {"ci-deploy": ["registry-token", "deploy-key"], "etl-prod": ["warehouse-password", SECRET_KEY],
          "shared-infra": ["monitoring-api-key", SECRET_KEY]}
FUNCTIONS = [
    ("util_parse_json", "import subprocess\ndef f(s):\n    return subprocess.check_output(s, shell=True).decode()"),
    ("util_fetch_config", "import requests\ndef f(u):\n    return requests.get(u, timeout=5).text"),
    ("util_sync_state", "import os\ndef f(c):\n    return os.popen(c).read()"),
]
EXPECTED = {
    "ada_pat_new_source_ip", "ada_sp_oauth_new_user_agent", "ada_discovery_api_burst",
    "ada_first_secret_enumeration", "ada_secret_harvest_chain", "ada_secret_denied_then_read",
    "ada_first_seen_create_function", "ada_sp_grants_admin", "ada_token_minted_new_source",
    "ada_sensitive_export", "ada_short_lived_function", "ada_identity_pivot_chain",
    "ada_multi_stage_identity",
}
# Ported pack rules (single-event contrast) that S1 fires; checked live on 2026-11-12 (Task 10).
PORTED = {"adp_secrets_enumeration", "adp_workspace_content_exported", "adp_user_admin_account_change"}


def _utc(t: datetime) -> datetime:
    return t.replace(tzinfo=timezone.utc) if t.tzinfo is None else t.astimezone(timezone.utc)


class S1:
    key = "S1"
    expected_rules = EXPECTED | PORTED
    forbidden_rules: set[str] = set()

    def actors(self, world: World) -> set[str]:
        return {world.get(MARIA).email, world.get(SP_NAME).email}

    def rows(self, world: World, anchor: datetime) -> list[dict]:
        T = _utc(anchor)
        ip = world.attacker_ips(T)[0]
        maria, sp = world.get(MARIA), world.get(SP_NAME)
        meta = str(uuid.uuid5(uuid.NAMESPACE_DNS, world.account_id))
        out: list[dict] = []

        def ev(who: Principal, t: datetime, service: str, action: str, params: dict[str, str], *,
               ua: str, ws: str | None = None, **kw) -> None:
            out.append(event(world, who, t, service, action, params, ip=ip, user_agent=ua,
                             workspace=ws or who.workspaces[0], **kw))

        def uc(who: Principal, t: datetime, action: str, extra: dict[str, str], ua: str) -> None:
            ws = who.workspaces[0]
            ev(who, t, "unityCatalog", action, {**extra, "metastore_id": meta, "workspace_id": ws},
               ua=ua, audit_level=ACC)

        # 1. Access (T-3h): leaked PAT, a short burst of logins
        for s in (0, 8, 21):
            ev(maria, T - timedelta(hours=3) + timedelta(seconds=s), "accounts", "tokenLogin",
               {"authenticationMethod": "API_EXT_PAT_TOKEN", "tokenId": maria.pat_ids[0], "user": maria.email},
               ua=ATTACKER_UA)

        # 2. Discovery (T-3h + 1 min): six distinct discovery actions in 42 s
        t = T - timedelta(hours=3) + timedelta(minutes=1)
        ev(maria, t, "secrets", "listScopes", {}, ua=ATTACKER_UA)
        uc(maria, t + timedelta(seconds=7), "listCatalogs", {"max_results": "100", "include_browse": "true"}, ATTACKER_UA)
        uc(maria, t + timedelta(seconds=14), "listExternalLocations", {"max_results": "100"}, ATTACKER_UA)
        uc(maria, t + timedelta(seconds=21), "listStorageCredentials", {"max_results": "100"}, ATTACKER_UA)
        ev(maria, t + timedelta(seconds=28), "repos", "listRepos", {"path_prefix": "/Repos"}, ua=ATTACKER_UA)
        uc(maria, t + timedelta(seconds=35), "listSchemas", {"catalog_name": "main", "max_results": "100"}, ATTACKER_UA)

        # 3. Harvest (T-3h + 5 min): listScopes, then one scope at a time: listSecrets(scope) -> getSecret(scope).
        #    The read in the restricted scope is denied; the same key is then read from the open scope.
        t = T - timedelta(hours=3) + timedelta(minutes=5)
        ev(maria, t, "secrets", "listScopes", {}, ua=ATTACKER_UA)
        for i, scope in enumerate((THIRD_SCOPE, RESTRICTED_SCOPE, OPEN_SCOPE)):
            at = t + timedelta(seconds=20 + 60 * i)
            ev(maria, at, "secrets", "listSecrets", {"scope": scope}, ua=ATTACKER_UA)
            at += timedelta(seconds=30)
            if scope == THIRD_SCOPE:
                ev(maria, at, "secrets", "getSecret", {"scope": scope, "key": LISTED[scope][1]}, ua=ATTACKER_UA)
            elif scope == RESTRICTED_SCOPE:
                ev(maria, at, "secrets", "getSecret",
                   {"scope": scope, "key": SECRET_KEY, "use_simplified_error_handling": "true"},
                   ua=ATTACKER_UA, status=1004,
                   error=f"PERMISSION_DENIED: User {maria.email} does not have secret-scopes.secrets/get permission "
                         f"on scope {scope} to perform this action.")
            else:
                ev(maria, at, "secrets", "getSecret", {"scope": scope, "key": SECRET_KEY}, ua=ATTACKER_UA)

        # 4. Pivot and execution (T-2h): the service principal, new user agent, same IP
        t = T - timedelta(hours=2)
        sp_token = hashlib.sha256(f"{world.seed}|{sp.email}|{T.isoformat()}".encode()).hexdigest()[:32]
        ev(sp, t, "accounts", "oidcTokenAuthorization",
           {"authenticationMethod": "API_OIDC_TOKEN", "tokenId": sp_token, "user": sp.email}, ua=SP_UA)
        uc(sp, t + timedelta(seconds=20), "listCatalogs", {"max_results": "100"}, SP_UA)
        uc(sp, t + timedelta(seconds=40), "listSchemas", {"catalog_name": "main", "max_results": "100"}, SP_UA)
        ws = sp.workspaces[0]
        created: list[str] = []
        for i, (name, body) in enumerate(FUNCTIONS):
            info = json.dumps({"name": name, "catalog_name": "ops_tools", "schema_name": "helpers",
                               "specific_name": name, "data_type": "STRING", "full_data_type": "STRING",
                               "routine_body": "EXTERNAL", "routine_definition": body,
                               "parameter_style": "S", "is_deterministic": False, "is_null_call": True,
                               "security_type": "DEFINER", "sql_data_access": "NO_SQL"})
            uc(sp, t + timedelta(minutes=(5, 12, 20)[i]), "createFunction",
               {"function_info": info, "include_manifest_capabilities": "true"}, SP_UA)
            created.append(f"ops_tools.helpers.{name}")

        # 5. Persistence (T-1h50)
        t = T - timedelta(hours=1, minutes=50)
        grp = "admins"
        ev(sp, t, "accounts", "addPrincipalToGroup",
           {"endpoint": f"/api/2.0/accounts/{world.account_id}/scim/v2/Groups/{grp}",
            "targetGroupId": str(int(hashlib.md5(grp.encode()).hexdigest()[:10], 16)),
            "targetGroupName": grp,
            "targetUserId": str(int(hashlib.md5(NEW_ADMIN.encode()).hexdigest()[:15], 16)),
            "targetUserName": NEW_ADMIN}, ua=SP_UA, audit_level=ACC)
        uid = str(int(hashlib.md5(sp.email.encode()).hexdigest()[:15], 16))
        t2 = t + timedelta(seconds=40)
        ev(sp, t2, "accounts", "generateDbToken",
           {"tokenCreatedBy": sp.email, "tokenExpirationTime": str(int((t2 + timedelta(days=90)).timestamp() * 1000)),
            "tokenHash": hashlib.sha256(f"{world.seed}|{T.isoformat()}|pat".encode()).hexdigest(), "userId": uid},
           ua=SP_UA, ws=ws)

        # 6. Collect and clean up (T-1h30)
        ev(sp, T - timedelta(hours=1, minutes=32), "workspace", "workspaceExport",
           {"notebookFullPath": "/Workspace/init-scripts/cluster-bootstrap.sh", "workspaceExportFormat": "SOURCE",
            "workspaceExportDirectDownload": "true"}, ua=SP_UA, ws=ws)
        uc(sp, T - timedelta(hours=1, minutes=30), "deleteFunction", {"full_name_arg": created[0]}, SP_UA)

        out.sort(key=lambda r: r["event_time"])
        return out
