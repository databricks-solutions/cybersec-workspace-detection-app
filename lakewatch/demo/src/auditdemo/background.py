"""Background audit traffic from the profile, built on stable per-principal HABITS.

The stage rules look for first-seen behaviour against a 14-day baseline. So each
principal decides once (seeded) which sensitive actions it ever does. If it does one,
it does it from day 0, regularly, from its own IPs and user agent. The baseline then
always holds every habit before the detection window.

Choices worth knowing:
- accounts.IpAccessDenied is not in the background at all (decoys and scenarios add it).
- No failed clusters.create / jobs.submitRun in the background (compute_fallback).
- list* actions of one identity use disjoint minute slots: at most two distinct list
  actions fall in any 60 s window (discovery_api_burst needs five).
- sp-ci-deploy lists all scopes and secrets every night at the time of day of
  (end - 4 h). The run at end - 4 h itself is NOT written: decoy D1 produces it.
"""

from __future__ import annotations

import hashlib
import json
import random
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from itertools import accumulate
from typing import Iterator

from .rows import LOGIN_ACTIONS, event
from .world import Principal, World

UTC = timezone.utc
TARGET_ROWS_PER_DAY = 125_000
ACC = "ACCOUNT_LEVEL"
SECRET_SCOPES = {
    "ci-deploy": ["registry-token", "deploy-key"],
    "etl-prod": ["warehouse-password", "kafka-api-key", "s3-access-key"],
    "ml-platform": ["feature-store-token", "model-registry-key"],
    "bi-reporting": ["bi-service-token", "smtp-password"],
    "shared-infra": ["monitoring-api-key", "pagerduty-token", "vault-bootstrap"],
}
GROUPS = ["data-engineers", "analysts", "ml-team", "bi-users", "finance-readers", "platform-users"]
BROWSERS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
]
TOOL_UAS = ["databricks-sdk-py/0.38.0 python/3.11.9 os/linux", "python-requests/2.31.0", "cli/0.230.0",
            "PyDatabricksSqlConnector/3.4.0", "Go-http-client/2.0"]
SP_UAS = ["Apache-HttpClient/4.5.14", "grpc-python/1.62.0", "Go-http-client/2.0", "python-requests/2.31.0",
          "armeria/1.29.0", "databricks-sdk-py/0.38.0 python/3.11.9 os/linux"]
NOTEBOOKS = ["daily_sales", "churn_model", "etl_orders", "kpi_review", "feature_prep", "cohort_analysis"]
# Sensitive (service, action) pairs handled only through habits (secrets.* by service).
HABIT_ACTIONS = {
    ("unityCatalog", "createFunction"), ("unityCatalog", "deleteFunction"), ("workspace", "workspaceExport"),
    ("accounts", "generateDbToken"), ("accounts", "addPrincipalToGroup"), ("accounts", "IpAccessDenied"),
    ("clusters", "create"), ("jobs", "submitRun"), ("databrickssql", "startWarehouse"),
    ("workspace", "setAdmin"), ("accounts", "updatePermissionAssignment"),
}
# Stage 2 discovery set (constraints amendment). Handled only through habits; actions
# missing from the profile are skipped. secrets.* is covered by the "scopes" habit.
DISCOVERY = {
    ("unityCatalog", "listMetastores"), ("unityCatalog", "listCatalogs"), ("unityCatalog", "listSchemas"),
    ("unityCatalog", "listExternalLocations"), ("unityCatalog", "listStorageCredentials"),
    ("repos", "listRepos"), ("accountsManager", "listWorkspaceConfigurations"),
    ("accountsManager", "listNetworkConfigurations"), ("accountsManager", "listStorageConfigurations"),
}
# habit -> probability by role (users: data_engineer/analyst/admin; SPs: etl/ml/ci/bi/reporting)
HABIT_PROB = {
    "scopes": {"data_engineer": .4, "admin": .3, "etl": .5, "ml": .5, "ci": 1.0},
    "getsecret": {"data_engineer": .4, "admin": .2, "etl": .8, "ml": .8, "bi": .5, "reporting": .5},
    "functions": {"data_engineer": .3, "admin": .2, "ml": .3, "etl": .3},
    "export": {"data_engineer": .5, "analyst": .3, "admin": .5, "etl": .3, "bi": .3, "reporting": .3},
    "dbtoken": {"data_engineer": .5, "admin": .5, "etl": .3, "ml": .3},
    "groups": {"admin": 1.0},
    "cluster": {"data_engineer": .8, "etl": .8, "ml": .8, "ci": .5, "admin": .3},
    "submit": {"data_engineer": .6, "etl": .8, "ml": .8, "reporting": .5, "ci": .5},
    "warehouse": {"analyst": .9, "data_engineer": .5, "admin": .4, "bi": .9, "reporting": .9},
}
NEVER = {
    "maria.lopez@corp.example": {"scopes", "getsecret", "functions", "export"},
    "sp-etl-prod": {"functions", "groups"},
    "tom.becker@corp.example": {"export"},  # S3: first export ever = "no export history"
}
ERRORS = {400: "BAD_REQUEST: invalid request", 403: "PERMISSION_DENIED: access denied",
          500: "INTERNAL_ERROR: request failed", 1000: "INVALID_PARAMETER_VALUE: invalid value",
          1004: "PERMISSION_DENIED: not authorized", 3002: "RESOURCE_DOES_NOT_EXIST: resource not found"}
BUSINESS = [.2, .2, .2, .2, .2, .3, .5, 1.5, 4, 6, 6, 5, 4, 5, 6, 6, 5, 4, 2, 1, .6, .4, .3, .2]


def _kind(key: str) -> int:
    k = key.lower()
    if key == "workspace_id":
        return 0
    if key == "metastore_id":
        return 1
    if key in ("user", "email"):
        return 2
    if k.startswith(("include", "omit", "only", "unbound", "browse")):
        return 3
    if any(s in k for s in ("count", "size", "max", "num", "timeout", "limit", "minutes")):
        return 4
    if k.endswith("id") or "token" in k or "hash" in k:
        return 5
    return 6


def stable_uas(world_seed: int, p: Principal) -> tuple[str | None, list[str]]:
    """(browser, tool/SP user agents) of a principal, from the world seed only.

    Scenarios use this so they match the background whatever its own seed is."""
    r = random.Random(f"{world_seed}|{p.email}|ua")
    if p.kind == "user":
        return r.choice(BROWSERS), r.sample(TOOL_UAS, r.choice([1, 2]))
    return None, [r.choice(SP_UAS)]


def ci_nightly_calls() -> list[tuple[int, str, str, dict[str, str]]]:
    """The nightly sp-ci-deploy run: (offset seconds, service, action, params).

    Shared by the background and decoy D1, so the two can never differ."""
    calls: list[tuple[int, str, str, dict[str, str]]] = [(0, "secrets", "listScopes", {})]
    for i, scope in enumerate(SECRET_SCOPES):
        calls.append((3 * (i + 1), "secrets", "listSecrets", {"scope": scope}))
    return calls


class _Persona:
    def __init__(self, world: World, p: Principal, seed: int):
        r = random.Random(f"{seed}|{p.email}")
        self.act = r.uniform(.6, 1.4)
        self.uid = str(r.randrange(10**15, 10**16))
        self.oid = f"{r.getrandbits(128):032x}"
        self.scope = r.choice(sorted(SECRET_SCOPES))
        if p.kind == "user":
            self.browser = r.choice(BROWSERS)
            self.uas = r.sample(TOOL_UAS, r.choice([1, 2]))
        else:
            self.browser = None
            self.uas = [r.choice(SP_UAS)]
        self.browser, self.uas = stable_uas(world.seed, p)  # the draws above keep the rng stream
        never = NEVER.get(p.email, set()) | NEVER.get(p.display_name, set())
        self.habits = {h for h, probs in HABIT_PROB.items()
                       if (r.random() < probs.get(p.role, 0.0) or (p.role == "ci" and h == "scopes"))
                       and h not in never}
        self.pending: list[tuple[int, str, str]] = []  # (day, full name) of created functions
        self.legacy = 0


class _Gen:
    def __init__(self, world: World, profile: dict, start: datetime, end: datetime, seed: int, scale: float):
        self.w, self.start, self.end, self.scale, self.seed = world, start, end, scale, seed
        self.rng = random.Random(seed * 7919 + 1)
        self.meta = str(uuid.uuid5(uuid.NAMESPACE_DNS, world.account_id))
        self.per = {p.email: _Persona(world, p, seed) for p in world.principals}
        self.users = [p for p in world.principals if p.kind == "user"]
        actions = profile["actions"]
        lists = sorted({(a["service_name"], a["action_name"]) for a in actions if a["action_name"].startswith("list")})
        self.cls = {k: i for i, k in enumerate(lists)}
        self.disc = {}  # (service, action) -> (audit level, kind -> entry)
        for a in actions:
            k = (a["service_name"], a["action_name"])
            if k in DISCOVERY:
                self.disc.setdefault(k, (a["audit_level"], {}))[1].setdefault(a["actor_kind"], a)
        for p in world.principals:  # seeded subset of discovery actions per principal
            self.per[p.email].disc = [k for k in sorted(self.disc)
                                      if random.Random(f"{seed}|{p.email}|{k}").random() < .6]
        self.nls = max(len(lists), 1)
        self.entries: dict[tuple[str, str, str], dict] = {}
        self.plans = {"user": [], "sp": []}
        for a in actions:
            key = (a["service_name"], a["action_name"])
            if a["status_codes"].get("200") == 1.0:
                self.entries.setdefault(key + (a["actor_kind"],), a)
            if a["service_name"] == "secrets" or key in HABIT_ACTIONS or key in DISCOVERY:
                continue
            codes = [200 if c == "null" else int(c) for c in a["status_codes"]]  # "null" = no code in profile
            h = a["hourly"]
            if a["actor_kind"] == "user":
                tot = sum(h) or 1.0
                h = [.15 * x / tot + .85 * b / sum(BUSINESS) for x, b in zip(h, BUSINESS)]
            cw = list(accumulate(h)) if sum(h) > 0 else list(accumulate([1] * 24))
            self.plans[a["actor_kind"]].append((
                key[0], key[1], a["audit_level"], a["per_actor_per_day"], cw, self.cls.get(key),
                codes, list(accumulate(a["status_codes"].values())), self._gens(a["param_keys"])))
        total = sum(per_rate * self.per[p.email].act
                    for p in world.principals for (_, act, _, per_rate, *_) in self.plans[p.kind]
                    if not (act == "tokenLogin" and not p.pat_ids))
        self.f = TARGET_ROWS_PER_DAY / total
        self.hab_cw = {"user": list(accumulate(BUSINESS)), "sp": list(accumulate([1] * 24))}
        self.first = datetime.combine(start.date(), datetime.min.time(), tzinfo=UTC)
        self.state: dict[tuple[str, int], tuple[str, str]] = {}

    @staticmethod
    def _gens(keys):
        return [(k, _kind(k)) for k in keys]

    def _gen_for(self, svc: str, act: str, kind: str):
        a = self.entries.get((svc, act, kind)) or self.entries[(svc, act, "user" if kind == "sp" else "sp")]
        return self._gens(a["param_keys"])

    # ---- time and actor helpers
    def _place(self, day0, lo, hi, cw, cls):
        rng = self.rng
        for _ in range(6):
            sec = rng.choices(range(24), cum_weights=cw)[0] * 3600 + rng.random() * 3600
            t = self._snap(day0, sec, cls)
            if lo <= t < hi:
                return t
        return lo + (hi - lo) * rng.random()

    def _snap(self, day0, sec, cls):
        if cls is not None:
            m = int(sec // 60)
            m += (cls - m) % self.nls
            if m >= 1440:
                m -= self.nls
            sec = m * 60 + self.rng.random() * 60
        return day0 + timedelta(seconds=sec)

    def _actor(self, p, d, interactive):
        per, rng = self.per[p.email], self.rng
        if p.kind == "sp":
            return rng.choice(p.home_ips), per.uas[0], None
        if interactive:
            k = (p.email, d)
            if k not in self.state:
                r = random.Random(f"{self.seed}|{p.email}|{d}")
                self.state[k] = (r.choice(p.home_ips), str(uuid.UUID(int=r.getrandbits(128), version=4)))
            ip, sid = self.state[k]
            return ip, per.browser, sid
        return rng.choice(p.home_ips), rng.choice(per.uas), None

    def _emit(self, rows, p, d, t, svc, act, params, *, level="WORKSPACE_LEVEL", ws=None, status=200, err=None,
              interactive=False, ip=None, ua=None):
        a_ip, a_ua, sid = self._actor(p, d, interactive and level != ACC)
        rows.append(event(self.w, p, t, svc, act, params, ip=ip or a_ip, user_agent=ua or a_ua,
                          workspace=ws or self.rng.choice(p.workspaces), status=status, error=err,
                          session_id=sid, audit_level=level, rng=self.rng))

    def _params(self, gens, p, ws):
        rng, out = self.rng, {}
        for k, kd in gens:
            out[k] = (ws if kd == 0 else self.meta if kd == 1 else p.email if kd == 2
                      else rng.choice(("true", "false")) if kd == 3 else str(rng.randrange(1, 100)) if kd == 4
                      else f"{rng.getrandbits(64):016x}" if kd == 5 else f"{k}-{rng.randrange(1000)}")
        return out

    @staticmethod
    def _auth_method(p, per, pat, tid, ip):
        """Stable per (PAT, source IP): CI range and ~1/4 of user IPs look external."""
        if not pat:
            return "API_OIDC_TOKEN"
        if p.role == "ci":
            return "API_EXT_PAT_TOKEN"
        if p.kind == "sp":
            return "API_INT_PAT_TOKEN"
        return "API_INT_PAT_TOKEN" if hashlib.md5(f"{tid}|{ip}".encode()).digest()[0] % 4 == 0 else "API_EXT_PAT_TOKEN"

    def _login(self, p, per, d, t, act, rows, ip=None, tid=None):
        rng = self.rng
        ip = ip or rng.choice(p.home_ips)
        pat = act == "tokenLogin"
        tid = tid or (rng.choice(p.pat_ids) if pat else per.oid)
        ua = per.uas[0] if p.kind == "sp" else (rng.choice(per.uas) if pat else per.browser)
        ws = rng.choice(p.workspaces)
        self._emit(rows, p, d, t, "accounts", act,
                   {"authenticationMethod": self._auth_method(p, per, pat, tid, ip), "tokenId": tid, "user": p.email},
                   ws=ws, ip=ip, ua=ua)

    # ---- generation
    def days(self) -> Iterator[list[dict]]:
        n_days = (self.end - timedelta(microseconds=1) - self.first).days + 1
        for d in range(n_days):
            yield self._day(d)

    def _day(self, d: int) -> list[dict]:
        rng, scale = self.rng, self.scale
        day0 = self.first + timedelta(days=d)
        lo, hi = max(day0, self.start), min(day0 + timedelta(days=1), self.end)
        weekend = day0.weekday() >= 5
        jit = rng.uniform(.9, 1.1) * self.f * scale
        rows: list[dict] = []
        for p in self.w.principals:
            per = self.per[p.email]
            mult = per.act * jit * (0.25 if weekend and p.kind == "user" else 1.0)
            kind = p.kind
            for svc, act, level, rate, cw, cls, codes, ccw, gens in self.plans[kind]:
                if act == "tokenLogin" and not p.pat_ids:
                    continue
                rate *= mult
                n = int(rate)
                if rng.random() < rate - n:
                    n += 1
                for _ in range(n):
                    t = self._place(day0, lo, hi, cw, cls) if n < 3 else self._snap(
                        day0, rng.choices(range(24), cum_weights=cw)[0] * 3600 + rng.random() * 3600, cls)
                    if not lo <= t < hi:
                        continue
                    if act in LOGIN_ACTIONS:
                        self._login(p, per, d, t, act, rows)
                        continue
                    code = codes[0] if len(codes) == 1 else rng.choices(codes, cum_weights=ccw)[0]
                    ws = rng.choice(p.workspaces)
                    self._emit(rows, p, d, t, svc, act, self._params(gens, p, ws), level=level, ws=ws,
                               status=code, err=None if code == 200 else ERRORS.get(code, "FAILED: request failed"),
                               interactive=kind == "user" and level != ACC and rng.random() < .5)
            self._habits(p, per, d, day0, lo, hi, weekend, rows)
        rows.sort(key=lambda r: r["event_time"])
        return rows

    def _habits(self, p, per, d, day0, lo, hi, weekend, rows):
        rng, h = self.rng, per.habits
        wk = .3 if weekend and p.kind == "user" else 1.0
        cw = self.hab_cw[p.kind]

        def count(period, extra):
            r = extra * wk
            return (1 if d % period == 0 else 0) + int(r) + (1 if rng.random() < r - int(r) else 0)

        def at(svc="", act=""):
            return self._place(day0, lo, hi, cw, self.cls.get((svc, act)))

        def spaced(n, gap=3):  # times at least `gap` hours apart
            out: list[datetime] = []
            for _ in range(n):
                t = at()
                if all(abs((t - o).total_seconds()) >= gap * 3600 for o in out):
                    out.append(t)
            return out

        if d == 0:  # every home IP, PAT and the OAuth flow appear on day 0
            for ip in p.home_ips:
                self._login(p, per, d, lo + (hi - lo) * rng.random() * .5, "oidcTokenAuthorization", rows, ip=ip)
                for tid in p.pat_ids:
                    self._login(p, per, d, lo + (hi - lo) * rng.random() * .5, "tokenLogin", rows, ip=ip, tid=tid)
                if "dbtoken" in h:
                    self._token(p, per, d, lo + (hi - lo) * rng.random() * .5, rows, ip)
        for k in per.disc:
            level, by_kind = self.disc[k]
            ent = by_kind.get(p.kind) or next(iter(by_kind.values()))
            gens = self._gens(ent["param_keys"])
            for _ in range(count(2, .3)):
                ws = rng.choice(p.workspaces)
                self._emit(rows, p, d, at(*k), k[0], k[1], self._params(gens, p, ws), level=level, ws=ws,
                           interactive=p.kind == "user" and level != ACC and rng.random() < .5)
        if "scopes" in h:
            if p.role == "ci":
                self._nightly(p, per, d, day0, rows)
            else:
                for _ in range(count(2, .5)):
                    self._emit(rows, p, d, at("secrets", "listScopes"), "secrets", "listScopes", {})
                for _ in range(count(2, .5)):
                    self._emit(rows, p, d, at("secrets", "listSecrets"), "secrets", "listSecrets", {"scope": per.scope})
        if "getsecret" in h:
            for _ in range(count(2, 1.0)):
                miss = rng.random() < .05
                key = "legacy-key" if miss else rng.choice(SECRET_SCOPES[per.scope])
                params = {"scope": per.scope, "key": key}
                if miss:
                    params["use_simplified_error_handling"] = "true"
                self._emit(rows, p, d, at(), "secrets", "getSecret", params, status=3002 if miss else 200,
                           err=ERRORS[3002] if miss else None)
        if "functions" in h:
            self._functions(p, per, d, count(2, .3), count(3, .2), spaced, at, rows)
        if "export" in h:
            for _ in range(count(2, .5)):
                path = rng.choice([f"/Users/{p.email}/notebooks/", "/Shared/reports/", f"/Repos/{p.email}/project/"]) + rng.choice(NOTEBOOKS)
                self._emit(rows, p, d, at(), "workspace", "workspaceExport",
                           {"notebookFullPath": path, "workspaceExportFormat": rng.choice(["SOURCE", "HTML", "DBC"]),
                            "workspaceExportDirectDownload": rng.choice(["true", "false"])},
                           interactive=p.kind == "user" and rng.random() < .5)
        if "dbtoken" in h and d > 0:
            for _ in range(count(3, .2)):
                self._token(p, per, d, at(), rows, rng.choice(p.home_ips))
        if "groups" in h:
            for t in spaced(count(2, .5), gap=1):
                tgt = rng.choice(self.users)
                grp = rng.choice(GROUPS)
                self._emit(rows, p, d, t, "accounts", "addPrincipalToGroup",
                           {"endpoint": f"/api/2.0/accounts/{self.w.account_id}/scim/v2/Groups/{grp}",
                            "targetGroupId": str(int(hashlib.md5(grp.encode()).hexdigest()[:10], 16)),
                            "targetGroupName": grp, "targetUserId": self.per[tgt.email].uid,
                            "targetUserName": tgt.email}, level=ACC)
        if "cluster" in h:
            for _ in range(count(2, .5)):
                ws = rng.choice(p.workspaces)
                self._emit(rows, p, d, at(), "clusters", "create",
                           self._params(self._gen_for("clusters", "create", p.kind), p, ws), ws=ws)
        if "submit" in h:
            for _ in range(count(2, .5)):
                ws = rng.choice(p.workspaces)
                self._emit(rows, p, d, at(), "jobs", "submitRun",
                           self._params(self._gen_for("jobs", "submitRun", p.kind), p, ws), ws=ws)
        if "warehouse" in h:
            for _ in range(count(2, .7)):
                ws = rng.choice(p.workspaces)
                self._emit(rows, p, d, at(), "databrickssql", "startWarehouse",
                           {"id": hashlib.md5(ws.encode()).hexdigest()[:16]}, ws=ws)

    def _token(self, p, per, d, t, rows, ip):
        self._emit(rows, p, d, t, "accounts", "generateDbToken",
                   {"tokenCreatedBy": p.email, "tokenExpirationTime": str(int((t + timedelta(days=90)).timestamp() * 1000)),
                    "tokenHash": hashlib.sha256(f"{self.rng.getrandbits(64)}".encode()).hexdigest(), "userId": per.uid},
                   ip=ip)

    def _nightly(self, p, per, d, day0, rows):
        ref = self.end - timedelta(hours=4)
        t = day0 + (ref - datetime.combine(ref.date(), datetime.min.time(), tzinfo=UTC))
        if not (self.start <= t < ref):
            return
        ws, ip = p.workspaces[0], p.home_ips[0]
        for off, svc, act, params in ci_nightly_calls():
            self._emit(rows, p, d, t + timedelta(seconds=off), svc, act, params, ws=ws, ip=ip)

    def _functions(self, p, per, d, n_create, n_delete, spaced, at, rows):
        rng = self.rng
        for t in spaced(min(n_create, 2)):
            cat, sch = "main", rng.choice(["analytics", "utils", "ml"])
            name = f"fn_{per.uid[-4:]}_{d}_{rng.randrange(1000)}"
            ws = rng.choice(p.workspaces)
            info = json.dumps({"name": name, "catalog_name": cat, "schema_name": sch, "specific_name": name,
                               "data_type": "STRING", "routine_body": "SQL", "routine_definition": "SELECT 1"})
            self._emit(rows, p, d, t, "unityCatalog", "createFunction",
                       {"function_info": info, "include_manifest_capabilities": "true",
                        "metastore_id": self.meta, "workspace_id": ws}, level=ACC)
            per.pending.append((d, f"{cat}.{sch}.{name}", ws))
        for _ in range(n_delete):
            old = [x for x in per.pending if x[0] <= d - 2]
            if old:
                per.pending.remove(old[0])
                full, ws = old[0][1], old[0][2]
            else:
                per.legacy += 1
                full, ws = f"main.legacy.old_fn_{per.uid[-4:]}_{per.legacy}", rng.choice(p.workspaces)
            self._emit(rows, p, d, at(), "unityCatalog", "deleteFunction",
                       {"full_name_arg": full, "metastore_id": self.meta, "workspace_id": ws}, level=ACC)


def background(world: World, profile: dict, start: datetime, end: datetime, seed: int,
               scale: float = 1.0) -> Iterator[dict]:
    """Stream background rows in time order per day. `start`/`end` must be tz-aware (UTC)."""
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("start and end must be timezone-aware")
    gen = _Gen(world, profile, start.astimezone(UTC), end.astimezone(UTC), seed, scale)
    for day_rows in gen.days():
        yield from day_rows
