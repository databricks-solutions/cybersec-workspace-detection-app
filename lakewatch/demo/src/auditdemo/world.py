"""Fake org: workspaces, users, service principals, IP ranges, tokens.

Everything derives from one seed, so the same seed gives the same org.
"""

from __future__ import annotations

import hashlib
import ipaddress
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

IP_RANGES = {
    "corp": "10.20.0.0/16",
    "vpn": "10.99.0.0/16",
    "ci": "172.20.10.0/24",
    "cloud": "172.31.0.0/16",
}
ATTACKER_RANGES = ("203.0.113.0/24", "198.51.100.0/24")

FIRST = [
    "Ivan", "Elena", "Noah", "Mia", "Lucas", "Sofia", "Omar", "Priya", "Jonas", "Chloe",
    "Kenji", "Laura", "Diego", "Hana", "Pavel", "Nina", "Felix", "Aisha", "Marco", "Greta",
    "Samir", "Julia", "Oscar", "Rita", "Viktor", "Lena", "Tariq", "Emma", "Hugo", "Yuki",
    "Carla", "Dmitri", "Alma", "Boris", "Zoe", "Rafael", "Ingrid", "Leo", "Mona", "Arjun",
]
LAST = [
    "Novak", "Keller", "Moreau", "Tanaka", "Rossi", "Ivanova", "Haddad", "Nilsson", "Park",
    "Costa", "Weber", "Singh", "Duarte", "Kowalski", "Berg", "Okafor", "Mendez", "Fischer",
    "Petrov", "Larsen", "Nakamura", "Ferrari", "Yilmaz", "Dubois", "Horvat", "Ribeiro", "Brandt",
    "Ito", "Vasquez", "Lindqvist", "Popescu", "Hansen", "Santos", "Meyer", "Zhou", "Bauer",
    "Rinaldi", "Olsen", "Kaya", "Marin",
]

# (display_name, role, workspaces by name)
NAMED_USERS = [
    ("Maria Lopez", "maria.lopez@corp.example", "data_engineer", ("prod", "dev")),
    ("Tom Becker", "tom.becker@corp.example", "analyst", ("analytics", "prod")),
    ("Ana Silva", "ana.silva@corp.example", "admin", ("prod", "dev", "analytics")),
]
SERVICE_PRINCIPALS = [
    ("sp-etl-prod", "etl", ("prod",)),
    ("sp-reporting", "reporting", ("analytics", "prod")),
    ("sp-ci-deploy", "ci", ("prod", "dev")),
    ("sp-ml-batch", "ml", ("prod", "analytics")),
    ("sp-etl-dev", "etl", ("dev",)),
    ("sp-bi-dashboards", "bi", ("analytics",)),
    ("sp-ml-training", "ml", ("dev", "analytics")),
    ("sp-bi-refresh", "bi", ("analytics", "prod")),
]
N_USERS = 40


@dataclass(frozen=True)
class Principal:
    email: str
    display_name: str
    kind: Literal["user", "sp"]
    role: str
    home_ips: list[str] = field(default_factory=list)
    workspaces: list[str] = field(default_factory=list)
    pat_ids: list[str] = field(default_factory=list)


def _uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def _hex32(rng: random.Random) -> str:
    return f"{rng.getrandbits(128):032x}"


def _ips(rng: random.Random, cidr: str, n: int) -> list[str]:
    net = ipaddress.ip_network(cidr)
    out: list[str] = []
    while len(out) < n:
        ip = str(net[rng.randrange(1, net.num_addresses - 1)])
        if ip not in out:
            out.append(ip)
    return out


class World:
    def __init__(self, seed: int):
        self.seed = seed
        rng = random.Random(seed)
        self.ip_ranges = dict(IP_RANGES)
        self.account_id = _uuid(rng)
        self.workspaces = {
            name: str(rng.randrange(10**15, 10**16))
            for name in ("prod", "dev", "analytics")
        }
        self.principals: list[Principal] = []
        self._build(rng)

    def _build(self, rng: random.Random) -> None:
        ws = self.workspaces
        for name, email, role, wss in NAMED_USERS:
            self.principals.append(self._user(rng, name, email, role, wss))
        names = [(f, l) for f in FIRST for l in LAST]
        rng.shuffle(names)
        used = {e for _, e, _, _ in NAMED_USERS}
        for first, last in names:
            if len(self.principals) >= N_USERS:
                break
            email = f"{first}.{last}".lower() + "@corp.example"
            if email in used:
                continue
            used.add(email)
            # about 1/4 engineers, 1/8 admins, rest analysts
            roll = rng.random()
            role = "data_engineer" if roll < 0.3 else "admin" if roll < 0.4 else "analyst"
            wss = tuple(rng.sample(list(ws), rng.choice([1, 2])))
            self.principals.append(self._user(rng, f"{first} {last}", email, role, wss))
        for name, role, wss in SERVICE_PRINCIPALS:
            net = "ci" if role == "ci" else "cloud"
            self.principals.append(
                Principal(
                    email=_uuid(rng),
                    display_name=name,
                    kind="sp",
                    role=role,
                    home_ips=_ips(rng, self.ip_ranges[net], 2),
                    workspaces=[ws[w] for w in wss],
                    pat_ids=[_hex32(rng) for _ in range(rng.choice([1, 2]))],
                )
            )

    def _user(self, rng, name, email, role, wss) -> Principal:
        home = _ips(rng, self.ip_ranges["corp"], 2) + _ips(rng, self.ip_ranges["vpn"], 1)
        uses_pat = role in ("data_engineer", "admin") or rng.random() < 0.3
        return Principal(
            email=email,
            display_name=name,
            kind="user",
            role=role,
            home_ips=home,
            workspaces=[self.workspaces[w] for w in wss],
            pat_ids=[_hex32(rng) for _ in range(rng.choice([1, 2]))] if uses_pat else [],
        )

    def by_role(self, role: str) -> list[Principal]:
        return [p for p in self.principals if p.role == role]

    def get(self, key: str) -> Principal:
        """Look up by display name or email."""
        for p in self.principals:
            if key in (p.display_name, p.email):
                return p
        raise KeyError(key)

    def attacker_ips(self, anchor: datetime) -> list[str]:
        """4 distinct IPs (2 per TEST-NET range) for the anchor's hour.

        A hash of a fixed salt sets the starting point; the hour index then
        steps through the hosts, so anchors up to ~127 h apart never share an IP.
        """
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=timezone.utc)
        hour = int(anchor.timestamp()) // 3600
        out: list[str] = []
        for i, cidr in enumerate(ATTACKER_RANGES):
            net = ipaddress.ip_network(cidr)
            salt = int.from_bytes(hashlib.sha256(f"attacker-{i}".encode()).digest()[:4], "big")
            for k in range(2):
                host = 1 + (37 * (2 * hour + k) + salt) % 254  # 37 is coprime to 254
                out.append(str(net[host]))
        return out
