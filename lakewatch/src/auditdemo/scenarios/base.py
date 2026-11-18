"""Scenario interface: a planted attack or decoy that produces audit rows."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from ..world import World


class Scenario(Protocol):
    key: str  # S1 ... D2
    expected_rules: set[str]
    forbidden_rules: set[str]

    def actors(self, world: World) -> set[str]:
        """user_identity.email values whose signals belong to this scenario."""
        ...

    def rows(self, world: World, anchor: datetime) -> list[dict]:
        """Deterministic rows for (world, anchor). T = anchor."""
        ...
