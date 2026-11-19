"""Demo target: where the audit table and the raw volume live."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DemoConfig:
    catalog: str
    schema: str
    audit_table: str | None = None

    @property
    def table(self) -> str:
        return self.audit_table or f"{self.catalog}.{self.schema}.audit"

    @property
    def demo_table(self) -> str:
        """The table load() writes; never the audit_table override."""
        return f"{self.catalog}.{self.schema}.audit"

    @property
    def volume_root(self) -> str:
        return f"/Volumes/{self.catalog}/{self.schema}/raw"
