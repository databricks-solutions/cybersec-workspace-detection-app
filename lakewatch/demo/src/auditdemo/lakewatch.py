"""Lakewatch v2 REST base path and the SDK-backed api (REST, volume upload, SQL).

Copied from identity-graph-demo/src/igdemo/lakewatch.py (each demo package is standalone); only
BASE and SdkApi are kept.
"""

from __future__ import annotations

import time
from pathlib import Path

BASE = "/api/2.0/lakewatch"


class SdkApi:
    """The real api: Databricks SDK REST calls, volume upload and SQL."""

    def __init__(self, profile: str | None = None):
        """profile None: default auth (environment, or the identity of a job)."""
        from databricks.sdk import WorkspaceClient
        self.w = WorkspaceClient(profile=profile) if profile else WorkspaceClient()

    def do(self, method, path, *, query=None, body=None):
        return self.w.api_client.do(method, path, query=query, body=body) or {}

    def exists(self, volume_path: str) -> bool:
        from databricks.sdk.errors import NotFound
        try:
            self.w.files.get_metadata(volume_path)
            return True
        except NotFound:
            return False

    def mkdirs(self, volume_path: str) -> None:
        """Create a volume folder and its parents (no error if it exists)."""
        self.w.files.create_directory(volume_path.rstrip("/"))

    def delete_dir(self, volume_path: str) -> None:
        """Delete the files in a volume folder (no error if the folder is missing)."""
        from databricks.sdk.errors import NotFound
        base = volume_path.rstrip("/")
        try:
            entries = list(self.w.files.list_directory_contents(base))
        except NotFound:
            return
        for e in entries:
            if e.is_directory:
                self.delete_dir(e.path)
                self.w.files.delete_directory(e.path)
            else:
                self.w.files.delete(e.path)

    def upload(self, volume_path: str, local_path: Path) -> None:
        with open(local_path, "rb") as fh:
            self.w.files.upload(volume_path, fh, overwrite=True)

    def sql(self, statement: str, warehouse_id: str) -> list[list]:
        from databricks.sdk.service.sql import StatementState
        resp = self.w.statement_execution.execute_statement(
            statement=statement, warehouse_id=warehouse_id, wait_timeout="50s")
        while resp.status.state in (StatementState.PENDING, StatementState.RUNNING):
            time.sleep(2)
            resp = self.w.statement_execution.get_statement(resp.statement_id)
        if resp.status.state != StatementState.SUCCEEDED:
            raise RuntimeError(resp.status.error.message if resp.status.error else str(resp.status.state))
        return (resp.result.data_array or []) if resp.result else []
