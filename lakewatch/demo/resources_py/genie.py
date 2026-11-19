"""The Genie Agent of the demo (Agent mode). Content: genie/databricks_audit.geniespace.json."""
from __future__ import annotations

from pathlib import Path

from databricks.bundles.genie_spaces import GenieSpace

SPACE_FILE = Path(__file__).resolve().parents[1] / "genie" / "databricks_audit.geniespace.json"
TITLE = "Databricks audit demo"
DESCRIPTION = ("Investigate the planted credential attacks of the Databricks audit demo (a synthetic audit "
               "log for corp.example): the detection queries of the workspace detection app, the principals, "
               "and the Lakewatch detection signals of the demo.")


def genie_space() -> GenieSpace:
    return GenieSpace(
        title=TITLE,
        description=DESCRIPTION,
        warehouse_id="${var.warehouse_id}",
        parent_path="/Workspace/Users/${workspace.current_user.userName}/databricks-audit-demo",
        serialized_space=SPACE_FILE.read_text(),
    )
