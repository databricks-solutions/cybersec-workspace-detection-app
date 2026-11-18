"""Bundle resources in Python: the Genie Agent, only when `--var genie=true`.

The space reads the demo tables (audit, principals, demo_signals), which exist only after the first
reset. So the first `databricks bundle deploy` leaves it out (genie=false, the default), and a later
deploy with `--var genie=true` creates it. The space file uses the placeholder names
`audit_demo_catalog.audit_demo`; the genie_agent_retarget mutator rewrites them to
${var.catalog}.${var.schema}.
"""
from __future__ import annotations

from databricks.bundles.core import Bundle, Resources, Variable, variables

from resources_py.genie import genie_space


@variables
class Variables:
    genie: Variable[bool]


def load_resources(bundle: Bundle) -> Resources:
    resources = Resources()
    if bundle.resolve_variable(Variables.genie):
        resources.add_genie_space("databricks_audit", genie_space())
    return resources
