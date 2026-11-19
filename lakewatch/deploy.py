# /// script
# requires-python = ">=3.10"
# dependencies = ["databricks-sdk>=0.40", "pyyaml>=6"]
# ///
"""Deploy the Lakewatch rules in lakewatch/rules/*.yaml to a Lakewatch environment.

    uv run lakewatch/deploy.py --profile <cli-profile> --catalog <lakewatch catalog> \\
        --schema detection --warehouse-id <id> [--run-as <sp-application-id>] \\
        [--enable | --disable] [--only NAME,...] [--prune | --prune-delete] [--dry-run] [--name-prefix test_]

Each rule file is rendered ({{catalog}}, {{schema}}, {{warehouse_id}}, {{audit_table}}), checked with
the rules API dry run (rules:validateRule, which also runs the SQL on the warehouse), then created,
or updated when its content changed. Deploy is idempotent and safe to re-run:

- Every deployed rule carries two annotations: managed_by=cybersec-workspace-detection-app and
  content_hash (a hash of the rendered rule without its enabled state or run-as). A rule whose hash matches
  is skipped.
- An update sends an explicit update_mask with only the top-level fields this repository owns.
  Fields an analyst sets in the Lakewatch UI (suppress_until_time, run_as_principal) are not in the
  mask, and the rule keeps its current enabled state unless --enable/--disable is given.
- --prune disables rules in the schema that carry managed_by=cybersec-workspace-detection-app but no
  longer have a file here. Disabling keeps the rule's alerts and history. --prune-delete deletes
  those rules instead; deleting a Lakewatch rule also deletes its alerts. Rules this script did not
  create are never touched.

New rules are created DISABLED unless --enable is given: back-test first (see SETUP.md).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
RULES_DIR = HERE / "rules"
BASE = "/api/2.0/lakewatch"
MANAGED_BY = "cybersec-workspace-detection-app"
IDENTITY = ("catalog_name", "schema_name", "rule_name")
# Top-level fields the repository owns. An update keeps the rule's current schedule.enabled unless
# --enable/--disable is given, so masking the whole schedule never flips an analyst's choice.
OWNED = ("description", "severity", "category", "fidelity", "objective", "mitre", "deduplication",
         "deduplication_time_window", "schedule", "timerange", "batch", "output", "annotations",
         "runbook", "references")


def quote_table(name: str) -> str:
    return ".".join(f"`{p.strip('`')}`" for p in name.split("."))


def render(path: Path, catalog: str, schema: str, warehouse_id: str, audit_table: str) -> dict:
    values = {"catalog": catalog, "schema": schema, "warehouse_id": warehouse_id,
              "audit_table": quote_table(audit_table)}
    text = re.sub(r"\{\{\s*(\w+)\s*\}\}", lambda m: values[m.group(1)], path.read_text())
    return yaml.safe_load(text)


def content_hash(rule: dict) -> str:
    # run_as_principal is left out so a deploy with or without --run-as hashes the same rule the same.
    body = {k: v for k, v in rule.items() if k not in ("annotations", "run_as_principal")}
    body["schedule"] = {k: v for k, v in (rule.get("schedule") or {}).items() if k != "enabled"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


def with_annotations(rule: dict) -> dict:
    ann = {**(rule.get("annotations") or {}), "managed_by": MANAGED_BY, "content_hash": content_hash(rule)}
    return {**rule, "annotations": ann}


def list_rules(api, catalog: str) -> list[dict]:
    out, token = [], None
    while True:
        query = {"catalog_name": catalog, "page_size": 100, **({"page_token": token} if token else {})}
        page = api.do("GET", f"{BASE}/rules", query=query) or {}
        out += page.get("rules", [])
        token = page.get("next_page_token")
        if not token:
            return out


def mask_for(rule: dict) -> list[str]:
    return [f for f in OWNED if f in rule]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", required=True, help="Databricks CLI profile of the Lakewatch workspace")
    ap.add_argument("--catalog", required=True, help="The Lakewatch environment's Unity Catalog catalog")
    ap.add_argument("--schema", default="detection", help="Schema (Lakewatch folder) for the rules")
    ap.add_argument("--warehouse-id", required=True, help="SQL warehouse the rules run on")
    ap.add_argument("--audit-table", default="system.access.audit",
                    help="Table the rules read (default system.access.audit)")
    state = ap.add_mutually_exclusive_group()
    state.add_argument("--enable", action="store_true", help="enable the deployed rules")
    state.add_argument("--disable", action="store_true", help="disable the deployed rules")
    ap.add_argument("--only", default="", help="comma-separated rule names (default: all files)")
    prune = ap.add_mutually_exclusive_group()
    prune.add_argument("--prune", action="store_true",
                       help=f"disable {MANAGED_BY} rules that have no file here (keeps their alerts)")
    prune.add_argument("--prune-delete", action="store_true",
                       help=f"delete {MANAGED_BY} rules that have no file here (also deletes their alerts)")
    ap.add_argument("--dry-run", action="store_true", help="validate only; create, update and delete nothing")
    ap.add_argument("--run-as", default="",
                    help="run the rules as this service principal (application ID); see SETUP.md step 7")
    ap.add_argument("--name-prefix", default="",
                    help="prefix every rule name, e.g. test_ to trial the rules next to deployed ones")
    a = ap.parse_args()

    from databricks.sdk import WorkspaceClient

    api = WorkspaceClient(profile=a.profile).api_client
    only = {x.strip() for x in a.only.split(",") if x.strip()}
    files = sorted(p for p in RULES_DIR.glob("*.yaml") if not only or p.stem in only)
    if only - {p.stem for p in files}:
        print(f"unknown rule(s): {sorted(only - {p.stem for p in files})}", file=sys.stderr)
        return 2
    existing = {(r.get("schema_name"), r.get("rule_name")): r for r in list_rules(api, a.catalog)}
    set_enabled = a.enable or a.disable
    counts = {"created": 0, "updated": 0, "unchanged": 0, "pruned": 0, "failed": 0}

    for path in files:
        rule = render(path, a.catalog, a.schema, a.warehouse_id, a.audit_table)
        rule["rule_name"] = a.name_prefix + rule["rule_name"]
        if a.run_as:
            rule["run_as_principal"] = a.run_as
        rule = with_annotations(rule)
        if set_enabled:
            rule["schedule"] = {**rule["schedule"], "enabled": bool(a.enable)}
        found = existing.get((a.schema, rule["rule_name"]))
        try:
            if found is None:
                api.do("POST", f"{BASE}/rules:validateRule", body={"rule": rule, "warehouse": a.warehouse_id})
                if not a.dry_run:
                    api.do("POST", f"{BASE}/rules", body=rule)
                counts["created"] += 1
                print(f"created   {rule['rule_name']}" + (" (dry run)" if a.dry_run else ""))
                continue
            same = (found.get("annotations") or {}).get("content_hash") == rule["annotations"]["content_hash"]
            same_state = not set_enabled or bool((found.get("schedule") or {}).get("enabled")) == bool(a.enable)
            if same and same_state:
                counts["unchanged"] += 1
                print(f"unchanged {rule['rule_name']}")
                continue
            if (found.get("annotations") or {}).get("managed_by") not in (None, MANAGED_BY):
                print(f"skipped   {rule['rule_name']}: managed by {found['annotations']['managed_by']}")
                continue
            if not set_enabled:  # keep the state the rule has now
                rule["schedule"] = {**rule["schedule"], "enabled": bool((found.get("schedule") or {}).get("enabled"))}
            mask = ",".join(mask_for(rule) + (["run_as_principal"] if a.run_as else []))
            fields = {k: v for k, v in rule.items() if k not in IDENTITY}
            api.do("POST", f"{BASE}/rules:validateRule",
                   body={"rule": {**rule, "name": found["name"]}, "warehouse": a.warehouse_id, "update_mask": mask})
            if not a.dry_run:
                api.do("PATCH", f"{BASE}/{found['name']}", query={"update_mask": mask}, body=fields)
            counts["updated"] += 1
            print(f"updated   {rule['rule_name']}" + (" (dry run)" if a.dry_run else ""))
        except Exception as ex:  # report every rule, then fail at the end
            counts["failed"] += 1
            print(f"FAILED    {rule['rule_name']}: {str(ex)[:500]}", file=sys.stderr)

    if a.prune or a.prune_delete:
        names = {a.name_prefix + p.stem for p in RULES_DIR.glob("*.yaml")}
        for (schema, name), r in existing.items():
            if not (schema == a.schema and name.startswith(a.name_prefix) and name not in names
                    and (r.get("annotations") or {}).get("managed_by") == MANAGED_BY):
                continue
            enabled = bool((r.get("schedule") or {}).get("enabled"))
            if a.prune and not enabled:
                print(f"orphaned  {name} (already disabled)")
                continue
            try:
                if not a.dry_run:
                    if a.prune_delete:
                        api.do("DELETE", f"{BASE}/{r['name']}")
                    else:
                        api.do("PATCH", f"{BASE}/{r['name']}", query={"update_mask": "schedule"},
                               body={"schedule": {**(r.get("schedule") or {}), "enabled": False}})
                counts["pruned"] += 1
                verb = "deleted " if a.prune_delete else "disabled"
                print(f"{verb}  {name}" + (" (dry run)" if a.dry_run else ""))
            except Exception as ex:
                counts["failed"] += 1
                print(f"FAILED    {name}: {str(ex)[:500]}", file=sys.stderr)

    print(" ".join(f"{k}={v}" for k, v in counts.items()))
    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
