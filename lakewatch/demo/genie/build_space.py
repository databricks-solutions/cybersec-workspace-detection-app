"""Write databricks_audit.geniespace.json (the Genie Agent of the demo) from the detection app's Genie Agent.

The app's own build (../../genie-agent/deploy/install.py at the repository root: build_serialized_space) puts every detection
function into the space as an example query. This script changes its output for the demo:

- system.access.audit becomes the placeholder table audit_demo_catalog.audit_demo.audit (the bundle's
  genie_agent_retarget mutator rewrites audit_demo_catalog.audit_demo to ${var.catalog}.${var.schema});
- the examples that read system.query.history are dropped (the demo has no query history);
- the tables principals and demo_signals, two example queries and a paragraph about the demo are added.

Usage: python genie/build_space.py [--check]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True   # keep the app's genie-agent/ free of __pycache__

HERE = Path(__file__).resolve().parent
OUT = HERE / "databricks_audit.geniespace.json"
INSTALL = HERE.parents[2] / "genie-agent" / "deploy" / "install.py"   # the app at the repository root

SOURCE = "audit_demo_catalog.audit_demo"       # data source identifiers are not quoted
S = "`audit_demo_catalog`.`audit_demo`"        # quoted in SQL, so that a catalog such as my-catalog works
AUDIT_SQL = f"{S}.`audit`"
AUDIT_TEXT = f"{SOURCE}.audit"
DROP_TABLE = "system.query.history"

# The text in the app's instructions that names system.query.history (its examples are dropped).
QUERY_HISTORY_TEXT = ("(`system.access.audit`, plus `system.query.history` for one detection).",
                      f"({AUDIT_TEXT}).")

TIME_PARAMS = [
    {"name": "start_time", "type_hint": "DATETIME", "default_value": {"values": ["now-30d/s"]}},
    {"name": "end_time", "type_hint": "DATETIME", "default_value": {"values": ["now/s"]}},
]

DEMO_TEXT = f"""
## This demo

- The data is a synthetic copy of the Databricks audit log system table for the fake company
  corp.example. The audit table is {AUDIT_TEXT}. It has the same columns as the system table.
- A service principal shows in `user_identity.email` as its application id (a UUID), not as a name.
  To show its name, join {SOURCE}.principals on `principals.email = audit.user_identity.email` and use
  `principals.display_name` (for example sp-etl-prod). `identity_metadata.run_as_display_name` also has
  the name on most rows. Always show the name together with the id.
- When the user names an identity (for example sp-etl-prod or maria.lopez), find it in `principals`
  first: match `display_name`, `email`, or the part of `email` before '@'. Then filter the audit table
  on that `email`.
- {SOURCE}.demo_signals has the Lakewatch detection signals of this demo, one row per signal:
  `rule`, `stage`, `actor` (the same value as `user_identity.email`), `actor_name`, `src_ip`,
  `event_time`. Stages: 1 access, 2 discovery, 3 secret harvest, 4 execution, 5 persistence,
  6 collection and clean-up, corr = correlation of several stages.
- Rules that start with `ada_` find attack stages and chains. Rules that start with `adp_` are
  single-event rules from the detection pack. They also fire on normal work, so one `adp_` signal
  alone is not an incident.
- For "were we compromised?" and other open questions: start with `demo_signals`. Rank the actors by
  the number of distinct stages of their `ada_` signals, and read the correlation rules
  `ada_identity_pivot_chain` and `ada_multi_stage_identity`. Name every identity in a chain (for
  example a user and the service principal that worked from the same IP address), not only the first.
  Then confirm the chain in the audit table with the trusted queries.
- For a question about one identity, also read its rows in `demo_signals`. Its `ada_` signals show
  the time and the IP address to look at first. Do not call the identity's activity normal before
  you have checked them.
- A sign-in with an OAuth token shows as `accounts.oidcTokenAuthorization`
  (`request_params.authenticationMethod` = API_OIDC_TOKEN), and a sign-in with a personal access
  token as `accounts.tokenLogin`. For "after it got an OAuth token", start from
  `oidcTokenAuthorization` and look for a new IP address or user agent.
- Before you call an action suspicious, compare it with the history of the same identity in the
  last 14 days: the same action, the same hour, the same IP range and the same user agent. Work that
  repeats on a schedule, or that an admin does from their usual IP address and browser, is a likely
  normal explanation. Say so.
- Always name the objects of an action from `request_params`: the group (`targetGroupName`) and the
  added principal (`targetUserName`) of a group change, the scope and key of a secret, the path of an
  export (`notebookFullPath`), the function name of a function change.
- Time: use `current_timestamp()` as now. A demo reset loads data that ends at the reset time. If the
  newest `event_time` in the audit table is more than one day before `current_timestamp()`, use that
  newest `event_time` as now. In this demo, time words are rolling windows that end at now: "today"
  and "yesterday" = the last 24 hours, "last week" = the last 7 days, "last 90 days" = 90 days.
"""

TIMELINE_SQL = f"""WITH actor AS (
  SELECT email
  FROM {S}.`principals`
  WHERE lower(:actor) IN (lower(email), lower(display_name), lower(split_part(email, '@', 1)))
),
actor_ips AS (
  SELECT DISTINCT a.source_ip_address AS ip
  FROM {AUDIT_SQL} AS a
  JOIN actor ON a.user_identity.email = actor.email
  WHERE a.event_time BETWEEN :start_time AND :end_time
),
shared_ips AS (
  SELECT a.source_ip_address AS ip
  FROM {AUDIT_SQL} AS a
  JOIN actor_ips AS i ON a.source_ip_address = i.ip
  WHERE a.event_time BETWEEN :start_time AND :end_time
  GROUP BY a.source_ip_address
  HAVING count(DISTINCT a.user_identity.email) BETWEEN 2 AND 5
)
SELECT
  a.event_time,
  coalesce(p.display_name, a.user_identity.email) AS identity,
  a.user_identity.email AS identity_id,
  a.source_ip_address,
  a.service_name,
  a.action_name,
  a.response.status_code AS status_code,
  a.user_agent,
  a.request_params
FROM {AUDIT_SQL} AS a
JOIN shared_ips AS s ON a.source_ip_address = s.ip
LEFT JOIN {S}.`principals` AS p ON p.email = a.user_identity.email
WHERE a.event_time BETWEEN :start_time AND :end_time
ORDER BY a.event_time
LIMIT 500"""

AFTER_SECRETS_SQL = f"""WITH reads AS (
  SELECT actor, src_ip, min(event_time) AS read_time
  FROM {S}.`demo_signals`
  WHERE stage = '3' AND startswith(rule, 'ada_') AND coalesce(src_ip, '') <> ''
    AND event_time BETWEEN :start_time AND :end_time
  GROUP BY actor, src_ip
)
SELECT
  coalesce(rp.display_name, r.actor) AS secret_reader,
  r.src_ip,
  r.read_time,
  a.event_time,
  coalesce(p.display_name, a.user_identity.email) AS identity,
  a.user_identity.email AS identity_id,
  a.service_name,
  a.action_name,
  a.response.status_code AS status_code,
  a.user_agent,
  a.request_params
FROM reads AS r
JOIN {AUDIT_SQL} AS a
  ON a.source_ip_address = r.src_ip
  AND a.event_time > r.read_time
  AND a.event_time <= r.read_time + INTERVAL 24 HOURS
LEFT JOIN {S}.`principals` AS p ON p.email = a.user_identity.email
LEFT JOIN {S}.`principals` AS rp ON rp.email = r.actor
ORDER BY a.event_time
LIMIT 500"""

# (id, question, sql, extra parameters, usage guidance)
DEMO_EXAMPLES = [
    ("e0000000000000000000000000000001",
     "Show the full timeline for an identity and every identity that shared its IP addresses",
     TIMELINE_SQL,
     [{"name": "actor", "type_hint": "STRING", "default_value": {"values": ["maria.lopez"]}}],
     "Timeline of all audit events from the IP addresses that the identity used and that 2 to 5 "
     "identities shared in the window (an IP address that many identities use is a corporate egress, "
     "not a lead). Set :actor to a name, an email, or the part of the email before '@'. Use for: "
     "timeline for a user and every identity that shared their IP, who else used this IP, pivot from a "
     "user to a service principal, identity pivot, what happened from the attacker IP. If it returns "
     "no rows, the identity shared no IP address: use the trusted detection queries for that identity."),
    ("e0000000000000000000000000000002",
     "What did the attacker do after reading secrets?",
     AFTER_SECRETS_SQL,
     [],
     "Starts from the secret-harvest signals (stage 3, ada_ rules) in demo_signals and lists every "
     "audit event from the same IP address in the 24 hours after the first read, by any identity. "
     "Use for: what happened after secrets were read, what did the attacker do next, how were the "
     "stolen secrets used, events after the secret harvest."),
]

SAMPLES = [
    "Were we compromised in the last 90 days?",
    "What did the attacker do after reading secrets?",
    "Show the timeline for maria.lopez and every identity that shared her IPs",
    "Who was added to the admins group?",
    "Is the nightly secret listing by sp-ci-deploy suspicious?",
]

TABLE_COLUMNS = {
    "demo_signals": [
        {"column_name": "actor", "description": ["Identity of the signal: the same value as "
                                                 "audit.user_identity.email (a UUID for a service principal)."]},
        {"column_name": "actor_name", "synonyms": ["identity name", "display name"],
         "enable_entity_matching": True},
        {"column_name": "rule", "enable_entity_matching": True, "synonyms": ["detection", "rule name"]},
        {"column_name": "src_ip", "synonyms": ["source IP", "attacker IP"]},
        {"column_name": "stage", "enable_format_assistance": True,
         "description": ["1 access, 2 discovery, 3 secret harvest, 4 execution, 5 persistence, "
                         "6 collection and clean-up, corr = correlation."]},
    ],
    "principals": [
        {"column_name": "display_name", "enable_entity_matching": True, "synonyms": ["name", "identity"]},
        {"column_name": "email", "description": ["The value of audit.user_identity.email: an email for "
                                                 "a user, the application id (UUID) for a service principal."]},
        {"column_name": "kind", "enable_format_assistance": True,
         "description": ["user or sp (service principal)."]},
    ],
}


def _hex(prefix: str, n: int) -> str:
    return f"{prefix}{n:0{32 - len(prefix)}x}"


def _lines(text: str) -> list[str]:
    lines = text.strip("\n").split("\n")
    return [line + "\n" for line in lines[:-1]] + [lines[-1]]


def _app_space() -> dict:
    spec = importlib.util.spec_from_file_location("auditdemo_app_install", INSTALL)
    install = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(install)
    return json.loads(install.build_serialized_space())


def _text(text: str) -> str:
    # A whole name in backticks reads as one quoted part to the retarget mutator: drop the backticks.
    return text.replace("`system.access.audit`", AUDIT_TEXT).replace("system.access.audit", AUDIT_TEXT)


def _replace_audit(node, in_sql: bool = False):
    """Replace system.access.audit everywhere: quoted placeholder in SQL, plain name in text."""
    if isinstance(node, dict):
        return {k: _replace_audit(v, in_sql or k == "sql") for k, v in node.items()}
    if isinstance(node, list):
        return [_replace_audit(v, in_sql) for v in node]
    if isinstance(node, str):
        return node.replace("system.access.audit", AUDIT_SQL) if in_sql else _text(node)
    return node


def build() -> dict:
    space = _app_space()
    ins = space["instructions"]

    examples = [e for e in ins["example_question_sqls"] if DROP_TABLE not in "".join(e["sql"])]
    tables = [t for t in space["data_sources"]["tables"] if t["identifier"] != DROP_TABLE]
    assert [t["identifier"] for t in tables] == ["system.access.audit"], tables

    text = "".join(ins["text_instructions"][0]["content"])
    old, new = QUERY_HISTORY_TEXT
    if old not in text:
        raise SystemExit("the app's instructions changed: update QUERY_HISTORY_TEXT in build_space.py")
    text = _text(text.replace(old, new) + DEMO_TEXT)

    space = _replace_audit({**space, "data_sources": {"tables": tables},
                            "instructions": {**ins, "example_question_sqls": examples}})
    space["data_sources"]["tables"][0]["identifier"] = AUDIT_TEXT
    space["data_sources"]["tables"] += [
        {"identifier": f"{SOURCE}.{name}", "column_configs": sorted(cols, key=lambda c: c["column_name"])}
        for name, cols in TABLE_COLUMNS.items()]
    space["data_sources"]["tables"].sort(key=lambda t: t["identifier"])

    examples = space["instructions"]["example_question_sqls"]
    examples += [{"id": i, "question": [q], "sql": _lines(sql), "parameters": TIME_PARAMS + extra,
                  "usage_guidance": [g]} for i, q, sql, extra, g in DEMO_EXAMPLES]
    examples.sort(key=lambda e: e["id"])   # the API rejects an unsorted list
    space["instructions"]["text_instructions"] = [{"id": _hex("c", 1), "content": _lines(text)}]
    space["config"] = {"sample_questions": [{"id": _hex("a", i), "question": [q]}
                                            for i, q in enumerate(SAMPLES, 1)]}
    return {"version": space["version"], "config": space["config"],
            "data_sources": space["data_sources"], "instructions": space["instructions"]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if the JSON file is out of date")
    args = ap.parse_args(argv)
    text = json.dumps(build(), indent=2) + "\n"
    if args.check:
        if not OUT.exists() or OUT.read_text() != text:
            print(f"out of date: {OUT} (run python genie/build_space.py)", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
