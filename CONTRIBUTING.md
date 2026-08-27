# Contributing

Thanks for contributing. This repo is **public** and customer-facing: people
install these detections into their own Databricks accounts and act on the
results during real investigations. That shapes most of what follows.

## The one rule that matters most

**A detection that returns fewer rows than it should is worse than no detection.**

During an incident, an empty result reads as *"nothing happened."* A filter that
silently misses events, or a `request_params` key that does not exist, produces
exactly that — a confident, clean-looking answer that is wrong. Several bugs found
in this repo were of precisely this shape, and none of them would have been caught
by reading the code.

So: **run your detection against real audit data before opening a PR.**

## Before you open a PR

1. **Execute it** against a real workspace over a window you know contains
   activity. Note the row count in your PR description.
2. **Verify every `request_params` key against live data.** They do **not** match
   the REST API field names, and a wrong key returns `NULL` rather than erroring:
   ```sql
   SELECT action_name, map_keys(request_params)
   FROM system.access.audit
   WHERE action_name = '<your action>' LIMIT 5
   ```
3. **Check your `service_name` filter is not too narrow.** Measured on a real
   workspace, `runCommand` appears 396,612 times under `service_name='jobs'` and
   776 times under `'notebook'`. A detection filtering only `notebook` misses
   99.8% of command executions — including anything an attacker scheduled as a
   job.
4. **Say what your false positives are** in the `dscc` YAML block. Every
   detection has some; naming them is what makes the detection usable.
5. **If your detection is high-volume, aggregate it.** One detection here returned
   242,738 rows from 6 actors before it was aggregated per actor and day. Anything
   that large is unreadable and will truncate.

## Adding a detection

Detections live in `base/detections/{event-based,behavioral}/` as notebooks with a
`dscc` YAML metadata block. Copy an existing one — the metadata is machine-read
(the Genie Agent's catalog is generated from it), so keep the shape.

Fill in honestly:

- `severity` / `fidelity` — a triage hint, not a verdict
- `taxonomy` — MITRE technique(s)
- `false_positives` — what will legitimately fire this
- `objective` — what an analyst learns from a hit

Add it to `lib/threat_model_mappings.py` under the threat models it serves, and to
`docs/detection_tracker.md`.

**Do not bake your own account's allowlist into a shipped detection.** One
notebook excludes a specific `user_agent` and source IP for a known internal job;
shipping that pattern would silently hide real activity in every other customer's
account. Return the columns and let the caller filter.

## Adding to the Genie Agent

If your detection should also be answerable in natural language, port it to a UC
SQL function in `genie-agent/functions/`. Read
[`genie-agent/docs/PORTING.md`](genie-agent/docs/PORTING.md) first — it documents
the traps, several of which fail obscurely:

- A SQL UDF body cannot begin with a top-level `WITH` (wrap the CTE in a subquery)
- `IN (SELECT explode(...))` creates on a SQL warehouse but **fails** in a UDF body
  on DBR — use `array_contains(transform(split(...)))`
- Fully qualify function names; a bare `CREATE FUNCTION` can land in
  `hive_metastore`, where it cannot reference `system.access.audit`

**Test both install paths.** The notebook installer and the CLI installer use
different engines (DBR vs DBSQL) and are not interchangeable — a bug was found
that affected one and not the other.

## Review and merge

- Open a PR against `main`. `.github/CODEOWNERS` auto-requests the right
  reviewers.
- **Say what you tested and on what data.** "Ran over 90 days on a live
  workspace, 47 rows, no false positives" is worth more than any description of
  the logic.
- Squash-merge preferred. Branches are deleted on merge.

## Security

Do not open a public issue for a vulnerability — see
[`SECURITY.md`](SECURITY.md).

**Never commit real audit data, credentials, tokens, or customer identifiers.**
Secret scanning with push protection is enabled on this repo and will block a
push containing a recognised secret, but it cannot recognise everything: sanitise
your examples. Use placeholder emails and RFC5737 documentation IPs
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) rather than real ones from
your own logs.
