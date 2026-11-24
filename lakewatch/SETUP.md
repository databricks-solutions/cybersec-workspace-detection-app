# Lakewatch setup: from scratch to running detections

This guide takes a Databricks workspace with no Lakewatch to running two sets of detection rules on your
`system.access.audit` table: the Databricks rules in Lakewatch's Content library, and the rules in this folder
(`lakewatch/rules/`). Follow the steps in order. Each step ends with a **Check** — don't move on until it passes.

> **Lakewatch is in Beta.** It is provided as-is and is not intended for production use. Detection content in
> this repo is provided as-is under the repo license.

## What you need

| Requirement | Who usually has it |
|---|---|
| Workspace admin on the target workspace (also creates the run-as service principal in Step 7) | Platform team |
| Metastore admin (to grant read on `system.access.audit`) | Platform / data governance team |
| Databricks CLI **v1.25.0 or later** | You |
| Unity Catalog enabled on the workspace | — |
| Serverless compute for jobs and serverless SQL warehouses, allowed for the Lakewatch users and the run-as service principal (Step 2) | Workspace admin; account admin only if serverless is off for the account |

Your audit logs do **not** need to be ingested. Lakewatch rules read the `system.access.audit` system table directly.

---

## Step 0 — Before you start: check platform status

Lakewatch setup, rules, and the detection warehouse all depend on serverless compute.
Open https://status.databricks.com and confirm there's no open incident for **Compute** or **Databricks SQL**
in your region. If there is, wait — setup can hang or fail while serverless compute can't start.

## Step 1 — Install or upgrade the Databricks CLI

```bash
brew upgrade databricks        # or: brew install databricks
databricks -v                  # must print v1.25.0 or later
databricks auth login --host https://<your-workspace-url> --profile <ws-profile>
# Only if you use the account-level alternative in Step 7:
databricks auth login --host https://accounts.cloud.databricks.com --account-id <account-id> --profile <acct-profile>
```
**Check:** `databricks lakewatch --help` lists commands such as `create-rule` and `list-rules`.

## Step 2 — Confirm serverless compute is available

Lakewatch uses two kinds of serverless compute, and they are configured separately: serverless compute for jobs
(Lakewatch's datasource and rule jobs) and serverless SQL warehouses (the detection warehouse in Step 4).

- **Account:** **Accounts Console → Settings → Feature enablement → Serverless compute → On** (account admin).
  Accounts created after December 16, 2024 have it on by default.
- **Workspace:** a workspace admin can restrict serverless compute for users. In the workspace, open
  **Compute → Serverless** and make sure **Default Automated Compute** is allowed for the groups that use
  Lakewatch and for the run-as service principal (Step 7).
- The *Serverless compute* toggle on the workspace **Previews** page is a different setting — it is not the one
  Lakewatch needs.

**Check:** as a Lakewatch user who isn't a workspace admin, you can start a serverless SQL warehouse and run a
notebook on serverless compute.

## Step 3 — Turn on the Lakewatch preview

As a workspace admin: click your **username** in the top bar → **Previews** → turn on **Lakewatch**.

**Check:** the **app switcher** in the top navigation bar lists **Lakewatch**. (Lakewatch is not in the workspace sidebar.)

## Step 4 — Create a detection warehouse

Detection rules run on a SQL warehouse you provide. Use a dedicated one so detection cost is easy to attribute.

| Setting | Value |
|---|---|
| Type | Serverless |
| Size | 2X-Small |
| Min clusters | 1 |
| Max clusters | `ceil(number of active rules / 10)` |
| Auto stop | 10 minutes |

```bash
databricks warehouses create --profile <ws-profile> \
  --name lakewatch-detections --cluster-size 2X-Small --warehouse-type PRO \
  --enable-serverless-compute --min-num-clusters 1 --max-num-clusters 4 --auto-stop-mins 10
```

**Check:** on that warehouse, run
```sql
SELECT current_version().dbsql_version;
```
The result must be **2026.36 or later**, or Lakewatch rejects rules that use the warehouse.

## Step 5 — Set up Lakewatch

1. Open **Lakewatch** from the **app switcher** (top-right grid icon). Select a **serverless** warehouse under
   **Environment, workspace and compute** in the top bar — setup won't continue without one.
2. On **Welcome to Lakewatch → Configuration**, the **Recommended configuration** tab is selected by default. Its text says
   the environment "allows everyone in this workspace to administer it". Select **Custom configuration** instead.
3. **Environment:** create a new catalog. In a metastore shared with other workspaces, use a workspace-specific name
   (for example `lakewatch_<workspace>`) — catalog names are unique across the metastore. Requires `CREATE CATALOG`
   on the metastore, or `MANAGE` + `CREATE SCHEMA` on an existing catalog. A new catalog is bound to this workspace only.
4. **Folders:** keep `datasources` and `detection` (separate folders keep read/edit permissions separable).
5. ⚠️ **Admins: remove "All account users".** Custom configuration *starts from the Recommended settings*, so the
   Admins section is pre-filled with all account users. If you leave it, every user of the workspace gets `MANAGE`,
   `MODIFY`, `SELECT`, `CREATE RULE` and the Lakewatch security-data privileges on the whole catalog — they can read
   alerts and signals and edit or disable detection rules. Add only your security admin group (and yourself).
6. Select **Create**. You land on the Lakewatch **Overview** page.

**Check:**
```bash
databricks lakewatch list-rules <lakewatch_catalog> --profile <ws-profile>                   # returns [] (empty is fine)
databricks lakewatch get-rule-config catalogs/<lakewatch_catalog>/ruleConfig --profile <ws-profile>   # default_folder: detection
databricks workspace-bindings get <lakewatch_catalog> --profile <ws-profile>                 # only your workspace id
```
```sql
SHOW SCHEMAS IN <lakewatch_catalog>;            -- __lakewatch, datasources, default, detection, information_schema
SHOW GRANTS `account users` ON CATALOG <lakewatch_catalog>;
-- Expected: USE CATALOG and USE SCHEMA only (Lakewatch grants these so secrets can be created in __lakewatch).
-- If you see MANAGE / MODIFY / SELECT / CREATE RULE / READ SECURITY DATA for `account users`, fix it in two places
-- (removing the admin does NOT clear the folders):
--   a) Lakewatch → Settings → Environment → Lakewatch administrators: Revoke "All account users".
--   b) Same page → Folders: each folder (datasources, detection) shows "All account users (Folder admin)" →
--      Edit → remove it, until the folder shows "No principals" (or only your security groups).
--   Re-run the check. USE CATALOG / USE SCHEMA are Unity Catalog grants and don't appear in the Lakewatch UI — leave them.
```
Expected after the fix: Lakewatch administrators lists only your security group(s); folders show only intended principals.

## Step 6 — Confirm Lakewatch can read your audit logs

In Lakewatch, open **Query**, set the time picker to the last 24 hours, and run:
```sql
SELECT event_time, service_name, action_name, user_identity.email, source_ip_address
FROM system.access.audit
WHERE IN_TIMERANGE(event_time)
LIMIT 100
```
Expected: rows within the window you picked in **Select time range**. `IN_TIMERANGE(event_time)` takes its bounds from
the picker on the Query page and from the schedule when the same SQL runs as a rule — so you can test rule SQL here
unchanged. Times display in your browser's time zone; the data is UTC. For service principals,
`user_identity.email` holds the application ID (a UUID), not an email.

⚠️ Do **not** create a datasource for `system.access.audit` with the built-in **Databricks Audit** parser. That parser
is for audit-log-delivery JSON files; on the system table it fails with
`missing required fields: 'serviceName', 'actionName'`. No datasource is needed.

Measure how far the audit table lags real time — you'll use this for each rule's **extend lookback**:
```sql
SELECT max(event_time) AS latest_event, current_timestamp() AS now FROM system.access.audit;
```

Run the lag query a few times over an hour. On our test workspace it read 9–15 minutes, and the newest event stayed
the same for ~15 minutes at a time — the system table receives audit events in batches, not continuously. Set each
rule's **extend lookback** to comfortably more than the worst lag you see (we start at **30 minutes**); the 15-minute
default can silently miss late-arriving events.

**Check:** the query returns rows, and you've noted the worst lag (minutes).

## Step 7 — Create the run-as service principal

Rules run as their creator by default, which breaks them if that person leaves and blocks teammates from editing them.
Run production rules as a service principal.

7.1 As a workspace admin, create it and add it to the workspace (**Settings → Identity and access → Service
principals → Manage → Add service principal → Add new**), or:
```bash
databricks service-principals create --display-name lakewatch --active --profile <ws-profile>
# note the "applicationId" in the output
```
This adds it to the workspace as a user. Never add it to the `admins` group.

7.2 Alternative for account admins: create it in the account and assign it to the workspace as a **User**:
```bash
databricks account service-principals create --display-name lakewatch --active --profile <acct-profile>
databricks account workspace-assignment update <workspace-id> <sp-id> \
  --json '{"permissions":["USER"]}' --profile <acct-profile>
```
**Check:**
```bash
databricks service-principals list --filter 'displayName eq "lakewatch"' --profile <ws-profile> -o json
# the service principal is listed, and "groups" doesn't include admins
```

7.3 Who may run rules as it: **Accounts Console → the service principal → Permissions**:
**Service Principal Manager** → your Lakewatch admin group; **Service Principal User** → the people/groups who
author detection rules. Grant *User* only to people you trust with the principal's access.

7.4 Lakewatch folder access: **Lakewatch → Settings → Environment** → edit the `detection` folder →
grant the service principal **Read Lakewatch tables**, **Modify Lakewatch tables**, **Create Lakewatch tables**.

7.5 Warehouse access (needs *Can manage* on the warehouse):
```bash
databricks permissions update warehouses <warehouse-id> --profile <ws-profile> --json \
  '{"access_control_list":[{"service_principal_name":"<sp-application-id>","permission_level":"CAN_USE"}]}'
```

7.6 Audit-log read access — a **metastore admin** runs:
```sql
GRANT USE CATALOG ON CATALOG system TO `<sp-application-id>`;
GRANT USE SCHEMA  ON SCHEMA  system.access TO `<sp-application-id>`;
GRANT SELECT      ON TABLE   system.access.audit TO `<sp-application-id>`;
GRANT SELECT      ON TABLE   system.access.table_lineage TO `<sp-application-id>`;  -- cwdf_audit_log_self_read
GRANT USE SCHEMA  ON SCHEMA  system.query TO `<sp-application-id>`;
GRANT SELECT      ON TABLE   system.query.history TO `<sp-application-id>`;  -- 5 rules (SQL text and clients)
GRANT USE SCHEMA  ON SCHEMA  system.serving TO `<sp-application-id>`;
GRANT SELECT      ON TABLE   system.serving.endpoint_usage TO `<sp-application-id>`;  -- cwdf_compute_serving_resource_abuse
```
Every system table a rule reads is listed here; `tests/test_rules.py` fails if a rule reads one that is not.
**Check:** after Step 9, open one rule's job run (**Jobs & Pipelines** → the rule's job) and confirm it ran as the
service principal and succeeded.

## Step 8 — Import the Databricks rules from the Content library

Lakewatch ships a **Databricks Audit Intelligence** content pack (46 rules) that reads `system.access.audit` directly —
no datasource or parser needed.

1. **Content library** → search `Databricks` → open a rule (for example *Databricks - Configuration Changes High Priority*).
   **Data requirements → Parsers** shows "—": nothing to ingest.
2. **Import rule** → the dialog shows **Target datasource: No table selection required** → **Import**.
   (If you have more than one detection-rules folder, pick the destination folder.)
3. Imported rules are **disabled**. Select **View & enable rule**, then for each rule:
   - **SQL warehouse:** the import uses the warehouse selected for Lakewatch — confirm it's your detection warehouse.
   - **Run as:** your run-as service principal (Step 7) for production.
   - **Schedule:** the pack default is every 12 hours. Run high-severity rules (verbose audit logging disabled,
     log delivery and federation policy changes) more often, for example hourly.
   - **Rule active:** on (Execution section). Save, then confirm the status reads *Active*.
   - **Deduplication:** on. From pack version 3, each rule scans its own run window (`IN_TIMERANGE`): the schedule
     plus 15 minutes for late audit events, so a shorter schedule also shortens the scan, and deduplication stops an
     event in the 15-minute overlap from alerting twice. Earlier versions look back a fixed 13 hours (the query has
     `CURRENT_TIMESTAMP() - INTERVAL 13 HOURS`); with those, if you shorten the schedule, set **Deduplication time
     window → Custom** to at least 13 hours, or each run re-signals the same events.

Each Lakewatch rule runs as a Databricks **job** (its `status.job_id` in the API) on your detection warehouse, so you
can also see run history under **Jobs & Pipelines**.

**Check:**
```bash
databricks lakewatch list-rules <lakewatch_catalog> --profile <ws-profile> -o json
# expect the rule with schedule.enabled true and batch.warehouse_id = your detection warehouse
```
A rule imported a few seconds ago can be missing from `list-rules` briefly — wait a minute and re-run.

**Check that a rule fires** (safe test for *Configuration Changes High Priority*; needs workspace admin): create and delete
a BLOCK list for the documentation range 203.0.113.0/24 — it can't block anyone, and the API refuses a list that would
block your own IP:
```bash
databricks ip-access-lists create --profile <ws-profile> --json '{"label":"lakewatch-test","list_type":"BLOCK","ip_addresses":["203.0.113.0/24"]}'
databricks ip-access-lists delete <list_id> --profile <ws-profile>
```
Expect two alerts within ~30 minutes (audit table lag ~10–15 min + the rule's schedule). In our test, the events reached
`system.access.audit` 12 minutes after they happened and the alerts came at the next rule run. Signals are also in
`<lakewatch_catalog>.__lakewatch.signals` (`summary`, `severity`, `rule_name`, `alert_id`, full `context`).
The Overview page's *Signals* count can lag behind — check **Alerts** or the signals table.

**Triage an alert with Genie** (details in Step 10): **Alerts** → open the alert → Genie panel → **Triage this
alert**. Genie states a plan, checks the rule and its history, queries the entities (user, IP, user agent), and
proposes a verdict (true / false / benign positive). It asks before it (1) adds its comment and (2) sets
classification + state and assigns the alert to you — approve only if you agree.
- If you see **"Failed to add alert comment"**, ask Genie to apply it again; on our test the retry succeeded.
- Genie's activity lookups can hit a row limit on busy accounts; it says so in its comment.

## Step 9 — Deploy this repository's rules

`lakewatch/rules/` holds 48 rules: 21 generated from this repository's detections (`cwda_*`) and 27 attack-family
rules (`cwdf_*`, see [README](README.md#attack-family-rules-cwdf_)). Of the `cwda_*` rules, 15 cover detections the
Content library does not have (session hijacking, token scanning, encoded commands, non-SSO logins, admin role
grants, data movement, and more). Four replace Content library rules whose logic has a bug that this repository
fixes, and two (bulk notebook export, workspace downloads) add thresholds the pack does not have.

1. Install [`uv`](https://docs.astral.sh/uv/) (it runs the deploy script with its two dependencies).
2. Dry run: validates every rule with the Lakewatch API, which also runs its SQL on your warehouse. Nothing is created
   (if the allow-list table doesn't exist yet, the dry run validates against an empty one).
   ```bash
   uv run lakewatch/deploy.py --profile <ws-profile> --catalog <lakewatch_catalog> --schema detection \
     --warehouse-id <warehouse-id> --run-as <sp-application-id> --dry-run
   ```
3. Deploy. Rules are created **disabled**. The first deploy also creates the allow-list table
   `<lakewatch_catalog>.detection.cwd_allowlist` and grants the run-as service principal `SELECT` on it (see *Tuning*):
   ```bash
   uv run lakewatch/deploy.py --profile <ws-profile> --catalog <lakewatch_catalog> --schema detection \
     --warehouse-id <warehouse-id> --run-as <sp-application-id>
   ```
4. Back-test before you enable: `uv run lakewatch/tools/backtest.py --profile <ws-profile> --warehouse-id <warehouse-id>
   --windows 24 --show 5` prints what each rule would have returned in its last 24 runs on your audit table (read-only).
   Or, in Lakewatch **Query**, paste a rule's SQL (with `{{audit_table}}` replaced by `system.access.audit`) and pick a
   time range. A rule that returns many rows of known-good activity needs tuning for your environment first (see
   *Tuning* below).
5. Enable the rules you reviewed, in the UI (**Detection rules** → rule → *Rule active*) or with
   `--enable --only cwda_<name>,cwda_<name>`.
6. **Turn off the Content library rules these replace**, or you get two alerts for one event:

   | Content library rule | Replaced by | Why |
   |---|---|---|
   | `configuration_changes_high_priority` | `cwda_configuration_changes_high_priority` | One settings change can carry several comma-joined keys; the pack compares the whole string, so a setting changed together with another is missed. Also treats IP access lists turned off as critical. |
   | `verbose_audit_logging_disabled` | `cwda_verbose_audit_logging_disabled` | Same bundled-keys gap |
   | `secrets_enumeration` | `cwda_secret_scanning_activity` | Counts listSecrets/listAcls, and only reads that succeeded |
   | `configuration_changes_account_level` | `cwda_configuration_changes_account_level` | Also catches `deleteSetting` (for example deleting an account IP access list rule) |

   Also consider leaving the pack's `workspace_content_exported` off. It signals every single workspace export: on our
   test workspace it returned 186,738 rows in one 12-hour run, during a security scanner's full-workspace scan.
   `cwda_bulk_notebook_export`, `cwdf_workspace_export_burst` and `cwda_potential_data_movement_workspace_downloads`
   report the same activity when it crosses per-principal thresholds.

Re-running the deploy is safe. Each rule carries `managed_by` and `content_hash` annotations: unchanged rules are
skipped, an update touches only the fields this repository owns (suppressions and the enabled state
stay; *Run as* changes only when you pass `--run-as`). A rule someone changed outside this repository since the last
deploy, for example by editing its SQL in the UI, is reported as `edited` and left as is, so a deploy never erases a
change. `--force` overwrites it. `--prune` disables rules this script created whose file is
gone; `--prune-delete` deletes them. Prefer disabling: deleting a Lakewatch rule also deletes its alerts, so pause a
rule you want to retire and delete it only after its alerts are no longer needed.

**Check:**
```bash
databricks lakewatch list-rules <lakewatch_catalog> --profile <ws-profile> -o json   # the 48 cwda_* and cwdf_* rules
```
Each rule gets its own job (**Jobs & Pipelines**, named `lakewatch-rule-batch-...`); its *Run as* is the service
principal from Step 7. On our test workspace, rules deployed with `--enable` ran once within minutes of being
created, so check that the first runs succeeded and look at what they found:
```sql
SELECT rule_name, severity, count(*) AS signals, max(summary) AS example
FROM <lakewatch_catalog>.__lakewatch.signals
WHERE created_at > current_timestamp() - INTERVAL 1 HOUR
  AND rule_name LIKE '<lakewatch_catalog>.detection.cwd%'   -- rule_name is catalog.schema.rule
GROUP BY ALL ORDER BY signals DESC
```
A failed run shows on the rule's job. The usual cause is a missing grant from Step 7.6.

**Tuning.** Tune the rules through the allow-list table, not by editing rule SQL. Every rule drops a finding that
matches a row in `<lakewatch_catalog>.detection.cwd_allowlist`, so your exclusions survive rule updates from this
repository. A row excludes a principal (email, or a service principal's application ID), a source IP, or both, for one
rule (`rule` is the rule name without any name prefix) or for every rule (`rule = '*'`). A row with neither a
principal nor an IP is ignored, so the table can't switch a rule off. Give every row a reason, and an expiry where it
fits:
```sql
INSERT INTO <lakewatch_catalog>.detection.cwd_allowlist (rule, principal, src_ip, reason, added_by, expires_at)
VALUES ('cwdf_anomalous_credential_minting', '<terraform-sp-application-id>', NULL,
        'Terraform mints PATs for CI from GitHub runners', current_user(), NULL);
```
Exclude what you know is benign by identity, never by user agent: the caller sets the user agent. The rules that read
command or query text skip the rule runner's own detection SQL, but only for the identity the rules run as.

Two rules are noisy on workspaces where staff reach Databricks through a corporate egress pool or VPN (many addresses
for one person): `cwda_session_hijacking_multi_device` and `cwda_session_hijacking_session_count`. Review them on your
data before enabling. The `cwda_*` rule SQL comes from this repository's Genie Agent functions
(`genie-agent/functions/`); to change a detection, change it there and regenerate with
`uv run lakewatch/tools/build_rules.py`.

**Authoring rule** for your own rules: name every output column on the outer `SELECT` items
(`a.user_identity.email AS actor`). Don't rename columns with a derived-table column list
(`SELECT * FROM (...) AS t(col1, col2)`): it works on the Query page, but the rule runtime drops the list and the rule
fails with `UNRESOLVED_COLUMN ... cannot be resolved`.

## Step 10 — Investigate with Lakewatch's built-in Genie

No extra Genie space is needed. Lakewatch's own Genie covers investigation:
- **Triage an alert:** **Alerts** → open an alert → open the Genie panel (Genie icon in the top bar). The panel offers
  *What can I do with this alert?*, *Summarize this alert* and *Triage this alert*. *Triage this alert* starts the
  **Alert Triage Assistant**. It shows its plan, queries `system.access.audit` for evidence, and gives a verdict
  (for example *benign positive*: the alert fired correctly on routine activity). Each finding in its table has a
  verdict weight, a timeframe and a source. It then proposes the alert update, a comment and a status. **Nothing is
  posted or changed until you confirm.**
- **Ask ad hoc questions:** **Genie** in the Lakewatch sidebar, over `system.access.audit`, signals and alerts.

Every rule puts `actor` in the signal's context, and most also put `src_ip` (the family rules add `actor_kind`, user
or service principal), so triage starts from the right identity and address. A rule's first alerts have no history to compare against, so the triage verdict says so; it gets sharper
as the rule runs.

**Check:** triage one alert from Step 9. Confirm the verdict cites audit-log evidence for that alert's actor and time,
and that the alert stays *Open* until you approve the proposed update.

The repo's standalone Genie agent (`genie-agent/`) remains the option for workspaces that don't use Lakewatch.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Lakewatch isn't in the app switcher | Preview not enabled | Step 3 |
| Setup won't continue | No warehouse selected | Select a serverless warehouse under *Environment, workspace and compute* |
| Datasources page shows no event counts | Classic/pro warehouse selected for the UI | Select a serverless warehouse |
| Rule rejected: "running a version that Lakewatch does not support" | Warehouse below DBSQL 2026.36 | Step 4 check; pick another warehouse |
| Data preview: "not compatible with the parser: missing required fields: 'serviceName', 'actionName'" | Databricks Audit parser attached to `system.access.audit` | Remove the datasource; query the system table directly |
| `databricks lakewatch`: unknown command | CLI older than v1.25.0 | Step 1 |
| `catalog '<name>' does not exist` from `databricks lakewatch list-rules` | Lakewatch setup not done, or wrong catalog name | Step 5 |
| Serverless warehouse stuck starting | Platform incident | Step 0 |
| Rule run fails: "Rule SQL references an object that could not be resolved" | Output column renamed via `AS t(col, ...)`, which the rule runtime drops; or a summary `{column}` that the query doesn't output | Alias columns on the SELECT items; the job run output (Jobs → the rule's job → failed run) shows the exact column |
| Encoded-command (or any command-text) rule alerts on the rule's own run-as identity, surface `jobs` | The Lakewatch rule runner's notebook code is itself audited | Run rules as a dedicated service principal (Step 7) and exclude it, or exclude the runner's commands |
| Triage with Genie: "Failed to add alert comment" | Transient failure applying the comment | Ask Genie to apply it again |
| `databricks lakewatch list-rules` prints `[]` right after an import | List not yet updated | Wait a minute and re-run |
| Two alerts for one settings change | Both the Content library rule and the `cwda_` rule that replaces it are on | Step 9.6 |
| `deploy.py` reports `FAILED ... UNRESOLVED_COLUMN` | A rule's SQL lost a column name | Regenerate with `uv run lakewatch/tools/build_rules.py`, or name the column on the SELECT item |
| Every workspace user can see alerts / edit rules | `All account users` left as admin in Step 5 (Custom config is pre-filled from Recommended) | Step 5 Check — remove from Admins and from each folder |

---

## For AI coding assistants (Claude, etc.) helping a customer through this guide

- Do the steps **in order**; run each **Check** and show the output before moving on. Stop and report if a Check fails.
- Steps 2, 3, 5, 7.3, 7.4 and 9.6 are **UI-only or admin-only**. Ask the human to do them and confirm; don't guess they're done —
  verify with the CLI checks where one exists.
- Never choose *Recommended configuration* in Step 5, and in *Custom configuration* confirm the human removed
  *All account users* from Admins — then run the Step 5 `SHOW GRANTS` check yourself and stop if `account users` has more
  than USE CATALOG / USE SCHEMA.
- Never make the service principal a workspace admin, and never attach the *Databricks Audit* parser to
  `system.access.audit`.
- Before starting, and whenever serverless compute hangs, check https://status.databricks.com (Step 0).
- Don't put `run_as_principal` or warehouse IDs in committed rule files; they're per-environment and passed at deploy time
  (`deploy.py --run-as --warehouse-id`).
- Always run `deploy.py --dry-run` first and show its output; stop if any rule reports FAILED.
- Deploy rules disabled, back-test them on the Query page (Step 9.4) with the human, and enable only the ones they approve.
