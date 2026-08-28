-- =============================================================================
-- Genie Agent Trusted Assets -- data movement, secrets, credential scanning
-- =============================================================================
-- Ports 7 detections. Replace ${CATALOG} / ${SCHEMA} before running.
--
-- NOTE ON ONE SOURCE TABLE: detect_data_movement_sql_queries reads
-- system.query.history, not system.access.audit. Grant SELECT on BOTH, and add
-- both as Genie data sources.
-- =============================================================================

-- --------------------------------------------------------------------------
-- Data movement with explicit credentials.
-- Port of behavioral/potential_data_movement_explicit_creds.py.
--
-- The action set is the notebook's: mount, create/updateStorageCredential,
-- create/updateConnection. These are the control-plane operations that attach
-- EXTERNAL storage or a foreign system -- the plumbing an exfiltration path
-- needs before any data moves. Verified live: updateConnection (33),
-- createConnection (15).
--
-- Default window in the notebook is 2 MONTHS, not 24 hours, because this is a
-- slow-burn detection: the credential is created well before it is used.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_data_movement_explicit_creds(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive). Prefer a wide window -- 60+ days -- since credential creation precedes use.',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time   TIMESTAMP COMMENT 'When the operation happened (UTC)',
  service_name STRING    COMMENT 'Emitting service',
  action       STRING    COMMENT 'mount / createStorageCredential / updateStorageCredential / createConnection / updateConnection',
  actor        STRING    COMMENT 'Identity that performed it',
  source_ip    STRING    COMMENT 'IP the request came from',
  user_agent   STRING    COMMENT 'Client used',
  request_params MAP<STRING, STRING> COMMENT 'Target of the mount/credential/connection -- inspect for the external destination'
)
COMMENT 'Creation or modification of external storage mounts, storage credentials, and external connections (mount, createStorageCredential, updateStorageCredential, createConnection, updateConnection). MITRE T1567 Exfiltration Over Web Service, TA0010 Exfiltration. These are the control-plane steps that attach an external destination BEFORE data moves, so they are an early indicator rather than evidence of transfer. Inspect request_params for where the external target points. Use for: data exfiltration setup, new storage credentials, external connections created, who mounted external storage, data movement, exfiltration paths, suspicious storage configuration.'
RETURN
  SELECT
    a.event_time,
    a.service_name,
    a.action_name,
    a.user_identity.email,
    a.source_ip_address,
    a.user_agent,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.action_name IN ('mount', 'createStorageCredential', 'updateStorageCredential',
                          'createConnection', 'updateConnection')
    AND a.event_time BETWEEN start_time AND end_time;

-- --------------------------------------------------------------------------
-- COPY INTO with inline credentials, from query history.
-- Port of behavioral/potential_data_movement_sql_queries.py.
--
-- READS system.query.history, NOT system.access.audit. The notebook looks for
-- statement_text containing both COPY INTO and CREDENTIALS -- a query that
-- writes to (or reads from) an external location using credentials supplied
-- inline rather than a governed UC credential, which bypasses Unity Catalog
-- lineage and grants.
--
-- statement_text can contain the credential material itself, so treat this
-- function's output as sensitive: it is the one detection here whose results may
-- carry a live secret. Do not paste rows into tickets unredacted.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_data_movement_sql_queries(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  start_time_ts    TIMESTAMP COMMENT 'When the statement started (UTC)',
  executed_as      STRING    COMMENT 'Identity the statement ran as',
  statement_id     STRING    COMMENT 'Statement id, for pivoting in query history',
  warehouse_id     STRING    COMMENT 'Warehouse that ran it',
  produced_rows    BIGINT    COMMENT 'Rows produced -- a volume signal',
  total_duration_ms BIGINT   COMMENT 'Duration in ms',
  statement_text   STRING    COMMENT 'SENSITIVE: full SQL, may contain inline credential material. Redact before sharing.'
)
COMMENT 'COPY INTO statements that supply credentials inline (statement_text contains both COPY INTO and CREDENTIALS), read from system.query.history. MITRE T1567 Exfiltration Over Web Service. Inline credentials bypass Unity Catalog governance and lineage, so this is data movement your UC grants did not mediate. WARNING: statement_text may contain live credential material -- redact before sharing. Requires SELECT on system.query.history. Use for: COPY INTO with credentials, data exfiltration via SQL, ungoverned data movement, queries using inline credentials, suspicious COPY INTO, bulk data export via SQL.'
RETURN
  SELECT
    q.start_time,
    q.executed_as,
    q.statement_id,
    q.compute.warehouse_id,
    q.produced_rows,
    q.total_duration_ms,
    q.statement_text
  FROM system.query.history AS q
  WHERE q.start_time BETWEEN start_time AND end_time
    AND upper(q.statement_text) LIKE '%COPY INTO%'
    AND upper(q.statement_text) LIKE '%CREDENTIALS%';

-- --------------------------------------------------------------------------
-- Bulk download / export out of the workspace.
-- Port of behavioral/potential_data_movement_workspace_downloads.py.
--
-- Two notebook exclusions are preserved deliberately, and both matter for
-- noise: workspaceExport with format SOURCE is normal notebook source control,
-- and downloadQueryResult with fileType 'arrows' is the UI's own result
-- rendering rather than a user-initiated download.
--
-- Verified live: filesGet (227,791), workspaceExport (28,045),
-- downloadQueryResult (3), downloadLargeResults (1). filesGet dominates, so
-- expect volume -- aggregate by actor before reading rows.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_data_movement_downloads(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_date   DATE      COMMENT 'Day of activity (UTC)',
  actor        STRING    COMMENT 'Identity that downloaded',
  action       STRING    COMMENT 'Download/export action',
  downloads    BIGINT    COMMENT 'Download events by this actor+action that day -- the volume signal',
  distinct_ips BIGINT    COMMENT 'Distinct source IPs used',
  source_ips   STRING    COMMENT 'The IPs, comma separated',
  user_agents  STRING    COMMENT 'Distinct clients used',
  first_seen   TIMESTAMP COMMENT 'First download that day (UTC)',
  last_seen    TIMESTAMP COMMENT 'Last download that day (UTC)'
)
COMMENT 'Data leaving the workspace via download or export, AGGREGATED per actor, action and day: downloadPreviewResults, downloadLargeResults, filesGet, getModelVersionDownloadUri, getModelVersionSignedDownloadUri, workspaceExport (excluding SOURCE format, which is normal source control) and downloadQueryResult (excluding arrows, which is UI rendering). MITRE T1567, TA0010 Exfiltration. Deliberately aggregated, not row-per-event: this is the highest-volume detection here (227,000+ filesGet events from 6 actors in one reference 90-day window), so per-event rows would be unreadable and would truncate. Look for an actor whose daily volume is out of character, or an identity that should not be downloading at all. Use for: data downloads, who exported data, workspace exports, bulk downloads, result downloads, data leaving the workspace, exfiltration via download, download volume by user.'
RETURN
  SELECT
    to_date(a.event_time) AS event_date,
    a.user_identity.email AS actor,
    a.action_name AS action,
    COUNT(*) AS downloads,
    COUNT(DISTINCT a.source_ip_address) AS distinct_ips,
    CONCAT_WS(', ', COLLECT_SET(a.source_ip_address)) AS source_ips,
    CONCAT_WS(', ', COLLECT_SET(a.user_agent)) AS user_agents,
    MIN(a.event_time) AS first_seen,
    MAX(a.event_time) AS last_seen
  FROM system.access.audit AS a
  WHERE a.event_time BETWEEN start_time AND end_time
    AND (
      a.action_name IN ('downloadPreviewResults', 'downloadLargeResults', 'filesGet',
                        'getModelVersionDownloadUri', 'getModelVersionSignedDownloadUri')
      OR (a.action_name = 'workspaceExport'
          AND COALESCE(a.request_params['workspaceExportFormat'], '') <> 'SOURCE')
      OR (a.action_name = 'downloadQueryResult'
          AND COALESCE(a.request_params['fileType'], '') <> 'arrows')
    )
  GROUP BY to_date(a.event_time), a.user_identity.email, a.action_name;

-- --------------------------------------------------------------------------
-- Secrets discovery -- enumerate scopes, then read secrets.
-- Port of behavioral/secret_scanning_activity.py.
--
-- The notebook's shape is what makes this a detection rather than a log dump: it
-- aggregates per (day, actor) and requires BOTH scope enumeration (listScopes)
-- above a threshold AND distinct secrets read. Reading one known secret is
-- normal application behaviour; enumerating scopes and then pulling many
-- distinct secrets is discovery.
--
-- Thresholds are parameters, defaulting via the caller. The notebook's defaults
-- are scopes_threshold / secrets_threshold; pass 1/1 to see all activity.
-- Verified live: getSecret (203,009), listScopes (1,009) -- high volume, so the
-- thresholds are load-bearing, not decorative.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_secrets_discovery(
  start_time        TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time          TIMESTAMP COMMENT 'End of the search window (inclusive)',
  scopes_threshold  INT       COMMENT 'Minimum listScopes calls per actor per day. Try 5 to start; 1 shows all activity.',
  secrets_threshold INT       COMMENT 'Minimum distinct secrets read per actor per day. Try 5 to start; 1 shows all activity.'
)
RETURNS TABLE (
  event_date        DATE   COMMENT 'Day of activity (UTC)',
  actor             STRING COMMENT 'Identity doing the enumeration',
  scopes_enumerated BIGINT COMMENT 'listScopes calls that day',
  secrets_used      BIGINT COMMENT 'Distinct scope:key pairs read that day',
  service_name      STRING COMMENT 'Emitting service'
)
COMMENT 'Secret discovery behaviour: an identity that both enumerates secret scopes (listScopes) and reads distinct secrets (getSecret) above the given thresholds on the same day. MITRE T1552 Unsecured Credentials, TA0006 Credential Access. Reading one known secret is normal application behaviour -- enumerate-then-read is the discovery pattern, which is why both thresholds must be met. Volume is high in most accounts, so raise the thresholds rather than widening the window. Use for: secret scanning, credential harvesting, who enumerated secret scopes, secrets discovery, listScopes activity, someone reading many secrets, credential access.'
RETURN
  SELECT
    to_date(a.event_time) AS event_date,
    a.user_identity.email AS actor,
    SUM(CASE WHEN a.action_name = 'listScopes' THEN 1 ELSE 0 END) AS scopes_enumerated,
    SIZE(COLLECT_SET(CONCAT(COALESCE(a.request_params['scope'], ''), ':',
                            COALESCE(a.request_params['key'], '')))) AS secrets_used,
    MAX(a.service_name) AS service_name
  FROM system.access.audit AS a
  WHERE a.action_name IN ('listScopes', 'getSecret')
    AND a.event_time BETWEEN start_time AND end_time
  GROUP BY to_date(a.event_time), a.user_identity.email
  HAVING SUM(CASE WHEN a.action_name = 'listScopes' THEN 1 ELSE 0 END) >= scopes_threshold
     AND SIZE(COLLECT_SET(CONCAT(COALESCE(a.request_params['scope'], ''), ':',
                                 COALESCE(a.request_params['key'], '')))) >= secrets_threshold;

-- --------------------------------------------------------------------------
-- TruffleHog / credential scanner detected.
-- Port of event-based/trufflehog_scan_detected.py.
--
-- Detects the tool by its user_agent. Dual-use: your own security team may run
-- it legitimately, so treat a hit as "identify who and confirm it was
-- sanctioned" rather than as an incident on its own.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_credential_scanner_activity(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time   TIMESTAMP COMMENT 'When the activity happened (UTC)',
  actor        STRING    COMMENT 'Identity running the scanner',
  user_agent   STRING    COMMENT 'The scanner user agent that matched',
  source_ip    STRING    COMMENT 'IP it ran from',
  service_name STRING    COMMENT 'Emitting service',
  action       STRING    COMMENT 'Audit action name',
  events       BIGINT    COMMENT 'Matching events for this actor+agent+ip'
)
COMMENT 'Credential-scanning tools identified by user agent (TruffleHog and similar). MITRE T1552 Unsecured Credentials, TA0006 Credential Access. Dual-use: your own security team may run these legitimately, so confirm whether the actor and timing were sanctioned before treating it as an incident. Use for: TruffleHog, credential scanning tools, secret scanners, who ran a credential scanner, scanning activity, security tool usage.'
RETURN
  SELECT
    MAX(a.event_time)  AS event_time,
    a.user_identity.email AS actor,
    a.user_agent,
    a.source_ip_address AS source_ip,
    MAX(a.service_name) AS service_name,
    MAX(a.action_name)  AS action,
    COUNT(*)            AS events
  FROM system.access.audit AS a
  WHERE a.event_time BETWEEN start_time AND end_time
    AND (lower(a.user_agent) LIKE '%trufflehog%'
      OR lower(a.user_agent) LIKE '%gitleaks%'
      OR lower(a.user_agent) LIKE '%secretscan%')
  GROUP BY a.user_identity.email, a.user_agent, a.source_ip_address;

-- --------------------------------------------------------------------------
-- Token scanning / PAT probing.
-- Port of behavioral/token_scanning_activity.py.
--
-- The notebook keys on request_params.authenticationMethod = API_EXT_PAT_TOKEN
-- and groups by (tokenId, source_ip) with the port stripped from the IP.
-- ONE token id presenting from MANY source IPs is the signal: a leaked token
-- being tried from multiple places.
--
-- The notebook's optional MaxMind geo enrichment is NOT ported -- it needs an
-- .mmdb file on the cluster and cannot be expressed in SQL. Nothing else is
-- lost; the geo columns were additive.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_token_scanning_activity(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  token_id       STRING    COMMENT 'The PAT being presented',
  distinct_ips   BIGINT    COMMENT 'Distinct source IPs that presented this token. >1 warrants a look',
  source_ips     STRING    COMMENT 'The IPs, comma separated',
  first_seen     TIMESTAMP COMMENT 'First use in the window (UTC)',
  last_seen      TIMESTAMP COMMENT 'Last use in the window (UTC)',
  attempts       BIGINT    COMMENT 'Total presentations',
  actors         STRING    COMMENT 'Identities associated with the token',
  user_agents    STRING    COMMENT 'Distinct clients that presented it'
)
COMMENT 'Personal access tokens (authenticationMethod API_EXT_PAT_TOKEN) grouped by token, showing how many distinct source IPs presented each one. MITRE T1078 Valid Accounts, T1552 Unsecured Credentials. A single token presenting from MANY IPs is the leaked-token signal -- one token is meant to live in one place. Geo enrichment from the source notebook is not available here (it needs a MaxMind database file), so judge by IP spread and user agent instead. Use for: token scanning, leaked tokens, PAT used from multiple locations, token abuse, stolen access token, is a token compromised, token used from many IPs.'
RETURN
  SELECT
    a.request_params['tokenId'] AS token_id,
    COUNT(DISTINCT regexp_replace(a.source_ip_address, ':[0-9]+$', '')) AS distinct_ips,
    CONCAT_WS(', ', COLLECT_SET(regexp_replace(a.source_ip_address, ':[0-9]+$', ''))) AS source_ips,
    MIN(a.event_time) AS first_seen,
    MAX(a.event_time) AS last_seen,
    COUNT(*) AS attempts,
    CONCAT_WS(', ', COLLECT_SET(a.user_identity.email)) AS actors,
    CONCAT_WS(', ', COLLECT_SET(a.user_agent)) AS user_agents
  FROM system.access.audit AS a
  WHERE a.request_params['authenticationMethod'] = 'API_EXT_PAT_TOKEN'
    AND a.event_time BETWEEN start_time AND end_time
    AND a.request_params['tokenId'] IS NOT NULL
  GROUP BY a.request_params['tokenId'];

-- --------------------------------------------------------------------------
-- Spike in administrative SQL activity.
-- Port of behavioral/spike_in_table_admin_activity.py.
--
-- The notebook looks at request_params.commandText for user/account admin DDL
-- (CREATE USER, ALTER USER, ALTER ACCOUNT ...), excluding Databricks' own
-- system-generated queries, and normalises per user into a RATE.
--
-- Simplified here to a per-actor-per-day count with a threshold: the notebook's
-- normalised rate depends on a baseline window that a stateless function cannot
-- compute honestly. A count above a threshold answers the same investigative
-- question ("who suddenly started issuing admin DDL?") without pretending to a
-- baseline it does not have. This is a DELIBERATE simplification, not an
-- oversight -- see docs/PORTING.md.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_admin_sql_activity_spike(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)',
  min_commands INT     COMMENT 'Minimum admin DDL statements per actor per day to report. Try 5.'
)
RETURNS TABLE (
  event_date   DATE   COMMENT 'Day of activity (UTC)',
  actor        STRING COMMENT 'Identity issuing the statements',
  commands     BIGINT COMMENT 'Admin DDL statements that day',
  distinct_cmds BIGINT COMMENT 'Distinct statement texts -- repetition vs variety',
  sample_command STRING COMMENT 'One example statement'
)
COMMENT 'Administrative SQL DDL (CREATE USER, ALTER USER, ALTER ACCOUNT and similar) aggregated per actor per day, above a threshold, excluding Databricks system-generated queries. MITRE T1098 Account Manipulation. A person who does not normally issue account DDL suddenly issuing a lot of it is the signal. Note this reports a COUNT above a threshold rather than the source notebook normalised rate, because a stateless function has no baseline window to normalise against. Use for: admin activity spike, unusual admin commands, who ran CREATE USER, account DDL, spike in administrative activity, admin SQL.'
RETURN
  SELECT
    to_date(a.event_time) AS event_date,
    a.user_identity.email AS actor,
    COUNT(*) AS commands,
    COUNT(DISTINCT a.request_params['commandText']) AS distinct_cmds,
    MAX(a.request_params['commandText']) AS sample_command
  FROM system.access.audit AS a
  WHERE a.event_time BETWEEN start_time AND end_time
    AND a.request_params['commandText'] IS NOT NULL
    AND upper(a.request_params['commandText']) NOT LIKE '%THIS IS A SYSTEM GENERATED QUERY%'
    AND (upper(a.request_params['commandText']) LIKE '%CREATE USER%'
      OR upper(a.request_params['commandText']) LIKE '%ALTER USER%'
      OR upper(a.request_params['commandText']) LIKE '%ALTER ACCOUNT%'
      OR upper(a.request_params['commandText']) LIKE '%DROP USER%'
      OR upper(a.request_params['commandText']) LIKE '%GRANT ADMIN%')
  GROUP BY to_date(a.event_time), a.user_identity.email
  HAVING COUNT(*) >= min_commands;

-- --------------------------------------------------------------------------
-- Bulk notebook export -- per-principal anomaly, not a global threshold.
-- Port of behavioral/bulk_notebook_export.py (David Veuve, PR #11).
--
-- WHY THIS EXISTS ALONGSIDE detect_data_movement_downloads: that function
-- EXCLUDES workspaceExport with format SOURCE, treating it as normal
-- development -- and SOURCE is exactly the format a bulk export of code uses.
-- So the broad download detection deliberately misses source-code exfiltration,
-- and this one covers it. Keep both.
--
-- THE SCORING IS THE DETECTION. Each principal is measured against its OWN
-- history via a Tukey-style fence, not one global number:
--
--     fence = Q3 + iqr_multiplier * max(Q3 - Q1, iqr_floor)
--
-- Measured on a live workspace over 60 days, this is why that matters:
--
--     actor                  active days   peak day   median   fence
--     service principal A         16          230        9      538
--     a human user                19          193        3      510
--     another human               60          113       12      533
--
-- A single global threshold tuned for the 230-notebook service principal would
-- never fire on a user whose normal day is 3 notebooks. Zero false positives in
-- that window, while staying close enough above observed peaks to catch a real
-- spike.
--
-- Three noise controls from the source notebook, all preserved:
--   * baseline_exclude_days -- trailing days are excluded from the baseline, so a
--     live in-progress bulk export cannot inflate its own fence.
--   * self-export exclusion -- a principal reading under its own home directory
--     (/Workspace/Users/<self>/...) is platform tooling (Databricks Apps pulling
--     a deployment bundle), not cross-user exfiltration.
--   * no_baseline_threshold -- a first-seen principal has no history, so it is
--     scored against a flat number rather than being invisible. That is the
--     failure mode that would matter most in a real incident: a new account
--     exfiltrating on day one.
--
-- NOTEBOOKS_EXPORTED counts DISTINCT paths, so re-exporting one notebook 500
-- times reads as 1. That is correct for IP exfiltration (breadth of code taken,
-- not request volume) and is deliberate -- do not "fix" it to a raw count.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_bulk_notebook_export(
  start_time            TIMESTAMP COMMENT 'Start of the search window (inclusive). Use 60+ days so each principal has a baseline.',
  end_time              TIMESTAMP COMMENT 'End of the search window (inclusive)',
  baseline_exclude_days INT       COMMENT 'Trailing days excluded from the baseline so a live export cannot inflate its own fence. Source notebook default: 2',
  iqr_multiplier        DOUBLE    COMMENT 'Multiplier on the floored IQR when building the fence. Source notebook default: 5.0',
  iqr_floor             INT       COMMENT 'Minimum IQR term, guaranteeing a minimum absolute rise over normal. Source notebook default: 100',
  no_baseline_threshold INT       COMMENT 'Flat threshold for a principal with no baseline. Source notebook default: 600'
)
RETURNS TABLE (
  event_date         DATE   COMMENT 'Day of the bulk export (UTC)',
  actor              STRING COMMENT 'Principal that exported',
  notebooks_exported BIGINT COMMENT 'DISTINCT notebooks exported that day',
  threshold_applied  DOUBLE COMMENT 'This principal own fence, or the flat fallback when it has no history',
  iqrs_from_median   DOUBLE COMMENT 'How many IQRs above this principal normal day -- the anomaly magnitude',
  baseline_median    DOUBLE COMMENT 'This principal usual daily count, for context',
  formats_used       STRING COMMENT 'Export formats seen. SOURCE means raw code',
  analysis           STRING COMMENT 'One-line summary for triage'
)
COMMENT 'Bulk notebook export scored against each principal OWN history (Tukey fence: Q3 + multiplier * max(IQR, floor)), not a global threshold. MITRE T1567 Exfiltration Over Web Service, TA0010 Exfiltration. This is source-code / IP exfiltration, and it is deliberately NOT covered by the general download detection, which excludes SOURCE-format exports as normal development -- the exact format bulk code theft uses. Self-exports from a principal own home directory are excluded as platform tooling; first-seen principals with no baseline are scored against a flat threshold so they are never invisible. Counts DISTINCT notebooks, so breadth of code taken rather than request volume. Use for: bulk notebook export, source code exfiltration, who exported many notebooks, IP theft, someone downloading all our code, notebook export spike, mass export, code exfiltration.'
RETURN
  -- The CTE chain is wrapped in a subquery deliberately. A SQL UDF body cannot
  -- begin with a top-level WITH: the CREATE fails with an opaque
  -- "request failed due to an unexpected condition" (no parse error, no line
  -- number). Verified live -- the identical query runs standalone but the CREATE
  -- is rejected until the WITH sits inside SELECT * FROM ( ... ).
  SELECT * FROM (
  WITH exports AS (
    SELECT
      to_date(a.event_time) AS event_date,
      a.user_identity.email AS actor,
      a.request_params['notebookFullPath'] AS notebook_path,
      a.request_params['workspaceExportFormat'] AS export_format
    FROM system.access.audit AS a
    WHERE a.action_name = 'workspaceExport'
      AND a.event_time BETWEEN start_time AND end_time
      AND NOT contains(COALESCE(a.request_params['notebookFullPath'], ''),
                       COALESCE(a.user_identity.email, ' '))
  ),
  per_user_day AS (
    SELECT event_date, actor,
           COUNT(DISTINCT notebook_path) AS notebooks_exported,
           CONCAT_WS('/', COLLECT_SET(export_format)) AS formats_used
    FROM exports
    GROUP BY event_date, actor
  ),
  baseline AS (
    SELECT * FROM per_user_day
    WHERE event_date < date_sub(current_date(), baseline_exclude_days)
  ),
  per_user_threshold AS (
    SELECT
      actor,
      percentile_approx(notebooks_exported, 0.5) AS median,
      (percentile_approx(notebooks_exported, 0.75)
       - percentile_approx(notebooks_exported, 0.25)) AS iqr,
      (percentile_approx(notebooks_exported, 0.75)
       + iqr_multiplier * GREATEST(
           percentile_approx(notebooks_exported, 0.75)
           - percentile_approx(notebooks_exported, 0.25),
           CAST(iqr_floor AS DOUBLE))) AS user_threshold
    FROM baseline
    GROUP BY actor
  )
  SELECT
    d.event_date,
    d.actor,
    d.notebooks_exported,
    ROUND(COALESCE(t.user_threshold, CAST(no_baseline_threshold AS DOUBLE)), 1),
    ROUND((d.notebooks_exported - t.median) / NULLIF(t.iqr, 0), 1),
    ROUND(t.median, 1),
    d.formats_used,
    CONCAT(CAST(d.notebooks_exported AS STRING), ' notebooks exported (threshold ',
           CAST(ROUND(COALESCE(t.user_threshold, CAST(no_baseline_threshold AS DOUBLE)), 1) AS STRING),
           ', formats: ', d.formats_used, ')')
  FROM per_user_day AS d
  LEFT JOIN per_user_threshold AS t ON d.actor = t.actor
  WHERE d.notebooks_exported >= COALESCE(t.user_threshold, CAST(no_baseline_threshold AS DOUBLE))
  );
