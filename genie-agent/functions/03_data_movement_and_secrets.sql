-- =============================================================================
-- Genie Agent Trusted Assets -- data movement, secrets, credential scanning
-- =============================================================================
-- Ports 9 detections. Replace ${CATALOG} / ${SCHEMA} before running.
--
-- NOTE ON SOURCE TABLES: two functions here read system.query.history in
-- addition to (or instead of) system.access.audit --
-- detect_data_movement_sql_queries and detect_encoded_command_execution. Grant
-- SELECT on BOTH tables, and add BOTH as Genie data sources.
-- =============================================================================

-- --------------------------------------------------------------------------
-- Data movement with explicit credentials.
-- Port of behavioral/potential_data_movement_explicit_creds.py.
--
-- The action set is the notebook's: mount, create/updateStorageCredential,
-- create/updateExternalLocation, create/updateConnection, and createCatalog
-- when it carries a connection_name (a foreign catalog). These are the
-- control-plane operations that attach
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
  action       STRING    COMMENT 'mount / create|updateStorageCredential / create|updateExternalLocation / create|updateConnection / createCatalog (foreign)',
  status_code  INT       COMMENT 'Response status. 403 = refused attempt, still a signal',
  actor        STRING    COMMENT 'Identity that performed it',
  source_ip    STRING    COMMENT 'IP the request came from',
  user_agent   STRING    COMMENT 'Client used',
  request_params MAP<STRING, STRING> COMMENT 'Target of the mount/credential/connection -- inspect for the external destination'
)
COMMENT 'Creation or modification of external storage mounts, storage credentials, external locations, external connections and foreign catalogs (mount, createStorageCredential, updateStorageCredential, createExternalLocation, updateExternalLocation, createConnection, updateConnection, createCatalog with a connection). MITRE T1567 Exfiltration Over Web Service, TA0010 Exfiltration. These are the control-plane steps that attach an external destination BEFORE data moves, so they are an early indicator rather than evidence of transfer. Refused attempts are kept (status_code 403): probing for a credential or location the actor cannot create is itself a signal. Inspect request_params for where the external target points. Use for: data exfiltration setup, new storage credentials, external locations created, external connections created, foreign catalog created, who mounted external storage, data movement, exfiltration paths, suspicious storage configuration.'
RETURN
  SELECT
    a.event_time,
    a.service_name,
    a.action_name,
    a.response.status_code,
    a.user_identity.email,
    a.source_ip_address,
    a.user_agent,
    a.request_params
  FROM system.access.audit AS a
  WHERE (a.action_name IN ('mount', 'createStorageCredential', 'updateStorageCredential',
                           'createExternalLocation', 'updateExternalLocation',
                           'createConnection', 'updateConnection')
         OR (a.action_name = 'createCatalog' AND a.request_params['connection_name'] IS NOT NULL))
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
-- SOURCE-format workspaceExport is INCLUDED: it is what the REST API, CLI and
-- scripted dumps use, so excluding it hid most bulk exports. downloadQueryResult
-- with fileType 'arrows' stays excluded (UI rendering, not a user download).
-- distinct_objects and foreign_homes are what separate a sweep from routine
-- sync: on the reference workspace every heavy exporter (CLI sync, CI service
-- principals, SAT) exported a single home folder.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_data_movement_downloads(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_date       DATE      COMMENT 'Day of activity (UTC)',
  actor            STRING    COMMENT 'Identity that downloaded',
  action           STRING    COMMENT 'Download/export action',
  downloads        BIGINT    COMMENT 'Download events by this actor+action that day -- the volume signal',
  distinct_objects BIGINT    COMMENT 'Distinct notebooks, files, artifacts or model versions',
  foreign_homes    BIGINT    COMMENT 'Distinct OTHER users home folders exported from -- >1 suggests a sweep',
  export_formats   STRING    COMMENT 'workspaceExport formats used (SOURCE, AUTO, JUPYTER, DBC, HTML)',
  distinct_ips     BIGINT    COMMENT 'Distinct source IPs used',
  source_ips       STRING    COMMENT 'The IPs, comma separated',
  user_agents      STRING    COMMENT 'Distinct clients used',
  first_seen       TIMESTAMP COMMENT 'First download that day (UTC)',
  last_seen        TIMESTAMP COMMENT 'Last download that day (UTC)'
)
COMMENT 'Data leaving the workspace via download or export, AGGREGATED per actor, action and day: workspaceExport in every format (SOURCE included -- it is what the REST API, CLI and scripted dumps use), filesGet, createDownloadUrl, downloadPreviewResults, downloadLargeResults, downloadQueryResult (excluding arrows, which is UI rendering), getModelVersionDownloadUri, getModelVersionSignedDownloadUri, MLflow readArtifact and readTraceData, and UC model-version read credentials. MITRE T1567, TA0010 Exfiltration. distinct_objects counts distinct notebooks, files, artifacts or model versions; foreign_homes counts OTHER users home folders (/Users/<x>, /Repos/<x>) exported from. Heavy legitimate exporters (CLI sync, CI, scanners) export one home folder; a sweep across several users homes is the exfiltration shape, so sort by foreign_homes, then distinct_objects. Deliberately aggregated, not row-per-event, because this is the highest-volume detection. Look for an actor whose daily volume is out of character, or an identity that should not be downloading at all. Use for: data downloads, who exported data, workspace exports, bulk downloads, notebook export sweep, exported other users notebooks, result downloads, artifact downloads, data leaving the workspace, exfiltration via download, download volume by user.'
RETURN
  SELECT
    to_date(a.event_time) AS event_date,
    a.user_identity.email AS actor,
    a.action_name AS action,
    COUNT(*) AS downloads,
    COUNT(DISTINCT COALESCE(a.request_params['notebookFullPath'], a.request_params['path'],
                            a.request_params['filePath'], a.request_params['artifactLocation'],
                            a.request_params['request_id'],
                            CONCAT(a.request_params['model_name'], '/', a.request_params['version']),
                            a.event_id)) AS distinct_objects,
    COUNT(DISTINCT CASE
      WHEN lower(regexp_extract(COALESCE(a.request_params['notebookFullPath'], a.request_params['path'], ''),
                                '^(/Workspace)?/(Users|Repos)/([^/]+)', 3)) NOT IN ('', lower(a.user_identity.email))
      THEN regexp_extract(COALESCE(a.request_params['notebookFullPath'], a.request_params['path'], ''),
                          '^(/Workspace)?/(Users|Repos)/([^/]+)', 3) END) AS foreign_homes,
    CONCAT_WS(', ', COLLECT_SET(a.request_params['workspaceExportFormat'])) AS export_formats,
    COUNT(DISTINCT a.source_ip_address) AS distinct_ips,
    CONCAT_WS(', ', COLLECT_SET(a.source_ip_address)) AS source_ips,
    CONCAT_WS(', ', COLLECT_SET(a.user_agent)) AS user_agents,
    MIN(a.event_time) AS first_seen,
    MAX(a.event_time) AS last_seen
  FROM system.access.audit AS a
  WHERE a.event_time BETWEEN start_time AND end_time
    AND (
      a.action_name IN ('downloadPreviewResults', 'downloadLargeResults', 'filesGet', 'createDownloadUrl',
                        'getModelVersionDownloadUri', 'getModelVersionSignedDownloadUri',
                        'readArtifact', 'readTraceData', 'workspaceExport')
      OR (a.action_name = 'downloadQueryResult'
          AND COALESCE(a.request_params['fileType'], '') <> 'arrows')
      OR (a.action_name = 'generateTemporaryModelVersionCredential'
          AND a.request_params['operation'] = 'READ_MODEL_VERSION')
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
  scopes_threshold  INT       COMMENT 'Minimum enumeration calls (listScopes, listSecrets, listAcls) per actor per day. Try 5 to start; 1 shows all activity.',
  secrets_threshold INT       COMMENT 'Minimum distinct secrets successfully read per actor per day. Try 5 to start; 1 shows all activity.'
)
RETURNS TABLE (
  event_date        DATE   COMMENT 'Day of activity (UTC)',
  actor             STRING COMMENT 'Identity doing the enumeration',
  scopes_enumerated BIGINT COMMENT 'Enumeration calls that day: listScopes + listSecrets + listAcls',
  secrets_used      BIGINT COMMENT 'Distinct scope:key pairs successfully read (getSecret, status 200) that day',
  secrets_refused   BIGINT COMMENT 'Secrets calls refused that day (non-200). Reported, not thresholded: applications probing optional secrets refuse often',
  service_name      STRING COMMENT 'Emitting service'
)
COMMENT 'Secret discovery behaviour: an identity that both enumerates secrets (listScopes, listSecrets or listAcls) and successfully reads distinct secrets (getSecret) above the given thresholds on the same day. MITRE T1552 Unsecured Credentials, TA0006 Credential Access. Reading one known secret is normal application behaviour -- enumerate-then-read is the discovery pattern, which is why both thresholds must be met. Refused secrets calls are returned as secrets_refused for context. Volume is high in most accounts, so raise the thresholds rather than widening the window. Use for: secret scanning, credential harvesting, who enumerated secret scopes, secrets discovery, listScopes activity, someone reading many secrets, credential access.'
RETURN
  SELECT
    to_date(a.event_time) AS event_date,
    a.user_identity.email AS actor,
    SUM(CASE WHEN a.action_name IN ('listScopes', 'listSecrets', 'listAcls') THEN 1 ELSE 0 END) AS scopes_enumerated,
    -- Successful reads only: listing calls carry no key (they used to add an empty ':' entry),
    -- and refused reads are not secrets obtained.
    SIZE(COLLECT_SET(CASE WHEN a.action_name = 'getSecret' AND a.response.status_code = 200
                          THEN CONCAT(COALESCE(a.request_params['scope'], ''), ':',
                                      COALESCE(a.request_params['key'], '')) END)) AS secrets_used,
    SUM(CASE WHEN a.response.status_code <> 200 THEN 1 ELSE 0 END) AS secrets_refused,
    MAX(a.service_name) AS service_name
  FROM system.access.audit AS a
  -- service_name = 'secrets': Unity Catalog also emits a listSecrets action, with other request_params.
  WHERE a.service_name = 'secrets'
    AND a.action_name IN ('listScopes', 'listSecrets', 'listAcls', 'getSecret')
    AND a.event_time BETWEEN start_time AND end_time
  GROUP BY to_date(a.event_time), a.user_identity.email
  HAVING SUM(CASE WHEN a.action_name IN ('listScopes', 'listSecrets', 'listAcls') THEN 1 ELSE 0 END) >= scopes_threshold
     AND SIZE(COLLECT_SET(CASE WHEN a.action_name = 'getSecret' AND a.response.status_code = 200
                               THEN CONCAT(COALESCE(a.request_params['scope'], ''), ':',
                                           COALESCE(a.request_params['key'], '')) END)) >= secrets_threshold;

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
-- The notebook keys on the external token methods (API_EXT_PAT_TOKEN,
-- API_AAD_OAUTH_TOKEN, API_OIDC_TOKEN) and groups by (credential, source_ip)
-- with the port stripped from the IP. ONE credential presenting from MANY
-- source IPs is the signal: a leaked token being tried from multiple places.
-- Entra and OAuth tokens may carry no tokenId, so the credential falls back to
-- the OAuth client_id, then to method + principal, rather than dropping them.
--
-- Two changes keep OAuth from flooding it (measured on SFE, 30 days: 93K OAuth
-- tokens, 47,821 on more than one IP): IPs that also carry Databricks-internal
-- authentication (cluster PATs, in-house OAuth clients behind Apps/serverless)
-- are platform egress, not a second location, and are excluded; and only
-- credentials seen from more than one IP are returned. Result: 9 tokens.
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
  token_id       STRING    COMMENT 'The credential being presented: token id, else OAuth client id, else method:principal',
  credential_type STRING   COMMENT 'authenticationMethod: API_EXT_PAT_TOKEN (PAT), API_AAD_OAUTH_TOKEN (Entra ID), API_OIDC_TOKEN (Databricks OAuth)',
  distinct_ips   BIGINT    COMMENT 'Distinct source IPs that presented this token. >1 warrants a look',
  source_ips     STRING    COMMENT 'The IPs, comma separated',
  first_seen     TIMESTAMP COMMENT 'First use in the window (UTC)',
  last_seen      TIMESTAMP COMMENT 'Last use in the window (UTC)',
  attempts       BIGINT    COMMENT 'Total presentations',
  actors         STRING    COMMENT 'Identities associated with the token',
  user_agents    STRING    COMMENT 'Distinct clients that presented it'
)
COMMENT 'External API tokens -- personal access tokens (API_EXT_PAT_TOKEN), Entra ID tokens (API_AAD_OAUTH_TOKEN) and Databricks OAuth tokens (API_OIDC_TOKEN) -- grouped by credential, showing how many distinct source IPs presented each one. The credential is the token id, else the OAuth client id, else the principal for that token type; credential_type says which. Only credentials presented from more than one IP are returned. Cluster-internal tokens (API_INT_PAT_TOKEN) and IPs that are Databricks platform egress (they also carry cluster-internal or in-house OAuth authentication, e.g. a Databricks App relaying the user token) are excluded. MITRE T1078 Valid Accounts, T1552 Unsecured Credentials, T1550.001 Application Access Token. A single credential presenting from MANY IPs is the leaked-token signal -- one token is meant to live in one place. Geo enrichment from the source notebook is not available here (it needs a MaxMind database file), so judge by IP spread and user agent instead. Use for: token scanning, leaked tokens, PAT used from multiple locations, OAuth token used from multiple IPs, Entra or service principal token abuse, token abuse, stolen access token, is a token compromised, token used from many IPs, was any token used from more than one IP.'
RETURN
  SELECT
    COALESCE(a.request_params['tokenId'], a.request_params['client_id'],
             CONCAT(a.request_params['authenticationMethod'], ':', a.user_identity.email)) AS token_id,
    MAX(a.request_params['authenticationMethod']) AS credential_type,
    COUNT(DISTINCT regexp_replace(a.source_ip_address, ':[0-9]+$', '')) AS distinct_ips,
    CONCAT_WS(', ', COLLECT_SET(regexp_replace(a.source_ip_address, ':[0-9]+$', ''))) AS source_ips,
    MIN(a.event_time) AS first_seen,
    MAX(a.event_time) AS last_seen,
    COUNT(*) AS attempts,
    CONCAT_WS(', ', COLLECT_SET(a.user_identity.email)) AS actors,
    CONCAT_WS(', ', COLLECT_SET(a.user_agent)) AS user_agents
  FROM system.access.audit AS a
  LEFT ANTI JOIN (
    -- Platform egress: IPs that also carry Databricks-internal authentication in the
    -- window (cluster-internal PATs, in-house OAuth clients used by Apps/serverless).
    SELECT DISTINCT regexp_replace(p.source_ip_address, ':[0-9]+$', '') AS ip
    FROM system.access.audit AS p
    WHERE p.event_time BETWEEN start_time AND end_time
      AND (p.request_params['authenticationMethod'] IN ('API_INT_PAT_TOKEN', 'API_INHOUSE_OAUTH_TOKEN')
           OR p.action_name IN ('workspaceInHouseOAuthClientAuthentication', 'accountInHouseOAuthClientAuthentication'))
  ) AS platform ON regexp_replace(a.source_ip_address, ':[0-9]+$', '') = platform.ip
  WHERE a.request_params['authenticationMethod'] IN ('API_EXT_PAT_TOKEN', 'API_AAD_OAUTH_TOKEN', 'API_OIDC_TOKEN')
    AND a.event_time BETWEEN start_time AND end_time
  GROUP BY COALESCE(a.request_params['tokenId'], a.request_params['client_id'],
                    CONCAT(a.request_params['authenticationMethod'], ':', a.user_identity.email))
  HAVING COUNT(DISTINCT regexp_replace(a.source_ip_address, ':[0-9]+$', '')) > 1;

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
-- WHY THIS EXISTS ALONGSIDE detect_data_movement_downloads: that function is a
-- volume table across every download action; this one scores notebook exports
-- against each principal's OWN history, which is what separates a code-theft
-- spike from a loud automated account. Keep both.
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
-- The baseline is read from its OWN trailing window -- baseline_days long,
-- ending baseline_exclude_days before start_time -- not from inside the scan
-- window, so any window works (a one-day question has a baseline too) and the
-- gap keeps a live export that began just before start_time from inflating its
-- own fence.
--
-- Noise controls, same as the source notebook:
--   * self-export exclusion -- a principal reading under its own home directory
--     (/Workspace/Users/<self>/...) is usually platform tooling (Databricks Apps
--     pulling a deployment bundle). Self-exports still COUNT when they come from
--     a network (/24) the principal did not use in the baseline window and the
--     IP is not Databricks platform egress (it also carries cluster-internal or
--     in-house OAuth authentication): a stolen token emptying its owner's home.
--   * no_baseline_threshold -- a first-seen principal has no history, so it is
--     scored against a flat number rather than being invisible. That is the
--     failure mode that would matter most in a real incident: a new account
--     exfiltrating on day one. Default 50 (was 600, which let modest theft by a
--     never-exporting service principal through).
--
-- NOTEBOOKS_EXPORTED counts DISTINCT paths, so re-exporting one notebook 500
-- times reads as 1. That is correct for IP exfiltration (breadth of code taken,
-- not request volume) and is deliberate -- do not "fix" it to a raw count.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_bulk_notebook_export(
  start_time            TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time              TIMESTAMP COMMENT 'End of the search window (inclusive)',
  baseline_exclude_days INT       COMMENT 'Gap in days between the baseline window and start_time, so a live export cannot inflate its own fence. Source notebook default: 2',
  iqr_multiplier        DOUBLE    COMMENT 'Multiplier on the floored IQR when building the fence. Source notebook default: 5.0',
  iqr_floor             INT       COMMENT 'Minimum IQR term, guaranteeing a minimum absolute rise over normal. Source notebook default: 100',
  no_baseline_threshold INT       COMMENT 'Flat threshold for a principal with no baseline. Source notebook default: 50',
  baseline_days         INT       COMMENT 'Length in days of the baseline window that ends baseline_exclude_days before start_time. Source notebook default: 30'
)
RETURNS TABLE (
  event_date            DATE   COMMENT 'Day of the bulk export (UTC)',
  actor                 STRING COMMENT 'Principal that exported',
  notebooks_exported    BIGINT COMMENT 'DISTINCT notebooks exported that day',
  threshold_applied     DOUBLE COMMENT 'This principal own fence, or the flat fallback when it has no history',
  iqrs_from_median      DOUBLE COMMENT 'How many IQRs above this principal normal day -- the anomaly magnitude',
  baseline_median       DOUBLE COMMENT 'This principal usual daily count, for context',
  formats_used          STRING COMMENT 'Export formats seen. SOURCE means raw code',
  self_home_new_network BIGINT COMMENT 'Of those, notebooks from the principal OWN home exported from a new network',
  source_ips            STRING COMMENT 'Source IPs of the counted exports',
  analysis              STRING COMMENT 'One-line summary for triage'
)
COMMENT 'Bulk notebook export scored against each principal OWN history (Tukey fence: Q3 + multiplier * max(IQR, floor)), not a global threshold. The baseline comes from its own window of baseline_days ending baseline_exclude_days before start_time, so any search window works. MITRE T1567 Exfiltration Over Web Service, TA0010 Exfiltration. This is source-code / IP exfiltration. Self-exports from a principal own home directory are excluded as platform tooling UNLESS they come from a network the principal did not use in the baseline window and the IP is not Databricks platform egress (self_home_new_network counts those) -- a stolen token emptying its owner home. First-seen principals with no baseline are scored against a flat threshold so they are never invisible. Counts DISTINCT notebooks, so breadth of code taken rather than request volume. Use for: bulk notebook export, source code exfiltration, who exported many notebooks, exported other users notebooks, IP theft, someone downloading all our code, notebook export spike, mass export, code exfiltration, stolen token exporting a home folder.'
RETURN
  -- The CTE chain is wrapped in a subquery deliberately. A SQL UDF body cannot
  -- begin with a top-level WITH: the CREATE fails with an opaque
  -- "request failed due to an unexpected condition" (no parse error, no line
  -- number). Verified live -- the identical query runs standalone but the CREATE
  -- is rejected until the WITH sits inside SELECT * FROM ( ... ).
  SELECT * FROM (
  WITH platform_ips AS (
    SELECT DISTINCT regexp_replace(p.source_ip_address, ':[0-9]+$', '') AS ip
    FROM system.access.audit AS p
    WHERE p.event_time BETWEEN start_time AND end_time
      AND (p.request_params['authenticationMethod'] IN ('API_INT_PAT_TOKEN', 'API_INHOUSE_OAUTH_TOKEN')
           OR p.action_name IN ('workspaceInHouseOAuthClientAuthentication', 'accountInHouseOAuthClientAuthentication'))
  ),
  scan AS (
    SELECT
      to_date(a.event_time) AS event_date,
      a.user_identity.email AS actor,
      a.request_params['notebookFullPath'] AS notebook_path,
      a.request_params['workspaceExportFormat'] AS export_format,
      regexp_replace(a.source_ip_address, ':[0-9]+$', '') AS ip,
      COALESCE(NULLIF(regexp_extract(regexp_replace(a.source_ip_address, ':[0-9]+$', ''), '^([0-9]+[.][0-9]+[.][0-9]+)[.]', 1), ''),
               regexp_replace(a.source_ip_address, ':[0-9]+$', '')) AS net,
      contains(COALESCE(a.request_params['notebookFullPath'], ''), COALESCE(a.user_identity.email, ' ')) AS self_home
    FROM system.access.audit AS a
    WHERE a.action_name = 'workspaceExport'
      AND a.event_time BETWEEN start_time AND end_time
  ),
  seen_nets AS (
    SELECT DISTINCT b.user_identity.email AS actor,
      COALESCE(NULLIF(regexp_extract(regexp_replace(b.source_ip_address, ':[0-9]+$', ''), '^([0-9]+[.][0-9]+[.][0-9]+)[.]', 1), ''),
               regexp_replace(b.source_ip_address, ':[0-9]+$', '')) AS net
    FROM system.access.audit AS b
    WHERE b.event_time >= timestampadd(DAY, -(baseline_exclude_days + baseline_days), start_time)
      AND b.event_time <  timestampadd(DAY, -baseline_exclude_days, start_time)
      AND b.user_identity.email IN (SELECT DISTINCT actor FROM scan)
  ),
  exports AS (
    SELECT s.*,
           (s.self_home AND n.net IS NULL AND pi.ip IS NULL) AS self_home_new_network
    FROM scan AS s
    LEFT JOIN seen_nets AS n ON s.actor = n.actor AND s.net = n.net
    LEFT JOIN platform_ips AS pi ON s.ip = pi.ip
    WHERE NOT s.self_home OR (n.net IS NULL AND pi.ip IS NULL)
  ),
  per_user_day AS (
    SELECT event_date, actor,
           COUNT(DISTINCT notebook_path) AS notebooks_exported,
           COUNT(DISTINCT CASE WHEN self_home_new_network THEN notebook_path END) AS self_home_new_network,
           CONCAT_WS('/', COLLECT_SET(export_format)) AS formats_used,
           CONCAT_WS(', ', slice(array_sort(COLLECT_SET(ip)), 1, 10)) AS source_ips
    FROM exports
    GROUP BY event_date, actor
  ),
  baseline AS (
    SELECT to_date(b.event_time) AS event_date, b.user_identity.email AS actor,
           COUNT(DISTINCT b.request_params['notebookFullPath']) AS notebooks_exported
    FROM system.access.audit AS b
    WHERE b.action_name = 'workspaceExport'
      AND b.event_time >= timestampadd(DAY, -(baseline_exclude_days + baseline_days), start_time)
      AND b.event_time <  timestampadd(DAY, -baseline_exclude_days, start_time)
      AND NOT contains(COALESCE(b.request_params['notebookFullPath'], ''), COALESCE(b.user_identity.email, ' '))
    GROUP BY to_date(b.event_time), b.user_identity.email
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
  -- Every output column is named here, not only by the caller's column list: the Lakewatch
  -- rule runtime drops a derived-table column list, so unnamed items would lose their names.
  SELECT
    d.event_date,
    d.actor,
    d.notebooks_exported,
    ROUND(COALESCE(t.user_threshold, CAST(no_baseline_threshold AS DOUBLE)), 1) AS threshold_applied,
    ROUND((d.notebooks_exported - t.median) / NULLIF(t.iqr, 0), 1) AS iqrs_from_median,
    ROUND(t.median, 1) AS baseline_median,
    d.formats_used,
    d.self_home_new_network,
    d.source_ips,
    CONCAT(CAST(d.notebooks_exported AS STRING), ' notebooks exported (threshold ',
           CAST(ROUND(COALESCE(t.user_threshold, CAST(no_baseline_threshold AS DOUBLE)), 1) AS STRING),
           ', formats: ', d.formats_used,
           CASE WHEN d.self_home_new_network > 0
                THEN CONCAT(', ', CAST(d.self_home_new_network AS STRING), ' from own home on a new network') ELSE '' END,
           ')') AS analysis
  FROM per_user_day AS d
  LEFT JOIN per_user_threshold AS t ON d.actor = t.actor
  WHERE d.notebooks_exported >= COALESCE(t.user_threshold, CAST(no_baseline_threshold AS DOUBLE))
  );

-- --------------------------------------------------------------------------
-- Encoded command execution in SQL statements and notebook/job commands.
-- Port of behavioral/encoded_command_execution.py (David Veuve, PR #10).
--
-- Detects hex/base64 payloads decoded at runtime -- UNHEX(), `xxd -r`,
-- `base64 -d | bash`, `printf "<hex>" | xxd -r -p | bash` -- the obfuscation
-- technique seen in Databricks pen tests to slip a shell command past
-- plain-text keyword detections. MITRE T1027 (Obfuscated Files or Information)
-- and T1059 (Command and Scripting Interpreter), TA0005 Defense Evasion.
--
-- TWO SOURCES, UNION ALL:
--   * system.query.history -- SQL cells, DBSQL warehouses, SQL-via-API. The actor
--     is executed_by (the submitter), NOT executed_as: executed_as is the run-as
--     identity, which masks the real submitter behind an owner or service
--     principal on scheduled/owned queries -- wrong for incident attribution.
--   * system.access.audit  -- notebook and job command executions (runCommand,
--     submitCommand), plus Command Execution API 1.2 calls (data-plane-router /
--     commandExecute, text in request_params.command, verbose audit only). service_name IN ('notebook','jobs') is load-bearing:
--     verified live, `jobs` runCommand outnumbers `notebook` ~370x (133,143 vs
--     356 in 30 days), and a scheduled job task is exactly where an encoded
--     payload would live -- it also buys persistence and a schedule. Filtering
--     `notebook` alone misses ~99.7% of command executions.
--
-- REGEX-ESCAPING TRAP (verified live 2026-09-03): the source notebook is PySpark
-- and writes r"\b" / r"\|" in rlike(). Ported VERBATIM into a Spark SQL string
-- literal those SILENTLY break -- a SQL literal turns \b into a backspace char,
-- so `base64 -d|bash` stops matching. Live proof:
--   'base64 -d|bash' RLIKE '(--decode|-d)\b'  -> FALSE   (backspace, wrong)
--   'base64 -d|bash' RLIKE '(--decode|-d)\\b' -> TRUE    (word boundary, right)
-- Every backslash below is doubled for this reason. Do NOT "simplify" them.
--
-- ENCODING_TECHNIQUE is a first-match triage label, NOT exhaustive: a statement
-- using both UNHEX( and base64 reports only UNHEX (tested first).
--
-- STATEMENT_TEXT is the payload itself -- treat output as SENSITIVE and inspect
-- before escalating. Legitimate data-engineering use of UNHEX/base64 for binary
-- data is the expected false positive; the pipe-to-shell requirement on the
-- printf branch is what separates an executable payload from a bare hex string.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_encoded_command_execution(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time         TIMESTAMP COMMENT 'When the statement/command ran (UTC)',
  actor              STRING    COMMENT 'Submitter: executed_by (query history) or user_identity.email (audit)',
  surface            STRING    COMMENT 'Where it ran: sql_warehouse, jobs, notebook, or command_execution_api',
  encoding_technique STRING    COMMENT 'First-match triage label (secret encode / UNHEX / xxd decode / base64 decode / printf hex) -- NOT exhaustive',
  source_ip          STRING    COMMENT 'Source IP (audit rows only; NULL for sql_warehouse -- query history carries none)',
  statement_id       STRING    COMMENT 'statement_id (query history) or commandId (audit), for pivoting',
  statement_text     STRING    COMMENT 'SENSITIVE: the full statement/command carrying the encoded payload. Redact before sharing.'
)
COMMENT 'SQL statements, notebook/job commands and Command Execution API calls that decode a hex or base64 payload at runtime (UNHEX of a hex string literal, xxd -r, base64 -d | bash, printf hex | bash) to obfuscate an executed command, or that ENCODE secret values (base64/hex of dbutils.secrets.get or SQL secret(), or a list-read-encode dump of scopes) to get past output redaction. MITRE T1027 Obfuscated Files or Information, T1059 Command and Scripting Interpreter, TA0005 Defense Evasion. Observed in Databricks pen tests to hide curl exfiltration, reverse shells and credential harvesting from plain-text keyword detections. Reads BOTH system.query.history AND system.access.audit (notebook + job command events, and data-plane-router commandExecute when verbose audit logging is on) -- requires SELECT on system.query.history. statement_text is the payload itself: SENSITIVE, redact before sharing. Legitimate UNHEX/base64 data engineering is the expected false positive. Statements that contain the own text of this function (its encoding_technique column) are excluded, so Genie, Lakewatch or a test running it do not report themselves. Use for: encoded command execution, obfuscated commands, hex encoded payload, base64 decode and execute, UNHEX, xxd, obfuscation, defense evasion, hidden shell command, encoded reverse shell, command injection obfuscation, secret redaction bypass, secrets printed encoded, remote command execution API.'
RETURN
  SELECT * FROM (
    SELECT
      to_timestamp(q.start_time) AS event_time,
      q.executed_by              AS actor,
      'sql_warehouse'            AS surface,
      CASE
        WHEN upper(q.statement_text) RLIKE '(BASE64|HEX|ENCODE|REVERSE)\\s*\\(\\s*SECRET\\s*\\(' THEN 'secret encode (redaction bypass)'
        WHEN q.statement_text RLIKE '(?i)UNHEX\\s*\\(\\s*[\'"][0-9a-fA-F]{16,}' THEN 'UNHEX'
        WHEN q.statement_text LIKE '%xxd%' AND q.statement_text LIKE '%-r%' THEN 'xxd decode'
        WHEN q.statement_text LIKE '%base64%'                               THEN 'base64 decode'
        WHEN q.statement_text LIKE '%printf%'                               THEN 'printf hex'
        ELSE 'encoded payload'
      END                        AS encoding_technique,
      CAST(NULL AS STRING)       AS source_ip,
      q.statement_id             AS statement_id,
      q.statement_text           AS statement_text
    FROM system.query.history AS q
    WHERE q.start_time BETWEEN start_time AND end_time
      -- this function's own text (Genie, Lakewatch or a test running it) is not a payload
      AND lower(q.statement_text) NOT LIKE '%encoding_technique%'
      AND (
        q.statement_text RLIKE '(?i)UNHEX\\s*\\(\\s*[\'"][0-9a-fA-F]{16,}'
        OR (q.statement_text LIKE '%xxd%' AND q.statement_text LIKE '%-r%')
        OR (q.statement_text LIKE '%base64%' AND q.statement_text RLIKE '(--decode|-d)\\b')
        OR (q.statement_text LIKE '%printf%' AND q.statement_text RLIKE '[0-9a-fA-F]{20,}'
            AND (q.statement_text LIKE '%xxd%' OR q.statement_text RLIKE '\\|\\s*(ba)?sh\\b'))
        OR upper(q.statement_text) RLIKE '(BASE64|HEX|ENCODE|REVERSE)\\s*\\(\\s*SECRET\\s*\\('
      )
    UNION ALL
    SELECT
      a.event_time                    AS event_time,
      a.user_identity.email           AS actor,
      CASE WHEN a.action_name = 'commandExecute' THEN 'command_execution_api' ELSE a.service_name END AS surface,
      CASE
        WHEN a.secret_encode                                                THEN 'secret encode (redaction bypass)'
        WHEN a.cmd RLIKE '(?i)UNHEX\\s*\\(\\s*[\'"][0-9a-fA-F]{16,}' THEN 'UNHEX'
        WHEN a.cmd LIKE '%xxd%' AND a.cmd LIKE '%-r%'                       THEN 'xxd decode'
        WHEN a.cmd LIKE '%base64%'                                          THEN 'base64 decode'
        WHEN a.cmd LIKE '%printf%'                                          THEN 'printf hex'
        ELSE 'encoded payload'
      END                             AS encoding_technique,
      a.source_ip_address             AS source_ip,
      a.statement_id                  AS statement_id,
      a.cmd                           AS statement_text
    FROM (
      SELECT x.*,
             COALESCE(x.request_params['commandText'], x.request_params['command']) AS cmd,
             COALESCE(x.request_params['commandId'], x.request_params['context_id']) AS statement_id,
             (COALESCE(x.request_params['commandText'], x.request_params['command'])
                RLIKE '(b(16|32|64|85)encode|a85encode|hexlify|codecs\\.encode)\\s*\\(\\s*dbutils\\.secrets\\.get(Bytes)?\\(|dbutils\\.secrets\\.get(Bytes)?\\([^)]*\\)\\s*(\\.encode\\([^)]*\\))?\\s*\\.(hex|encode)\\(|\\.join\\(\\s*(list\\()?\\s*dbutils\\.secrets\\.get\\(|for\\s+\\w+\\s+in\\s+dbutils\\.secrets\\.get\\('
              OR (COALESCE(x.request_params['commandText'], x.request_params['command']) LIKE '%dbutils.secrets.list%'
                  AND COALESCE(x.request_params['commandText'], x.request_params['command']) LIKE '%dbutils.secrets.get%'
                  AND COALESCE(x.request_params['commandText'], x.request_params['command']) RLIKE '(b(16|32|64|85)encode|a85encode|hexlify|codecs\\.encode|\\.hex\\(\\))')) AS secret_encode
      FROM system.access.audit AS x
      WHERE x.event_time BETWEEN start_time AND end_time
        AND ((x.service_name IN ('notebook', 'jobs') AND x.action_name IN ('runCommand', 'submitCommand'))
             OR (x.service_name = 'data-plane-router' AND x.action_name = 'commandExecute'))
    ) AS a
    WHERE lower(COALESCE(a.cmd, '')) NOT LIKE '%encoding_technique%'
      AND (a.cmd RLIKE '(?i)UNHEX\\s*\\(\\s*[\'"][0-9a-fA-F]{16,}'
       OR (a.cmd LIKE '%xxd%' AND a.cmd LIKE '%-r%')
       OR (a.cmd LIKE '%base64%' AND a.cmd RLIKE '(--decode|-d)\\b')
       OR (a.cmd LIKE '%printf%' AND a.cmd RLIKE '[0-9a-fA-F]{20,}'
           AND (a.cmd LIKE '%xxd%' OR a.cmd RLIKE '\\|\\s*(ba)?sh\\b'))
       OR a.secret_encode)
  );
