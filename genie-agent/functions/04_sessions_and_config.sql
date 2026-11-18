-- =============================================================================
-- Genie Agent Trusted Assets -- session anomalies + remaining config detections
-- =============================================================================
-- Ports 5 detections. Replace ${CATALOG} / ${SCHEMA} before running.
--
-- THE SESSION TRIO. base/detections/behavioral/ has three session-hijacking
-- notebooks (frequent_logins, multi_device, session_count) that share the same
-- preamble: filter to interactive logins, drop RFC1918 source IPs, and drop a
-- known-service user_agent allowlist. They differ only in what they then count.
-- Those two filters are the reason the detections work at all -- without them
-- every Databricks internal service and every VPN'd user is a false positive --
-- so they are reproduced faithfully in each function below rather than factored
-- away.
-- =============================================================================

-- --------------------------------------------------------------------------
-- One identity logging in from multiple IPs in a short window.
-- Port of behavioral/session_hijacking_frequent_logins.py.
--
-- The notebook's user_agent allowlist (Databricks-Service/driver,
-- Databricks-Runtime, Delta-Sharing-SparkStructuredStreaming, RawDBHttpClient,
-- wsfs/, mlflow-python, feature-store, dbr:) excludes platform services that
-- legitimately authenticate from many hosts. Dropping it would bury the signal.
-- It is matched case-sensitively and deliberately has no bare 'databricks':
-- that matched databricks-cli, databricks-sdk-* and the SQL connectors, which is
-- exactly the tooling an actor with a stolen token uses.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_session_multi_ip_logins(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)',
  min_ips    INT       COMMENT 'Minimum distinct public source IPs per identity to report. Try 3.'
)
RETURNS TABLE (
  actor        STRING    COMMENT 'Identity that logged in',
  distinct_ips BIGINT    COMMENT 'Distinct public source IPs used',
  logins       BIGINT    COMMENT 'Total logins in the window',
  source_ips   STRING    COMMENT 'The IPs, comma separated',
  user_agents  STRING    COMMENT 'Distinct clients used',
  first_seen   TIMESTAMP COMMENT 'First login (UTC)',
  last_seen    TIMESTAMP COMMENT 'Last login (UTC)'
)
COMMENT 'Identities that logged in from several distinct PUBLIC IP addresses within the window. MITRE T1078 Valid Accounts, T1550 Use Alternate Authentication Material. Private (RFC1918) IPs and known Databricks service user agents are excluded, because both legitimately appear from many hosts. Travel, VPN switching and mobile networks are common benign explanations -- geographic impossibility is the discriminator, and that needs IP geolocation this function does not do. Use for: session hijacking, logins from multiple IPs, impossible travel, account sharing, suspicious login locations, compromised credentials, one user many locations.'
RETURN
  SELECT
    a.user_identity.email AS actor,
    COUNT(DISTINCT a.source_ip_address) AS distinct_ips,
    COUNT(*) AS logins,
    CONCAT_WS(', ', COLLECT_SET(a.source_ip_address)) AS source_ips,
    CONCAT_WS(', ', COLLECT_SET(a.user_agent)) AS user_agents,
    MIN(a.event_time) AS first_seen,
    MAX(a.event_time) AS last_seen
  FROM system.access.audit AS a
  WHERE a.event_time BETWEEN start_time AND end_time
    AND a.service_name = 'accounts'
    -- Entra (aad*) and OAuth (oidc*, mintOAuthToken) logins are how service principals and
    -- Entra tokens authenticate; without them those identities were invisible.
    AND a.action_name IN ('login', 'tokenLogin', 'samlLogin', 'jwtLogin', 'aadTokenLogin', 'oidcTokenAuthorization',
                          'aadBrowserLogin', 'oidcBrowserLogin', 'mintOAuthToken')
    AND a.user_identity.email IS NOT NULL
    -- RFC 1918, CGNAT / Databricks-internal (100.64.0.0/10), loopback, link-local, IPv6 unique-local.
    AND NOT a.source_ip_address RLIKE
        '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.|127\\.|169\\.254\\.|(?i)f[cd][0-9a-f]{2}:)'
    -- Databricks-internal service clients only, case-sensitive. A bare 'databricks' (and lower())
    -- used to drop databricks-cli, databricks-sdk-* and the SQL connectors -- an actor's own tooling.
    AND NOT COALESCE(a.user_agent, '') RLIKE
        'Databricks-Service/driver|Databricks-Runtime|Delta-Sharing-SparkStructuredStreaming|RawDBHttpClient|wsfs/|mlflow-python|feature-store|dbr:'
  GROUP BY a.user_identity.email
  HAVING COUNT(DISTINCT a.source_ip_address) >= min_ips;

-- --------------------------------------------------------------------------
-- One session id used from multiple devices/IPs.
-- Port of behavioral/session_hijacking_multi_device.py.
--
-- The strongest of the three: a single session_id is meant to belong to one
-- browser on one machine. The same session presenting from two IPs or two user
-- agents is a stolen session cookie, not a travelling user -- a legitimate user
-- changing network gets a NEW session.
--
-- Token and OAuth login rows (tokenLogin, oidcTokenAuthorization, mintOAuthToken)
-- carry no session_id, so the credential is the tokenId / client_id. A token is
-- reported only when it is seen from a second public IP: the same token used by
-- two clients from one host (CLI plus a script) is normal.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_session_multi_device(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  credential_id   STRING    COMMENT 'The session id, or for token/OAuth logins the token id or OAuth client id',
  credential_type STRING    COMMENT 'session (browser) or token (PAT / OAuth token / OAuth client)',
  actor           STRING    COMMENT 'Identity the credential belongs to',
  distinct_ips    BIGINT    COMMENT 'Distinct public IPs using this credential',
  distinct_agents BIGINT    COMMENT 'Distinct user agents using this credential',
  source_ips      STRING    COMMENT 'The IPs, comma separated',
  user_agents     STRING    COMMENT 'The clients, comma separated',
  first_seen      TIMESTAMP COMMENT 'First activity (UTC)',
  last_seen       TIMESTAMP COMMENT 'Last activity (UTC)',
  events          BIGINT    COMMENT 'Logins with this credential'
)
COMMENT 'A single credential -- a browser session, or a personal access token / OAuth token / OAuth client -- used from more than one public IP (or, for a browser session, more than one user agent). MITRE T1550 Use Alternate Authentication Material, T1539 Steal Web Session Cookie. One session belongs to one browser on one machine, and one token replayed from a second network is the PAT/OAuth replay pattern. Token and OAuth login rows carry no session_id, so they are keyed by request_params tokenId / client_id. A token seen with two user agents from the same IP is normal (CLI plus a script) and is not reported. Private IPs, Databricks service agents and Databricks platform egress (IPs that also carry cluster-internal or in-house OAuth authentication, e.g. a Databricks App relaying the user token) are excluded. Use for: session hijacking, stolen session, session cookie theft, token replay, PAT used from two IPs, same token from different networks, hijacked session, session anomaly.'
RETURN
  SELECT
    COALESCE(a.session_id, a.request_params['tokenId'], a.request_params['client_id']) AS credential_id,
    CASE WHEN a.session_id IS NOT NULL THEN 'session' ELSE 'token' END AS credential_type,
    MAX(a.user_identity.email) AS actor,
    COUNT(DISTINCT a.source_ip_address) AS distinct_ips,
    COUNT(DISTINCT a.user_agent) AS distinct_agents,
    CONCAT_WS(', ', COLLECT_SET(a.source_ip_address)) AS source_ips,
    CONCAT_WS(', ', COLLECT_SET(a.user_agent)) AS user_agents,
    MIN(a.event_time) AS first_seen,
    MAX(a.event_time) AS last_seen,
    COUNT(*) AS events
  FROM system.access.audit AS a
  LEFT ANTI JOIN (
    -- Platform egress: IPs that also carry Databricks-internal authentication in the window
    -- (cluster-internal PATs, in-house OAuth clients behind Apps / serverless). A user's token
    -- relayed by a Databricks App shows up from these; they are not a second location.
    SELECT DISTINCT p.source_ip_address AS ip
    FROM system.access.audit AS p
    WHERE p.event_time BETWEEN start_time AND end_time
      AND (p.request_params['authenticationMethod'] IN ('API_INT_PAT_TOKEN', 'API_INHOUSE_OAUTH_TOKEN')
           OR p.action_name IN ('workspaceInHouseOAuthClientAuthentication', 'accountInHouseOAuthClientAuthentication'))
  ) AS platform ON a.source_ip_address = platform.ip
  WHERE a.event_time BETWEEN start_time AND end_time
    AND a.service_name = 'accounts'
    AND a.action_name IN ('login', 'tokenLogin', 'samlLogin', 'jwtLogin', 'aadTokenLogin', 'oidcTokenAuthorization',
                          'aadBrowserLogin', 'oidcBrowserLogin', 'mintOAuthToken')
    AND COALESCE(a.session_id, a.request_params['tokenId'], a.request_params['client_id']) IS NOT NULL
    AND NOT a.source_ip_address RLIKE
        '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.|127\\.|169\\.254\\.|(?i)f[cd][0-9a-f]{2}:)'
    AND NOT COALESCE(a.user_agent, '') RLIKE
        'Databricks-Service/driver|Databricks-Runtime|Delta-Sharing-SparkStructuredStreaming'
  GROUP BY COALESCE(a.session_id, a.request_params['tokenId'], a.request_params['client_id']),
           CASE WHEN a.session_id IS NOT NULL THEN 'session' ELSE 'token' END
  HAVING COUNT(DISTINCT a.source_ip_address) > 1
      OR (MAX(CASE WHEN a.session_id IS NOT NULL THEN 1 ELSE 0 END) = 1 AND COUNT(DISTINCT a.user_agent) > 1);

-- --------------------------------------------------------------------------
-- Many sessions from one source IP.
-- Port of behavioral/session_hijacking_session_count.py.
--
-- Groups by (source_ip, actor) rather than by session: many sessions from one IP
-- for one identity suggests scripted re-authentication; many DISTINCT IDENTITIES
-- from one IP suggests a shared exit node or credential stuffing, which is why
-- distinct_actors is returned.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_session_high_count_per_ip(
  start_time   TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time     TIMESTAMP COMMENT 'End of the search window (inclusive)',
  min_sessions INT       COMMENT 'Minimum distinct sessions from one IP to report. Try 10.'
)
RETURNS TABLE (
  source_ip        STRING    COMMENT 'Public source IP',
  distinct_sessions BIGINT   COMMENT 'Distinct credentials signing in from this IP: browser sessions, PATs, OAuth clients',
  distinct_actors  BIGINT    COMMENT 'Distinct identities from this IP -- >1 suggests a shared node or stuffing',
  actors           STRING    COMMENT 'The identities, comma separated',
  user_agents      STRING    COMMENT 'Distinct clients',
  first_seen       TIMESTAMP COMMENT 'First activity (UTC)',
  last_seen        TIMESTAMP COMMENT 'Last activity (UTC)',
  events           BIGINT    COMMENT 'Total events from this IP'
)
COMMENT 'Public source IPs where an unusually high number of distinct credentials signed in (browser sessions, PATs, OAuth clients; short-lived OAuth tokens count as their client), with the count of distinct identities per IP. MITRE T1078 Valid Accounts, T1110 Brute Force. Many sessions for ONE identity suggests scripted re-authentication; many DISTINCT identities from one IP suggests a shared exit node, a proxy, or credential stuffing. Private IPs, Databricks service agents and Databricks platform egress IPs are excluded. Use for: many sessions from one IP, credential stuffing, brute force, suspicious IP activity, shared IP address, session count anomaly, proxy or VPN abuse.'
RETURN
  SELECT
    a.source_ip_address AS source_ip,
    COUNT(DISTINCT COALESCE(a.session_id,
                      CASE WHEN a.request_params['authenticationMethod'] = 'API_OIDC_TOKEN'
                           THEN COALESCE(a.request_params['client_id'], CONCAT('oauth:', a.user_identity.email)) END,
                      a.request_params['tokenId'], a.request_params['client_id'])) AS distinct_sessions,
    COUNT(DISTINCT a.user_identity.email) AS distinct_actors,
    CONCAT_WS(', ', COLLECT_SET(a.user_identity.email)) AS actors,
    CONCAT_WS(', ', COLLECT_SET(a.user_agent)) AS user_agents,
    MIN(a.event_time) AS first_seen,
    MAX(a.event_time) AS last_seen,
    COUNT(*) AS events
  FROM system.access.audit AS a
  LEFT ANTI JOIN (
    -- Platform egress: IPs that also carry Databricks-internal authentication in the window
    -- (cluster-internal PATs, in-house OAuth clients behind Apps / serverless). A user's token
    -- relayed by a Databricks App shows up from these; they are not a second location.
    SELECT DISTINCT p.source_ip_address AS ip
    FROM system.access.audit AS p
    WHERE p.event_time BETWEEN start_time AND end_time
      AND (p.request_params['authenticationMethod'] IN ('API_INT_PAT_TOKEN', 'API_INHOUSE_OAUTH_TOKEN')
           OR p.action_name IN ('workspaceInHouseOAuthClientAuthentication', 'accountInHouseOAuthClientAuthentication'))
  ) AS platform ON a.source_ip_address = platform.ip
  WHERE a.event_time BETWEEN start_time AND end_time
    -- Sign-ins only: counting every API call let one person's CLI session read as many credentials.
    AND a.action_name IN ('login', 'tokenLogin', 'samlLogin', 'jwtLogin', 'aadTokenLogin', 'oidcTokenAuthorization',
                          'aadBrowserLogin', 'oidcBrowserLogin', 'mintOAuthToken')
    -- A credential is a browser session, a PAT, or an OAuth client. Short-lived OAuth access tokens
    -- (API_OIDC_TOKEN) get a new tokenId every few minutes, so they count as their client, not
    -- as one credential each.
    AND COALESCE(a.session_id,
                      CASE WHEN a.request_params['authenticationMethod'] = 'API_OIDC_TOKEN'
                           THEN COALESCE(a.request_params['client_id'], CONCAT('oauth:', a.user_identity.email)) END,
                      a.request_params['tokenId'], a.request_params['client_id']) IS NOT NULL
    AND NOT a.source_ip_address RLIKE
        '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.|127\\.|169\\.254\\.|(?i)f[cd][0-9a-f]{2}:)'
    AND NOT COALESCE(a.user_agent, '') RLIKE
        'Databricks-Service/driver|Databricks-Runtime|Delta-Sharing-SparkStructuredStreaming|RawDBHttpClient|wsfs/|mlflow-python|feature-store'
  GROUP BY a.source_ip_address
  HAVING COUNT(DISTINCT COALESCE(a.session_id,
                      CASE WHEN a.request_params['authenticationMethod'] = 'API_OIDC_TOKEN'
                           THEN COALESCE(a.request_params['client_id'], CONCAT('oauth:', a.user_identity.email)) END,
                      a.request_params['tokenId'], a.request_params['client_id'])) >= min_sessions;

-- --------------------------------------------------------------------------
-- Verbose audit logging disabled.
-- Port of event-based/verbose_audit_logging_disabled.py.
--
-- This gets its own function despite overlapping
-- detect_config_changes_high_priority, because it is the FIRST question of any
-- investigation and deserves a direct answer rather than a filter over a broader
-- result. Verified live: workspaceConfEdit occurs (57 events).
--
-- Returns BOTH enable and disable events on purpose: knowing when logging came
-- back on is what bounds the visibility gap at the other end.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_verbose_audit_logging_disabled(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time   TIMESTAMP COMMENT 'When the setting changed (UTC)',
  set_to       STRING    COMMENT 'true (enabled) or false (DISABLED -- a visibility gap starts here)',
  severity     STRING    COMMENT 'CRITICAL when disabled, INFO when re-enabled',
  status       STRING    COMMENT 'Success or Failure',
  actor        STRING    COMMENT 'Identity that changed it',
  workspace_id STRING    COMMENT 'Workspace affected',
  source_ip    STRING    COMMENT 'IP the request came from',
  user_agent   STRING    COMMENT 'Client used'
)
COMMENT 'Changes to the enableVerboseAuditLogs workspace setting, both disables and re-enables. MITRE T1562.008 Impair Defenses: Disable Cloud Logs, TA0005 Defense Evasion. RUN THIS FIRST IN ANY INVESTIGATION: while verbose logging is off, workspaceConfEdit and notebook-level actions may never be recorded, so every other detection has a blind spot for that period and any absence of evidence afterwards is uninterpretable. Both directions are returned so the gap can be bounded at both ends. Use for: was audit logging disabled, verbose audit logging, who turned off logging, defense evasion, log tampering, audit gap, is my audit trail complete.'
RETURN
  SELECT
    a.event_time,
    filter(transform(split(COALESCE(a.request_params['workspaceConfKeys'], ''), ','), (k, i) -> named_struct('key', trim(k), 'value', trim(try_element_at(split(COALESCE(a.request_params['workspaceConfValues'], ''), ','), i + 1)))), c -> c.key = 'enableVerboseAuditLogs')[0].value AS set_to,
    CASE WHEN lower(COALESCE(filter(transform(split(COALESCE(a.request_params['workspaceConfKeys'], ''), ','), (k, i) -> named_struct('key', trim(k), 'value', trim(try_element_at(split(COALESCE(a.request_params['workspaceConfValues'], ''), ','), i + 1)))), c -> c.key = 'enableVerboseAuditLogs')[0].value, '')) = 'false'
         THEN 'CRITICAL - audit logging disabled, visibility gap starts here'
         ELSE 'INFO - audit logging enabled' END,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    CAST(a.workspace_id AS STRING),
    a.source_ip_address,
    a.user_agent
  FROM system.access.audit AS a
  WHERE a.action_name = 'workspaceConfEdit'
    -- Keys and values are comma-joined in matching positions when one request changes
    -- several settings; match the key anywhere in the list, not the whole string.
    AND exists(transform(split(COALESCE(a.request_params['workspaceConfKeys'], ''), ','), (k, i) -> named_struct('key', trim(k), 'value', trim(try_element_at(split(COALESCE(a.request_params['workspaceConfValues'], ''), ','), i + 1)))), c -> c.key = 'enableVerboseAuditLogs')
    AND a.event_time BETWEEN start_time AND end_time;

-- --------------------------------------------------------------------------
-- All workspace-level configuration changes.
-- Port of event-based/configuration_changes_workspace_level.py.
--
-- The broad net: EVERY workspaceConfEdit, not just the security-relevant subset
-- that detect_config_changes_high_priority covers. Use this when you need a
-- complete workspace config changelog rather than a triaged one.
-- Verified live: 57 events / 90 days.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_config_changes_workspace_level(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time    TIMESTAMP COMMENT 'When the change was made (UTC)',
  service_name  STRING    COMMENT 'Emitting service',
  setting_key   STRING    COMMENT 'Which workspace setting changed',
  new_value     STRING    COMMENT 'What it was set to',
  actor         STRING    COMMENT 'Identity that made the change',
  workspace_id  STRING    COMMENT 'Workspace affected',
  source_ip     STRING    COMMENT 'IP the request came from',
  user_agent    STRING    COMMENT 'Client used'
)
COMMENT 'Every workspace-level configuration change (all workspaceConfEdit events) with the setting key and its new value. Broader than the high-priority function, which triages only the security-relevant subset -- use this one when you need a COMPLETE workspace config changelog. MITRE T1484 Domain or Tenant Policy Modification. Use for: all workspace configuration changes, complete config changelog, every setting that changed, workspace settings audit, what settings were modified, workspaceConfEdit.'
RETURN
  SELECT
    a.event_time,
    a.service_name,
    COALESCE(a.request_params['workspaceConfKeys'], 'unknown_key'),
    COALESCE(a.request_params['workspaceConfValues'], 'unknown_value'),
    a.user_identity.email,
    CAST(a.workspace_id AS STRING),
    a.source_ip_address,
    a.user_agent
  FROM system.access.audit AS a
  WHERE a.action_name = 'workspaceConfEdit'
    AND a.event_time BETWEEN start_time AND end_time;
