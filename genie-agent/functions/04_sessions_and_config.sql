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
-- The notebook's user_agent allowlist (databricks, Databricks-Service/driver,
-- Databricks-Runtime, Delta-Sharing-SparkStructuredStreaming, RawDBHttpClient,
-- mlflow-python, feature-store, dbr:) excludes platform services that
-- legitimately authenticate from many hosts. Dropping it would bury the signal.
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
    AND a.action_name IN ('login', 'tokenLogin', 'samlLogin', 'jwtLogin')
    AND a.user_identity.email IS NOT NULL
    AND NOT a.source_ip_address RLIKE '^(10\\..*|192\\.168\\..*|172\\.(1[6-9]|2[0-9]|3[0-1])\\..*)$'
    AND NOT lower(COALESCE(a.user_agent, '')) RLIKE
        'databricks|databricks-service/driver|databricks-runtime|delta-sharing-sparkstructuredstreaming|rawdbhttpclient|mlflow-python|feature-store|dbr:'
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
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_session_multi_device(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  session_id     STRING    COMMENT 'The session presenting from more than one place',
  actor          STRING    COMMENT 'Identity the session belongs to',
  distinct_ips   BIGINT    COMMENT 'Distinct public IPs using this session',
  distinct_agents BIGINT   COMMENT 'Distinct user agents using this session',
  source_ips     STRING    COMMENT 'The IPs, comma separated',
  user_agents    STRING    COMMENT 'The clients, comma separated',
  first_seen     TIMESTAMP COMMENT 'First activity (UTC)',
  last_seen      TIMESTAMP COMMENT 'Last activity (UTC)',
  events         BIGINT    COMMENT 'Events on this session'
)
COMMENT 'A single session id used from more than one public IP or more than one user agent. MITRE T1550 Use Alternate Authentication Material, T1539 Steal Web Session Cookie. This is the strongest session signal available in audit data: one session belongs to one browser on one machine, and a legitimate user changing network gets a NEW session rather than carrying the old one. Private IPs and Databricks service agents are excluded. Use for: session hijacking, stolen session, session cookie theft, same session from different devices, session used from two IPs, hijacked session, session anomaly.'
RETURN
  SELECT
    a.session_id,
    MAX(a.user_identity.email) AS actor,
    COUNT(DISTINCT a.source_ip_address) AS distinct_ips,
    COUNT(DISTINCT a.user_agent) AS distinct_agents,
    CONCAT_WS(', ', COLLECT_SET(a.source_ip_address)) AS source_ips,
    CONCAT_WS(', ', COLLECT_SET(a.user_agent)) AS user_agents,
    MIN(a.event_time) AS first_seen,
    MAX(a.event_time) AS last_seen,
    COUNT(*) AS events
  FROM system.access.audit AS a
  WHERE a.event_time BETWEEN start_time AND end_time
    AND a.service_name = 'accounts'
    AND a.action_name IN ('login', 'tokenLogin', 'samlLogin', 'jwtLogin')
    AND a.session_id IS NOT NULL
    AND NOT a.source_ip_address RLIKE '^(10\\..*|192\\.168\\..*|172\\.(1[6-9]|2[0-9]|3[0-1])\\..*)$'
    AND NOT lower(COALESCE(a.user_agent, '')) RLIKE
        'databricks-service/driver|databricks-runtime|delta-sharing-sparkstructuredstreaming'
  GROUP BY a.session_id
  HAVING COUNT(DISTINCT a.source_ip_address) > 1
      OR COUNT(DISTINCT a.user_agent) > 1;

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
  distinct_sessions BIGINT   COMMENT 'Distinct session ids from this IP',
  distinct_actors  BIGINT    COMMENT 'Distinct identities from this IP -- >1 suggests a shared node or stuffing',
  actors           STRING    COMMENT 'The identities, comma separated',
  user_agents      STRING    COMMENT 'Distinct clients',
  first_seen       TIMESTAMP COMMENT 'First activity (UTC)',
  last_seen        TIMESTAMP COMMENT 'Last activity (UTC)',
  events           BIGINT    COMMENT 'Total events from this IP'
)
COMMENT 'Public source IPs producing an unusually high number of distinct sessions, with the count of distinct identities per IP. MITRE T1078 Valid Accounts, T1110 Brute Force. Many sessions for ONE identity suggests scripted re-authentication; many DISTINCT identities from one IP suggests a shared exit node, a proxy, or credential stuffing. Private IPs and Databricks service agents are excluded. Use for: many sessions from one IP, credential stuffing, brute force, suspicious IP activity, shared IP address, session count anomaly, proxy or VPN abuse.'
RETURN
  SELECT
    a.source_ip_address AS source_ip,
    COUNT(DISTINCT a.session_id) AS distinct_sessions,
    COUNT(DISTINCT a.user_identity.email) AS distinct_actors,
    CONCAT_WS(', ', COLLECT_SET(a.user_identity.email)) AS actors,
    CONCAT_WS(', ', COLLECT_SET(a.user_agent)) AS user_agents,
    MIN(a.event_time) AS first_seen,
    MAX(a.event_time) AS last_seen,
    COUNT(*) AS events
  FROM system.access.audit AS a
  WHERE a.event_time BETWEEN start_time AND end_time
    AND a.session_id IS NOT NULL
    AND NOT a.source_ip_address RLIKE '^(10\\..*|192\\.168\\..*|172\\.(1[6-9]|2[0-9]|3[0-1])\\..*)$'
    AND NOT lower(COALESCE(a.user_agent, '')) RLIKE
        'databricks|databricks-service/driver|databricks-runtime|delta-sharing-sparkstructuredstreaming|rawdbhttpclient|mlflow-python|feature-store'
  GROUP BY a.source_ip_address
  HAVING COUNT(DISTINCT a.session_id) >= min_sessions;

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
    a.request_params['workspaceConfValues'] AS set_to,
    CASE WHEN lower(COALESCE(a.request_params['workspaceConfValues'], '')) = 'false'
         THEN 'CRITICAL - audit logging disabled, visibility gap starts here'
         ELSE 'INFO - audit logging enabled' END,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    CAST(a.workspace_id AS STRING),
    a.source_ip_address,
    a.user_agent
  FROM system.access.audit AS a
  WHERE a.action_name = 'workspaceConfEdit'
    AND a.request_params['workspaceConfKeys'] = 'enableVerboseAuditLogs'
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
