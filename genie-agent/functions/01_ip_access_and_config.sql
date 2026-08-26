-- =============================================================================
-- Genie Agent Trusted Assets -- IP access lists + security configuration
-- =============================================================================
-- Ported from:
--   base/detections/event-based/configuration_changes_high_priority.py
--   base/detections/event-based/configuration_changes_account_level.py
--   base/detections/event-based/attempted_logon_from_denied_ip.py
--
-- WHY SQL FUNCTIONS AND NOT THE NOTEBOOKS. A Genie Agent chooses between Trusted
-- Assets -- "parameterized example queries and SQL functions whose exact logic
-- has been verified" -- and cannot call a PySpark @detect function. The notebooks
-- stay as-is for scheduled/batch alerting; these are the interactive
-- investigation surface over the same logic. Keep both in step.
--
-- Every COMMENT ends with a "Use for:" list of real analyst phrasings. That text
-- is not decoration -- it is what Genie matches a question against.
--
-- ALL request_params KEYS BELOW WERE VERIFIED AGAINST LIVE AUDIT DATA
-- (SFE workspace, 90-day window, 2026-08-26). Do not "tidy" them to the names
-- the REST API documentation uses -- the audit log does NOT use those names, and
-- a wrong key yields NULL rather than an error. See the note on
-- detect_ip_access_list_changes for the one that matters most.
--
--   createIpAccessList / updateIpAccessList / deleteIpAccessList
--                                   -> ipAccessListId, userId          (2 keys only)
--   accountIpAclsValidationFailed   -> sourceIpAddress, user
--   IpAccessDenied                  -> path, userId, user
--   workspaceConfEdit               -> workspaceConfKeys, workspaceConfValues
--   setSetting                      -> settingName, settingTypeName,
--                                      settingKeyName, settingValueForAudit,
--                                      settingKeyTypeName
--
-- Install:
--   USE CATALOG <your_catalog>; USE SCHEMA security_detections;
-- =============================================================================

-- -----------------------------------------------------------------------------
-- IP access list changes.
--
-- READ THIS BEFORE PROMISING A CUSTOMER A "CONFIG DIFF".
--
-- The audit log does NOT record the CIDR values for these events. Verified over
-- all 54 IP-ACL mutations in a live 90-day window: request_params contains
-- EXACTLY TWO keys -- ipAccessListId and userId -- and response.result is NULL
-- on every row. There is no ipAddresses, no ip_addresses, no label, no
-- list_type, and no before/after payload anywhere in the event.
--
-- So a before/after CIDR diff CANNOT be reconstructed from system.access.audit.
-- An earlier draft of this function did LAG(request_params['ip_addresses']) and
-- would have returned NULL for every value -- a function that looks like it
-- works and silently answers nothing, which during an investigation reads as
-- "no changes were made". That is the single most dangerous outcome here, which
-- is why this is called out at the top rather than buried.
--
-- WHAT YOU CAN ANSWER: which list changed (id), who changed it, when, from what
-- IP, with which client, and whether it succeeded. That is a CHANGELOG, and it
-- is enough to scope an incident and to identify the actor.
--
-- TO GET THE ACTUAL CIDRs you need the current state from the REST API
-- (GET /api/2.0/ip-access-lists, or account-level
-- /api/2.0/accounts/{id}/ip-access-lists) correlated to these ids. Point-in-time
-- historical values are not recoverable from audit data at all -- if a customer
-- needs them, capture list state on a schedule going forward.
--
-- SCOPE: filter on service_name, NOT audit_level. Verified live -- every IP-ACL
-- mutation is service_name='accounts' with audit_level='WORKSPACE_LEVEL', even
-- though IP ACLs also exist at account scope. Filtering
-- audit_level='ACCOUNT_LEVEL' here returns zero rows.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION detect_ip_access_list_changes(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time       TIMESTAMP COMMENT 'When the change was made (UTC)',
  action           STRING    COMMENT 'createIpAccessList / updateIpAccessList / deleteIpAccessList',
  status           STRING    COMMENT 'Success or Failure',
  actor            STRING    COMMENT 'Email of the identity that made the change',
  source_ip        STRING    COMMENT 'IP the change request came FROM',
  user_agent       STRING    COMMENT 'Client used (browser, terraform, CLI, SDK)',
  workspace_id     STRING    COMMENT 'Workspace whose list was changed',
  ip_access_list_id STRING   COMMENT 'Id of the list changed. Resolve to CIDRs via the REST API; the audit log does not carry them',
  change_seq       INT       COMMENT 'Nth change to this list in the window, oldest = 1',
  severity         STRING    COMMENT 'Triage hint: deletions rank above modifications',
  request_params   MAP<STRING, STRING> COMMENT 'Raw payload (only ipAccessListId + userId exist)'
)
COMMENT 'IP access list creations, updates and deletions: which list, who, when, from where, with what client. MITRE T1484 Domain or Tenant Policy Modification. IMPORTANT: the audit log does NOT contain the CIDR/IP values for these events, so a before/after IP diff cannot be produced from audit data -- report the changelog and resolve ip_access_list_id against the IP Access Lists REST API for current CIDRs. Use for: who changed the IP allow list, IP access list history, was our allow list modified, who deleted an IP access list, IP allowlist changelog, network access control changes, allow list audit trail.'
RETURN
  SELECT
    a.event_time,
    a.action_name,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    a.source_ip_address,
    a.user_agent,
    CAST(a.workspace_id AS STRING),
    a.request_params['ipAccessListId'],
    CAST(ROW_NUMBER() OVER (
      PARTITION BY a.request_params['ipAccessListId'] ORDER BY a.event_time
    ) AS INT),
    CASE
      WHEN a.action_name = 'deleteIpAccessList' THEN 'HIGH - IP access list deleted'
      ELSE 'MEDIUM - IP access list modified'
    END,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.action_name IN ('createIpAccessList', 'updateIpAccessList', 'deleteIpAccessList')
    AND a.event_time BETWEEN start_time AND end_time;

-- -----------------------------------------------------------------------------
-- Account-level IP ACL validation failures.
--
-- Covered by NO notebook in base/detections/. Found while investigating live
-- data, where it was the highest-volume IP-ACL action by an order of magnitude
-- (447 events vs 54 successful mutations in the same 90 days).
--
-- Unlike the mutation events, this one DOES carry the offending IP, in
-- request_params['sourceIpAddress'] -- distinct from the top-level
-- source_ip_address column, which is where the REQUEST came from. Both are
-- returned because they answer different questions.
--
-- Benign cause: a client connecting from an IP outside the configured account
-- ACL. Adversarial cause: probing from many IPs to find one that passes. Volume
-- and IP spread separate the two.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION detect_ip_acl_validation_failures(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time      TIMESTAMP COMMENT 'When validation failed (UTC)',
  audit_level     STRING    COMMENT 'ACCOUNT_LEVEL for these events',
  actor           STRING    COMMENT 'Identity whose access was rejected',
  rejected_ip     STRING    COMMENT 'The IP that failed the account ACL check',
  request_ip      STRING    COMMENT 'Top-level source_ip_address of the request',
  user_agent      STRING    COMMENT 'Client used',
  attempts        BIGINT    COMMENT 'Failures for this identity+IP pair in the window'
)
COMMENT 'Account-level IP ACL validation failures (accountIpAclsValidationFailed), aggregated per identity and rejected IP. Carries the offending IP, unlike the ACL mutation events. Many distinct IPs from one identity can indicate probing for an allowed range; a single repeated IP is usually a user outside the corporate network. Use for: failed IP access list checks, rejected IP addresses, who was blocked by the account IP ACL, IP ACL validation errors, accountIpAclsValidationFailed, access blocked by IP policy.'
RETURN
  SELECT
    MAX(a.event_time),
    MAX(a.audit_level),
    COALESCE(a.user_identity.email, a.request_params['user']),
    a.request_params['sourceIpAddress'],
    MAX(a.source_ip_address),
    MAX(a.user_agent),
    COUNT(*)
  FROM system.access.audit AS a
  WHERE a.action_name = 'accountIpAclsValidationFailed'
    AND a.event_time BETWEEN start_time AND end_time
  GROUP BY COALESCE(a.user_identity.email, a.request_params['user']),
           a.request_params['sourceIpAddress'];

-- -----------------------------------------------------------------------------
-- High-priority security configuration changes.
-- Port of configuration_changes_high_priority.py -- same event families, same
-- severity ladder. workspaceConfEdit's keys (workspaceConfKeys /
-- workspaceConfValues) were verified live and match the notebook.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION detect_config_changes_high_priority(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time     TIMESTAMP COMMENT 'When the change was made (UTC)',
  action         STRING    COMMENT 'Audit action name',
  status         STRING    COMMENT 'Success or Failure',
  actor          STRING    COMMENT 'Identity that made the change',
  config_change  STRING    COMMENT 'Which setting changed, and to what',
  severity       STRING    COMMENT 'CRITICAL / HIGH / MEDIUM triage hint',
  audit_level    STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL',
  source_ip      STRING    COMMENT 'IP the change came from',
  user_agent     STRING    COMMENT 'Client used',
  request_params MAP<STRING, STRING> COMMENT 'Raw payload, for evidence'
)
COMMENT 'Security-weakening configuration changes: verbose audit logging disabled, IP access list modifications, and Databricks employee access window changes. MITRE T1484. Audit logging disabled ranks CRITICAL because it blinds every other detection. Use for: what security settings changed, show me configuration changes, did anyone disable audit logging, security posture changes, config changelog, who changed workspace settings, evasion activity, verbose audit logging.'
RETURN
  SELECT
    a.event_time,
    a.action_name,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    CASE
      WHEN a.action_name = 'workspaceConfEdit' THEN CONCAT(
        a.request_params['workspaceConfKeys'], ': ',
        COALESCE(a.request_params['workspaceConfValues'], 'N/A'))
      WHEN a.action_name IN ('createIpAccessList', 'updateIpAccessList', 'deleteIpAccessList')
        THEN CONCAT('IP Access List ', a.action_name, ' (id ',
                    COALESCE(a.request_params['ipAccessListId'], 'unknown'), ')')
      ELSE 'Unknown Configuration'
    END,
    CASE
      WHEN a.action_name = 'workspaceConfEdit'
       AND a.request_params['workspaceConfKeys'] = 'enableVerboseAuditLogs'
       AND lower(a.request_params['workspaceConfValues']) = 'false'
        THEN 'CRITICAL - Audit Logging Disabled'
      WHEN a.action_name = 'deleteIpAccessList' THEN 'HIGH - IP Access List Deleted'
      WHEN a.action_name IN ('createIpAccessList', 'updateIpAccessList')
        THEN 'MEDIUM - IP Access List Modified'
      WHEN a.action_name = 'workspaceConfEdit'
       AND a.request_params['workspaceConfKeys'] = 'customerApprovedWSLoginExpirationTime'
        THEN 'MEDIUM - Change to Databricks Employee Access Config'
      ELSE 'MEDIUM - Configuration Change'
    END,
    a.audit_level,
    a.source_ip_address,
    a.user_agent,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.event_time BETWEEN start_time AND end_time
    AND (
      (a.service_name = 'workspace'
        AND a.action_name = 'workspaceConfEdit'
        AND a.request_params['workspaceConfKeys'] = 'enableVerboseAuditLogs')
      OR a.action_name IN ('createIpAccessList', 'updateIpAccessList', 'deleteIpAccessList')
      OR (a.action_name = 'workspaceConfEdit'
        AND a.request_params['workspaceConfKeys'] = 'customerApprovedWSLoginExpirationTime')
    );

-- -----------------------------------------------------------------------------
-- Account-level settings changes (setSetting).
--
-- Port of configuration_changes_account_level.py. That notebook selects
-- request_params wholesale; the real keys are settingName, settingTypeName,
-- settingKeyName, settingValueForAudit and settingKeyTypeName (verified live),
-- so they are projected as named columns here -- Genie renders a named column
-- far better than a caller having to know a map key.
--
-- settingValueForAudit is the platform's own audit-safe rendering of the new
-- value. It is the closest thing to a "new value" that audit data provides for
-- settings, and unlike the IP-ACL events it IS populated.
--
-- audit_level='ACCOUNT_LEVEL' is a deliberate filter here and the ONE place it
-- is correct: setSetting is genuinely emitted at both scopes (verified: 8
-- ACCOUNT_LEVEL vs 25 WORKSPACE_LEVEL in 90 days) and this function is the
-- account-scope one.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION detect_config_changes_account_level(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time     TIMESTAMP COMMENT 'When the change was made (UTC)',
  service_name   STRING    COMMENT 'Emitting service',
  setting_name   STRING    COMMENT 'Which setting was changed',
  setting_key    STRING    COMMENT 'Key within that setting',
  new_value      STRING    COMMENT 'Audit-safe rendering of the new value',
  setting_type   STRING    COMMENT 'Setting type name',
  actor          STRING    COMMENT 'Identity that made the change',
  source_ip      STRING    COMMENT 'IP the change came from',
  user_agent     STRING    COMMENT 'Client used',
  request_params MAP<STRING, STRING> COMMENT 'Raw payload, for evidence'
)
COMMENT 'Account-level setting changes (setSetting at ACCOUNT_LEVEL), including the audit-safe new value. These apply across every workspace in the account, so blast radius is account-wide. Use for: account level configuration changes, account settings modified, what changed at the account level, setSetting events, account-wide config changes, who changed an account setting.'
RETURN
  SELECT
    a.event_time,
    a.service_name,
    a.request_params['settingName'],
    a.request_params['settingKeyName'],
    a.request_params['settingValueForAudit'],
    a.request_params['settingTypeName'],
    a.user_identity.email,
    a.source_ip_address,
    a.user_agent,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.audit_level = 'ACCOUNT_LEVEL'
    AND a.action_name = 'setSetting'
    AND a.event_time BETWEEN start_time AND end_time;

-- -----------------------------------------------------------------------------
-- Login attempts blocked by an IP access list.
-- Port of attempted_logon_from_denied_ip.py.
--
-- request_params carries path, userId and user (verified live) -- 'path' is the
-- endpoint that was blocked, which is useful triage: an API path versus a login
-- page distinguishes automation from a person.
--
-- Investigative pairing: if an allow list was WIDENED, denials against it should
-- DROP at that timestamp. Run either side of a detect_ip_access_list_changes hit
-- to confirm when a change actually took effect -- and since the audit log has no
-- CIDR values, this is one of the few ways to see the EFFECT of the change.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION detect_denied_ip_logon_attempts(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  last_seen    TIMESTAMP COMMENT 'Most recent denial for this identity+IP (UTC)',
  first_seen   TIMESTAMP COMMENT 'First denial for this identity+IP (UTC)',
  actor        STRING    COMMENT 'Identity that was blocked',
  source_ip    STRING    COMMENT 'Blocked source IP',
  attempts     BIGINT    COMMENT 'Denials for this identity+IP in the window',
  paths        STRING    COMMENT 'Distinct endpoints that were blocked',
  user_agent   STRING    COMMENT 'Client used',
  workspace_id STRING    COMMENT 'Workspace that rejected the attempt'
)
COMMENT 'Login and API attempts rejected by IP access lists (IpAccessDenied), aggregated per identity and source IP with the blocked endpoints. Use for: blocked login attempts, denied IP addresses, who was blocked by the allow list, access denied events, attempts from unauthorized IPs, brute force from blocked IPs, IpAccessDenied.'
RETURN
  SELECT
    MAX(a.event_time),
    MIN(a.event_time),
    COALESCE(a.user_identity.email, a.request_params['user']),
    a.source_ip_address,
    COUNT(*),
    CONCAT_WS(', ', COLLECT_SET(a.request_params['path'])),
    MAX(a.user_agent),
    CAST(MAX(a.workspace_id) AS STRING)
  FROM system.access.audit AS a
  WHERE a.action_name = 'IpAccessDenied'
    AND a.event_time BETWEEN start_time AND end_time
  GROUP BY COALESCE(a.user_identity.email, a.request_params['user']),
           a.source_ip_address;
