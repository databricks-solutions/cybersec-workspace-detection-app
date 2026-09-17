-- =============================================================================
-- Genie Agent Trusted Asset -- INVESTIGATION TRIAGE (the entry point)
-- =============================================================================
-- This is NOT a detection. It is the first query an investigation should run
-- once past the audit-visibility check: given an open goal ("were we
-- compromised?", "who looks suspicious?"), it ranks actors and their source IPs
-- by how much they touched SECURITY-SENSITIVE controls in the window, so the
-- lead surfaces at the top of a small result instead of drowning in login noise.
--
-- WHY THIS EXISTS. A Genie space answers one query per turn. Asked to
-- investigate, the model would otherwise either UNION every family into one
-- query (which truncates to a sample and buries the signal) or rank by raw event
-- volume (which floats a busy service principal to the top). Neither finds the
-- real lead. This asset makes triage deterministic: it ranks by the count of
-- DISTINCT sensitive action types an actor touched -- breadth across families --
-- because the signature of an incident is one identity touching several rare,
-- high-severity action types (an IP-ACL burst is low-volume but high-signal),
-- not one identity generating a lot of routine traffic.
--
-- WHAT COUNTS AS SENSITIVE. The action set below is the union of the action
-- names the detections in this repo already treat as security-relevant --
-- IP access list changes and denials, workspace/account config changes, admin
-- and role grants, identity and MFA changes, token lifecycle, secret access,
-- storage/metastore/mount changes, and download/export. Routine authentication
-- (login / tokenLogin / samlLogin / jwtLogin / mfaLogin / certLogin) is
-- DELIBERATELY EXCLUDED: it is high-volume and would dominate the ranking. The
-- non-SSO / employee-logon detections cover authentication specifically; triage
-- is about who touched controls.
--
-- Account CREATION and DELETION (MITRE T1136 / T1531) are also DELIBERATELY
-- EXCLUDED from the ranked set, for a different reason: their audit action names
-- are the generic 'add' / 'delete', which only mean "user account" when also
-- scoped to service_name='accounts' (and, for creation,
-- request_params.endpoint='adminConsole'). This asset ranks on action_name alone
-- with no service scope, so admitting bare 'add'/'delete' would match unrelated
-- add/delete events across services and inflate the breadth count. Persistence via
-- an attacker-created identity, and its later cleanup, are covered by the dedicated
-- detect_user_account_created / detect_user_account_deleted functions -- run those
-- against the lead during the Step 3 pivot when persistence or cleanup is in scope.
--
-- The output is one row per actor+source_ip, capped at the top 50 by breadth
-- then failures then volume. Pivot on the top row with the per-family detection
-- queries (e.g. detect_ip_access_list_changes) filtered to that actor.
-- =============================================================================
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_investigation_triage(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  actor                     STRING    COMMENT 'Identity that acted (user_identity.email)',
  source_ip                 STRING    COMMENT 'Source IP the actions came from',
  distinct_sensitive_actions INT      COMMENT 'How many distinct sensitive action types -- breadth is the lead signal',
  families_touched          INT       COMMENT 'How many distinct sensitive families (ip_acl, config, admin_role, identity, credential, secret, storage, data_movement)',
  failed_attempts           BIGINT    COMMENT 'Sensitive events that did not return status 200',
  total_sensitive_events    BIGINT    COMMENT 'Total sensitive events for this actor+IP in the window',
  sensitive_action_types    STRING    COMMENT 'The distinct sensitive action names seen (order not significant)',
  first_seen                TIMESTAMP COMMENT 'First sensitive event for this actor+IP (UTC)',
  last_seen                 TIMESTAMP COMMENT 'Last sensitive event for this actor+IP (UTC)'
)
COMMENT 'Investigation triage and starting point: ranks actors and their source IPs by how many distinct security-sensitive control actions they touched in the window (breadth across families first, then failed attempts, then volume), so the investigation lead surfaces without a raw sweep. Excludes routine logins by design. Run this FIRST for any open-ended investigation, then pivot on the top actor/IP with the per-family detection queries. Use for: where do I start, triage, who looks suspicious, rank actors by risk, investigation starting point, who touched the most security controls, find the lead, who should I investigate first, suspicious activity overview, most active on security settings, prioritize actors for review.'
RETURN
  SELECT
    a.user_identity.email,
    a.source_ip_address,
    CAST(COUNT(DISTINCT a.action_name) AS INT),
    CAST(COUNT(DISTINCT CASE
      WHEN a.action_name IN ('createIpAccessList','updateIpAccessList','deleteIpAccessList','IpAccessDenied','accountIpAclsValidationFailed') THEN 'ip_acl'
      WHEN a.action_name IN ('workspaceConfEdit','setSetting') THEN 'config'
      WHEN a.action_name IN ('setAdmin','setAccountAdmin','removeAdmin','changeAccountOwner','setRoleAssignment','updateRoleAssignment') THEN 'admin_role'
      WHEN a.action_name IN ('createGroup','removeGroup','addPrincipalToGroup','addPrincipalsToGroup','updateUser','changePassword','mfaAddKey','mfaDeleteKey') THEN 'identity'
      WHEN a.action_name IN ('generateDbToken','revokeDbToken') THEN 'credential'
      WHEN a.action_name IN ('getSecret','putSecret','listScopes') THEN 'secret'
      WHEN a.action_name IN ('createStorageCredential','updateStorageCredential','mount','updateMetastore') THEN 'storage'
      WHEN a.action_name IN ('downloadLargeResults','downloadPreviewResults','downloadQueryResult','filesGet','workspaceExport') THEN 'data_movement'
      ELSE 'other'
    END) AS INT),
    COUNT(CASE WHEN a.response.status_code <> 200 THEN 1 END),
    COUNT(*),
    CONCAT_WS(', ', COLLECT_SET(a.action_name)),
    MIN(a.event_time),
    MAX(a.event_time)
  FROM system.access.audit AS a
  WHERE a.event_time BETWEEN start_time AND end_time
    AND a.user_identity.email IS NOT NULL
    AND a.action_name IN (
      'createIpAccessList','updateIpAccessList','deleteIpAccessList','IpAccessDenied','accountIpAclsValidationFailed',
      'workspaceConfEdit','setSetting',
      'setAdmin','setAccountAdmin','removeAdmin','changeAccountOwner','setRoleAssignment','updateRoleAssignment',
      'createGroup','removeGroup','addPrincipalToGroup','addPrincipalsToGroup','updateUser','changePassword','mfaAddKey','mfaDeleteKey',
      'generateDbToken','revokeDbToken',
      'getSecret','putSecret','listScopes',
      'createStorageCredential','updateStorageCredential','mount','updateMetastore',
      'downloadLargeResults','downloadPreviewResults','downloadQueryResult','filesGet','workspaceExport'
    )
  GROUP BY a.user_identity.email, a.source_ip_address
  ORDER BY 3 DESC, 5 DESC, 6 DESC
  LIMIT 50;
