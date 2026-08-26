-- =============================================================================
-- Genie Agent Trusted Assets -- IP access lists + security configuration
-- =============================================================================
-- Ported from:
--   base/detections/event-based/configuration_changes_high_priority.py
--   base/detections/event-based/configuration_changes_account_level.py
--   base/detections/event-based/configuration_changes_workspace_level.py
--   base/detections/event-based/verbose_audit_logging_disabled.py
--   base/detections/event-based/attempted_logon_from_denied_ip.py
--
-- These are the INCIDENT-RESPONSE functions: "who widened our IP allow list",
-- "show me every security config change", "was audit logging turned off".
--
-- WHY SQL FUNCTIONS AND NOT THE NOTEBOOKS. A Genie Agent's Trusted Assets are
-- "parameterized example queries and SQL functions whose exact logic has been
-- verified" -- it cannot call a PySpark @detect function. The notebooks stay as
-- they are for scheduled/batch alerting; these functions are the interactive
-- investigation surface over the same logic. Keep both in step: if a notebook's
-- filter changes, change it here too.
--
-- Every COMMENT ends with a "Use for:" list of real analyst phrasings. That text
-- is not decoration -- it is what Genie matches a natural-language question
-- against when choosing a function, so phrase it the way customers actually ask.
--
-- Set your target schema before running:
--   USE CATALOG <your_catalog>; USE SCHEMA security_detections;
-- =============================================================================

-- -----------------------------------------------------------------------------
-- IP access list changes, WITH the before/after CIDR diff.
--
-- The diff is the point. Audit logs record the SUBMITTED state of a change, not
-- a before/after pair -- there is no "previous value" column anywhere in
-- system.access.audit. LAG over event_time partitioned by list id reconstructs
-- it, which is the only way to answer "what IPs did they add".
--
-- SCOPE NOTE, verified against a live account 2026-08-26: every IP-ACL mutation
-- (create/update/delete) is emitted with service_name='accounts' and
-- audit_level='WORKSPACE_LEVEL' -- even though IP ACLs also exist at account
-- scope. So filter on service_name, NOT on audit_level. Filtering
-- audit_level='ACCOUNT_LEVEL' here returns nothing and looks like "no changes",
-- which is the worst possible failure mode during an investigation.
-- Account-scope validation failures surface separately as
-- accountIpAclsValidationFailed (see detect_ip_acl_validation_failures below).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION detect_ip_access_list_changes(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time      TIMESTAMP COMMENT 'When the change was made (UTC)',
  action          STRING    COMMENT 'createIpAccessList / updateIpAccessList / deleteIpAccessList',
  status          STRING    COMMENT 'Success or Failure',
  actor           STRING    COMMENT 'Email of the identity that made the change',
  source_ip       STRING    COMMENT 'IP the change request came FROM',
  user_agent      STRING    COMMENT 'Client used (browser, terraform, CLI, SDK)',
  workspace_id    STRING    COMMENT 'Workspace the list belongs to',
  list_label      STRING    COMMENT 'Human label of the access list',
  list_type       STRING    COMMENT 'ALLOW or BLOCK',
  new_value       STRING    COMMENT 'CIDRs submitted by THIS change',
  previous_value  STRING    COMMENT 'CIDRs from the prior change to the same list (NULL on first)',
  severity        STRING    COMMENT 'Triage hint: deletions rank above modifications',
  request_params  MAP<STRING, STRING> COMMENT 'Full raw payload, for evidence'
)
COMMENT 'IP access list creations, updates and deletions with the before/after CIDR diff reconstructed per list. MITRE T1484 Domain or Tenant Policy Modification. A widened ALLOW list or a deleted list enlarges the network attack surface. Use for: who changed the IP allow list, show me IP access list history, what IP ranges were added or removed, was our allow list modified, who deleted an IP access list, IP allowlist changelog, network access control changes.'
RETURN
  SELECT
    a.event_time,
    a.action_name,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    a.source_ip_address,
    a.user_agent,
    CAST(a.workspace_id AS STRING),
    COALESCE(a.request_params['label'], a.request_params['ip_access_list_id']),
    a.request_params['list_type'],
    COALESCE(a.request_params['ip_addresses'], a.request_params['ipAddresses']),
    LAG(COALESCE(a.request_params['ip_addresses'], a.request_params['ipAddresses']))
      OVER (
        PARTITION BY COALESCE(a.request_params['ip_access_list_id'],
                              a.request_params['label'])
        ORDER BY a.event_time
      ),
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
-- NOT covered by any notebook in base/detections/ -- found while investigating a
-- live account, where it was the single highest-volume IP-related action (106
-- events vs 39 successful updates). Benign cause: an operator submitting a
-- malformed or conflicting CIDR. Adversarial cause: repeated attempts to push an
-- ACL change that the platform keeps rejecting. Volume and actor separate the
-- two, so both are returned.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION detect_ip_acl_validation_failures(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time     TIMESTAMP COMMENT 'When validation failed (UTC)',
  audit_level    STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL',
  actor          STRING    COMMENT 'Identity whose change was rejected',
  source_ip      STRING    COMMENT 'IP the rejected request came from',
  user_agent     STRING    COMMENT 'Client used',
  error_message  STRING    COMMENT 'Why the platform rejected it',
  request_params MAP<STRING, STRING> COMMENT 'Full raw payload, for evidence'
)
COMMENT 'Account-level IP ACL changes rejected by platform validation (accountIpAclsValidationFailed). High volume from one actor can indicate repeated attempts to weaken network controls; low volume is usually a malformed CIDR. Use for: failed IP access list changes, rejected allow list updates, IP ACL validation errors, who tried to change the IP allow list and failed, accountIpAclsValidationFailed.'
RETURN
  SELECT
    a.event_time,
    a.audit_level,
    a.user_identity.email,
    a.source_ip_address,
    a.user_agent,
    a.response.error_message,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.action_name = 'accountIpAclsValidationFailed'
    AND a.event_time BETWEEN start_time AND end_time;

-- -----------------------------------------------------------------------------
-- High-priority security configuration changes.
-- Port of configuration_changes_high_priority.py, same three event families and
-- the same severity ladder.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION detect_config_changes_high_priority(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time    TIMESTAMP COMMENT 'When the change was made (UTC)',
  action        STRING    COMMENT 'Audit action name',
  status        STRING    COMMENT 'Success or Failure',
  actor         STRING    COMMENT 'Identity that made the change',
  config_change STRING    COMMENT 'Which setting changed, and to what',
  severity      STRING    COMMENT 'CRITICAL / HIGH / MEDIUM triage hint',
  audit_level   STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL',
  source_ip     STRING    COMMENT 'IP the change came from',
  user_agent    STRING    COMMENT 'Client used',
  request_params MAP<STRING, STRING> COMMENT 'Full raw payload, for evidence'
)
COMMENT 'Security-weakening configuration changes: verbose audit logging disabled, IP access list modifications, and Databricks employee access window changes. MITRE T1484. Audit logging disabled ranks CRITICAL because it blinds every other detection. Use for: what security settings changed, show me configuration changes, did anyone disable audit logging, security posture changes, config changelog, who changed workspace settings, evasion activity.'
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
        THEN CONCAT('IP Access List - ', a.action_name)
      ELSE 'Unknown Configuration'
    END,
    CASE
      WHEN a.action_name = 'workspaceConfEdit'
       AND a.request_params['workspaceConfKeys'] = 'enableVerboseAuditLogs'
       AND a.request_params['workspaceConfValues'] = 'false'
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
-- Port of configuration_changes_account_level.py. Kept separate from the
-- high-priority function because that notebook filters ONLY setSetting and
-- deliberately does not include IP ACLs -- collapsing them would misrepresent
-- which detection found what.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION detect_config_changes_account_level(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time     TIMESTAMP COMMENT 'When the change was made (UTC)',
  service_name   STRING    COMMENT 'Emitting service',
  action         STRING    COMMENT 'Audit action name',
  actor          STRING    COMMENT 'Identity that made the change',
  source_ip      STRING    COMMENT 'IP the change came from',
  user_agent     STRING    COMMENT 'Client used',
  request_params MAP<STRING, STRING> COMMENT 'Which setting changed, and to what'
)
COMMENT 'Account-level setting changes (setSetting at ACCOUNT_LEVEL). These apply across every workspace in the account, so blast radius is account-wide. Use for: account level configuration changes, account settings modified, what changed at the account level, setSetting events, account-wide config changes.'
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
  WHERE a.audit_level = 'ACCOUNT_LEVEL'
    AND a.action_name = 'setSetting'
    AND a.event_time BETWEEN start_time AND end_time;

-- -----------------------------------------------------------------------------
-- Login attempts blocked by an IP access list.
-- Port of attempted_logon_from_denied_ip.py.
--
-- Investigative pairing worth knowing: if an allow list was WIDENED, the denial
-- rate against that list should DROP at the change timestamp. That makes this
-- function corroborating evidence for when a widening actually took effect --
-- run it either side of a detect_ip_access_list_changes hit.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION detect_denied_ip_logon_attempts(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time   TIMESTAMP COMMENT 'When access was denied (UTC)',
  actor        STRING    COMMENT 'Identity that was blocked (may be empty pre-auth)',
  source_ip    STRING    COMMENT 'Blocked source IP',
  user_agent   STRING    COMMENT 'Client used',
  workspace_id STRING    COMMENT 'Workspace that rejected the attempt',
  attempts     BIGINT    COMMENT 'Attempts from this identity+IP in the window'
)
COMMENT 'Login attempts rejected by IP access lists (IpAccessDenied), aggregated per identity and source IP. Use for: blocked login attempts, denied IP addresses, who was blocked by the allow list, access denied events, attempts from unauthorized IPs, brute force from blocked IPs.'
RETURN
  SELECT
    MAX(a.event_time),
    a.user_identity.email,
    a.source_ip_address,
    MAX(a.user_agent),
    CAST(MAX(a.workspace_id) AS STRING),
    COUNT(*)
  FROM system.access.audit AS a
  WHERE a.action_name = 'IpAccessDenied'
    AND a.event_time BETWEEN start_time AND end_time
  GROUP BY a.user_identity.email, a.source_ip_address;
