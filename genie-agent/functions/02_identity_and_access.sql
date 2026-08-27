-- =============================================================================
-- Genie Agent Trusted Assets -- identity, credentials, groups, admin privilege
-- =============================================================================
-- Ports 14 detections from base/detections/{behavioral,event-based}/.
--
-- Replace the placeholders before running (see 01_ip_access_and_config.sql for
-- why the names are fully qualified rather than relying on USE CATALOG):
--     ${CATALOG}  ->  your Unity Catalog catalog
--     ${SCHEMA}   ->  security_detections
--
-- request_params keys below are taken from each source notebook. Where a key was
-- confirmed against live audit data the comment says so; where a detection's
-- action does not occur in the reference account, the key is as the notebook has
-- it and is marked UNVERIFIED. A wrong key yields NULL, not an error, so treat
-- an all-NULL column as "verify the key", never as "no data".
-- =============================================================================

-- --------------------------------------------------------------------------
-- Personal access token created. Port of behavioral/access_token_created.py.
--
-- The notebook computes TOKEN_LIFETIME_DAYS from
-- request_params.tokenExpirationTime (epoch MILLIS) and keeps only rows > 0,
-- which drops already-expired/malformed rows. Preserved here.
--
-- The notebook also hardcodes an allowlist (user_agent ~ 'linux auth', src ip
-- 52.9.53.2) for a known internal job. That is environment-specific, so it is
-- NOT baked in -- the columns are returned instead and the caller can exclude.
-- Baking one account's allowlist into a shipped function would silently hide
-- real tokens in every other account.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_access_token_created(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time          TIMESTAMP COMMENT 'When the token was created (UTC)',
  status              STRING    COMMENT 'Success or Failure',
  actor               STRING    COMMENT 'Identity that created the token',
  token_lifetime_days DOUBLE    COMMENT 'Days until expiry. Long-lived tokens are the risk',
  source_ip           STRING    COMMENT 'IP the request came from',
  user_agent          STRING    COMMENT 'Client used -- distinguishes automation from a person',
  audit_level         STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL',
  request_params      MAP<STRING, STRING> COMMENT 'Raw payload, for evidence'
)
COMMENT 'Personal access tokens (PATs) created, with computed lifetime in days. MITRE T1098 Account Manipulation. A long-lived token is a durable credential that survives password rotation and often SSO; tokens minted from an unexpected user_agent or IP are the signal. Use for: who created a personal access token, new PATs, token creation, long-lived tokens, generateDbToken, who minted API credentials, token lifetime.'
RETURN
  SELECT
    a.event_time,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    ROUND((unix_timestamp(from_unixtime(CAST(a.request_params['tokenExpirationTime'] AS BIGINT) / 1000))
           - unix_timestamp(a.event_time)) / 3600 / 24, 0),
    a.source_ip_address,
    a.user_agent,
    a.audit_level,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.action_name = 'generateDbToken'
    AND a.event_time BETWEEN start_time AND end_time
    AND ROUND((unix_timestamp(from_unixtime(CAST(a.request_params['tokenExpirationTime'] AS BIGINT) / 1000))
           - unix_timestamp(a.event_time)) / 3600 / 24, 0) > 0;

-- --------------------------------------------------------------------------
-- Personal access token revoked. Port of behavioral/access_token_deleted.py.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_access_token_deleted(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time  TIMESTAMP COMMENT 'When the token was revoked (UTC)',
  status      STRING    COMMENT 'Success or Failure',
  actor       STRING    COMMENT 'Identity that revoked it',
  token_hash  STRING    COMMENT 'Hash of the revoked token',
  source_ip   STRING    COMMENT 'IP the request came from',
  user_agent  STRING    COMMENT 'Client used',
  audit_level STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL'
)
COMMENT 'Personal access tokens revoked (revokeDbToken). Usually routine hygiene, but mass revocation can be destructive action, and revoking a token right after use can be cleanup. Use for: revoked tokens, deleted PATs, token revocation, who removed an access token, revokeDbToken.'
RETURN
  SELECT
    a.event_time,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    a.request_params['tokenHash'],
    a.source_ip_address,
    a.user_agent,
    a.audit_level
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.action_name = 'revokeDbToken'
    AND a.event_time BETWEEN start_time AND end_time;

-- --------------------------------------------------------------------------
-- Account admin granted. Port of
-- event-based/account_admin_privileged_role_assignment.py.
--
-- The notebook covers TWO paths: direct (setAccountAdmin / changeAccountOwner)
-- and indirect (addPrincipalToGroup(s) into a caller-supplied admin group list).
-- The indirect path needs the customer's own admin group names, which this
-- function cannot know, so `admin_groups` is a PARAMETER -- a comma-separated
-- list. Empty (the default use) returns direct grants only.
--
-- Verified live: setAccountAdmin occurs (5 events), addPrincipalsToGroup occurs
-- (1). Both paths have real data in the reference account.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_account_admin_granted(
  start_time   TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time     TIMESTAMP COMMENT 'End of the search window (inclusive)',
  admin_groups STRING    COMMENT 'Comma-separated account-admin group names to also watch for membership adds. Pass an empty string for direct grants only.'
)
RETURNS TABLE (
  event_time   TIMESTAMP COMMENT 'When the privilege was granted (UTC)',
  grant_path   STRING    COMMENT 'DIRECT (setAccountAdmin/changeAccountOwner) or VIA_GROUP',
  action       STRING    COMMENT 'Audit action name',
  status       STRING    COMMENT 'Success or Failure',
  actor        STRING    COMMENT 'Identity that granted it',
  target       STRING    COMMENT 'Principal that received admin',
  target_group STRING    COMMENT 'Group joined, when grant_path is VIA_GROUP',
  source_ip    STRING    COMMENT 'IP the request came from',
  user_agent   STRING    COMMENT 'Client used',
  request_params MAP<STRING, STRING> COMMENT 'Raw payload, for evidence'
)
COMMENT 'Account administrator privilege granted, both directly (setAccountAdmin, changeAccountOwner) and indirectly by adding a principal to an admin group named in admin_groups. MITRE T1098 Account Manipulation, TA0004 Privilege Escalation. Account admin is the highest privilege in a Databricks account. Use for: who was made account admin, account admin grants, privilege escalation, new administrators, setAccountAdmin, changeAccountOwner, who granted admin rights, admin group membership changes.'
RETURN
  SELECT
    a.event_time,
    CASE WHEN a.action_name IN ('setAccountAdmin','changeAccountOwner')
         THEN 'DIRECT' ELSE 'VIA_GROUP' END,
    a.action_name,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    COALESCE(a.request_params['targetUserName'],
             a.request_params['target_user_name'],
             a.request_params['principals']),
    COALESCE(a.request_params['targetGroupName'], a.request_params['target_group_name']),
    a.source_ip_address,
    a.user_agent,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.event_time BETWEEN start_time AND end_time
    AND (
      a.action_name IN ('setAccountAdmin', 'changeAccountOwner')
      OR (
        a.action_name IN ('addPrincipalToGroup', 'addPrincipalsToGroup')
        AND admin_groups IS NOT NULL AND trim(admin_groups) <> ''
        AND COALESCE(a.request_params['targetGroupName'],
                     a.request_params['target_group_name'])
            IN (SELECT trim(g) FROM (SELECT explode(split(admin_groups, ',')) AS g))
      )
    );

-- --------------------------------------------------------------------------
-- Metastore admin / owner changed. Port of
-- event-based/metastore_admin_privilege_granted.py.
--
-- The notebook keys on updateMetastore WITH request_params.owner NOT NULL --
-- an updateMetastore that does not set an owner is an unrelated config change.
-- Same admin_groups parameter rationale as above.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_metastore_admin_granted(
  start_time       TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time         TIMESTAMP COMMENT 'End of the search window (inclusive)',
  admin_groups     STRING    COMMENT 'Comma-separated metastore-admin group names to also watch for membership adds. Empty string for direct grants only.'
)
RETURNS TABLE (
  event_time   TIMESTAMP COMMENT 'When it changed (UTC)',
  grant_path   STRING    COMMENT 'DIRECT (updateMetastore owner) or VIA_GROUP',
  action       STRING    COMMENT 'Audit action name',
  status       STRING    COMMENT 'Success or Failure',
  actor        STRING    COMMENT 'Identity that made the change',
  new_owner    STRING    COMMENT 'New metastore owner, when grant_path is DIRECT',
  target_group STRING    COMMENT 'Group joined, when grant_path is VIA_GROUP',
  source_ip    STRING    COMMENT 'IP the request came from',
  user_agent   STRING    COMMENT 'Client used',
  request_params MAP<STRING, STRING> COMMENT 'Raw payload, for evidence'
)
COMMENT 'Metastore administrator or owner changed (updateMetastore with an owner set), plus membership adds to metastore-admin groups named in admin_groups. MITRE T1098, TA0004 Privilege Escalation. A metastore admin controls Unity Catalog governance for every workspace sharing that metastore. Use for: who became metastore admin, metastore owner changed, Unity Catalog admin grants, updateMetastore, UC privilege escalation.'
RETURN
  SELECT
    a.event_time,
    CASE WHEN a.action_name = 'updateMetastore' THEN 'DIRECT' ELSE 'VIA_GROUP' END,
    a.action_name,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    a.request_params['owner'],
    COALESCE(a.request_params['targetGroupName'], a.request_params['target_group_name']),
    a.source_ip_address,
    a.user_agent,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.event_time BETWEEN start_time AND end_time
    AND (
      (a.action_name = 'updateMetastore' AND a.request_params['owner'] IS NOT NULL)
      OR (
        a.service_name = 'accounts'
        AND a.action_name IN ('addPrincipalToGroup', 'addPrincipalsToGroup')
        AND admin_groups IS NOT NULL AND trim(admin_groups) <> ''
        AND COALESCE(a.request_params['targetGroupName'],
                     a.request_params['target_group_name'])
            IN (SELECT trim(g) FROM (SELECT explode(split(admin_groups, ',')) AS g))
      )
    );

-- --------------------------------------------------------------------------
-- Workspace admin granted. Port of
-- event-based/workspace_admin_privileged_role_assignment.py.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_workspace_admin_granted(
  start_time   TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time     TIMESTAMP COMMENT 'End of the search window (inclusive)',
  admin_groups STRING    COMMENT 'Comma-separated workspace-admin group names to also watch. Empty string for direct grants only.'
)
RETURNS TABLE (
  event_time   TIMESTAMP COMMENT 'When the privilege was granted (UTC)',
  grant_path   STRING    COMMENT 'DIRECT or VIA_GROUP',
  action       STRING    COMMENT 'Audit action name',
  status       STRING    COMMENT 'Success or Failure',
  actor        STRING    COMMENT 'Identity that granted it',
  target       STRING    COMMENT 'Principal that received admin',
  target_group STRING    COMMENT 'Group joined, when grant_path is VIA_GROUP',
  workspace_id STRING    COMMENT 'Workspace the grant applies to',
  source_ip    STRING    COMMENT 'IP the request came from',
  user_agent   STRING    COMMENT 'Client used',
  request_params MAP<STRING, STRING> COMMENT 'Raw payload, for evidence'
)
COMMENT 'Workspace administrator privilege granted, directly (setAdmin) or by adding a principal to a workspace-admin group named in admin_groups. MITRE T1098, TA0004 Privilege Escalation. A workspace admin can read every notebook, alter every job, and change workspace security settings. Use for: who was made workspace admin, workspace admin grants, new admins on a workspace, setAdmin, privilege escalation in a workspace.'
RETURN
  SELECT
    a.event_time,
    CASE WHEN a.action_name IN ('setAdmin','removeAdmin') THEN 'DIRECT' ELSE 'VIA_GROUP' END,
    a.action_name,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    COALESCE(a.request_params['targetUserName'], a.request_params['target_user_name']),
    COALESCE(a.request_params['targetGroupName'], a.request_params['target_group_name']),
    CAST(a.workspace_id AS STRING),
    a.source_ip_address,
    a.user_agent,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.event_time BETWEEN start_time AND end_time
    AND (
      a.action_name IN ('setAdmin', 'removeAdmin')
      OR (
        a.service_name = 'accounts'
        AND a.action_name IN ('addPrincipalToGroup', 'addPrincipalsToGroup')
        AND admin_groups IS NOT NULL AND trim(admin_groups) <> ''
        AND COALESCE(a.request_params['targetGroupName'],
                     a.request_params['target_group_name'])
            IN (SELECT trim(g) FROM (SELECT explode(split(admin_groups, ',')) AS g))
      )
    );

-- --------------------------------------------------------------------------
-- User account created. Port of behavioral/user_account_created.py.
-- The notebook requires endpoint='adminConsole' AND a 200, i.e. a successful
-- console-driven add rather than any SCIM 'add'.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_user_account_created(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time  TIMESTAMP COMMENT 'When the account was created (UTC)',
  actor       STRING    COMMENT 'Identity that created it',
  target_user STRING    COMMENT 'Account that was created',
  endpoint    STRING    COMMENT 'Origin of the request (adminConsole)',
  source_ip   STRING    COMMENT 'IP the request came from',
  user_agent  STRING    COMMENT 'Client used',
  audit_level STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL'
)
COMMENT 'User accounts created through the admin console. MITRE T1136 Create Account. Attacker-created accounts are a persistence mechanism that survives password resets on the compromised original. Use for: new user accounts, who was added to the account, account creation, new users created, who created a user.'
RETURN
  SELECT
    a.event_time,
    a.user_identity.email,
    a.request_params['targetUserName'],
    a.request_params['endpoint'],
    a.source_ip_address,
    a.user_agent,
    a.audit_level
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.action_name = 'add'
    AND CAST(a.response.status_code AS INT) = 200
    AND a.request_params['endpoint'] = 'adminConsole'
    AND a.event_time BETWEEN start_time AND end_time;

-- --------------------------------------------------------------------------
-- User account deleted. Port of binary/user_account_deleted.py.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_user_account_deleted(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time  TIMESTAMP COMMENT 'When the account was deleted (UTC)',
  status      STRING    COMMENT 'Success or Failure',
  actor       STRING    COMMENT 'Identity that deleted it',
  target_user STRING    COMMENT 'Account that was deleted',
  source_ip   STRING    COMMENT 'IP the request came from',
  user_agent  STRING    COMMENT 'Client used',
  audit_level STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL'
)
COMMENT 'User accounts deleted. MITRE T1531 Account Access Removal. Mass deletion is destructive; deleting one account shortly after using it can be cleanup of an attacker-created identity. Use for: deleted user accounts, who removed a user, account deletion, offboarding events, removed identities.'
RETURN
  SELECT
    a.event_time,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    COALESCE(a.request_params['targetUserName'], a.request_params['targetUserId']),
    a.source_ip_address,
    a.user_agent,
    a.audit_level
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.action_name = 'delete'
    AND a.event_time BETWEEN start_time AND end_time;

-- --------------------------------------------------------------------------
-- Admin/user account attribute changes. Port of
-- event-based/user_admin_account_change.py -- keyed on updateUser.
-- Verified live: updateUser occurs (16 events).
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_user_account_changed(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time  TIMESTAMP COMMENT 'When the change was made (UTC)',
  status      STRING    COMMENT 'Success or Failure',
  actor       STRING    COMMENT 'Identity that made the change',
  target_user STRING    COMMENT 'Account that was modified',
  source_ip   STRING    COMMENT 'IP the request came from',
  user_agent  STRING    COMMENT 'Client used',
  audit_level STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL',
  request_params MAP<STRING, STRING> COMMENT 'What changed -- inspect for the modified attributes'
)
COMMENT 'User account attributes modified (updateUser) -- entitlements, active status, display name, roles. MITRE T1098 Account Manipulation. Re-enabling a disabled account or adding an entitlement is a quieter escalation path than granting admin outright. Use for: user account changes, modified users, entitlement changes, who changed a user account, updateUser, account attribute modification, reactivated accounts.'
RETURN
  SELECT
    a.event_time,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    COALESCE(a.request_params['targetUserName'], a.request_params['targetUserId']),
    a.source_ip_address,
    a.user_agent,
    a.audit_level,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.action_name = 'updateUser'
    AND a.event_time BETWEEN start_time AND end_time;

-- --------------------------------------------------------------------------
-- User role modified. Port of event-based/user_role_modified.py.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_user_role_modified(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time  TIMESTAMP COMMENT 'When the role changed (UTC)',
  action      STRING    COMMENT 'Audit action name',
  status      STRING    COMMENT 'Success or Failure',
  actor       STRING    COMMENT 'Identity that made the change',
  target      STRING    COMMENT 'Principal whose role changed',
  source_ip   STRING    COMMENT 'IP the request came from',
  user_agent  STRING    COMMENT 'Client used',
  request_params MAP<STRING, STRING> COMMENT 'Raw payload -- the role detail lives here'
)
COMMENT 'Role assignments changed for a principal (roleAssignment / updateRoleAssignment endpoints). MITRE T1098, TA0004 Privilege Escalation. Use for: role changes, who changed a role, role assignment, permission role modified, entitlement grants.'
RETURN
  SELECT
    a.event_time,
    a.action_name,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    COALESCE(a.request_params['targetUserName'], a.request_params['target_user_name']),
    a.source_ip_address,
    a.user_agent,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.event_time BETWEEN start_time AND end_time
    AND (a.request_params['endpoint'] IN ('roleAssignment', 'permissionAssignment')
         OR a.action_name IN ('updateRoleAssignment', 'setRoleAssignment'));

-- --------------------------------------------------------------------------
-- Password changed. Port of behavioral/user_password_changed.py.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_user_password_changed(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time      TIMESTAMP COMMENT 'When the password changed (UTC)',
  status          STRING    COMMENT 'Success or Failure',
  actor           STRING    COMMENT 'Identity that made the change',
  target_user     STRING    COMMENT 'Account whose password changed',
  password_source STRING    COMMENT 'How it was set (self-service vs admin reset)',
  source_ip       STRING    COMMENT 'IP the request came from',
  user_agent      STRING    COMMENT 'Client used',
  audit_level     STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL'
)
COMMENT 'Passwords changed (changePassword). MITRE T1098. An admin changing ANOTHER user account password is account takeover; compare actor to target_user. Use for: password changes, who reset a password, changePassword, credential changes, password resets.'
RETURN
  SELECT
    a.event_time,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    a.request_params['targetUserId'],
    a.request_params['newPasswordSource'],
    a.source_ip_address,
    a.user_agent,
    a.audit_level
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.action_name = 'changePassword'
    AND a.event_time BETWEEN start_time AND end_time;

-- --------------------------------------------------------------------------
-- MFA key added / removed. Ports of behavioral/mfa_key_added.py and
-- behavioral/mfa_key_deleted.py, combined -- an added key and a removed key are
-- the same investigative question ("did MFA change for this identity?") and
-- Genie picks better from one function than two near-identical ones.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_mfa_key_changes(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time  TIMESTAMP COMMENT 'When the MFA key changed (UTC)',
  action      STRING    COMMENT 'mfaAddKey or mfaDeleteKey',
  status      STRING    COMMENT 'Success or Failure',
  actor       STRING    COMMENT 'Identity whose MFA changed',
  key_id      STRING    COMMENT 'Key identifier (deletes only)',
  source_ip   STRING    COMMENT 'IP the request came from',
  user_agent  STRING    COMMENT 'Client used',
  audit_level STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL'
)
COMMENT 'MFA keys added or removed (mfaAddKey, mfaDeleteKey). MITRE T1556 Modify Authentication Process. Removing MFA weakens an account; ADDING an attacker-controlled key to a compromised account is a persistence mechanism that survives a password reset. Use for: MFA changes, who removed MFA, new MFA device registered, multi-factor authentication changes, mfaAddKey, mfaDeleteKey, authentication weakened.'
RETURN
  SELECT
    a.event_time,
    a.action_name,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    a.request_params['id'],
    a.source_ip_address,
    a.user_agent,
    a.audit_level
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.action_name IN ('mfaAddKey', 'mfaDeleteKey')
    AND a.event_time BETWEEN start_time AND end_time;

-- --------------------------------------------------------------------------
-- Group lifecycle + membership. Ports of behavioral/group_created.py,
-- event-based/group_deleted.py, behavioral/principal_added_to_group.py and
-- event-based/principal_removed_from_group.py -- combined for the same reason as
-- the MFA pair: one investigative question, four near-identical notebooks.
--
-- The source notebooks read the group name from different keys depending on
-- endpoint (targetGroupName / targetGroupId / targetUserName when
-- endpoint is permissionAssignment or roleAssignment). All are COALESCEd.
-- Verified live: createGroup (3), removeGroup (2), addPrincipalsToGroup (1).
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_group_changes(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time   TIMESTAMP COMMENT 'When the change was made (UTC)',
  action       STRING    COMMENT 'createGroup / removeGroup / addPrincipalToGroup / addPrincipalsToGroup / removePrincipalFromGroup',
  change_kind  STRING    COMMENT 'GROUP_LIFECYCLE or MEMBERSHIP',
  status       STRING    COMMENT 'Success or Failure',
  actor        STRING    COMMENT 'Identity that made the change',
  group_name   STRING    COMMENT 'Group affected',
  target_user  STRING    COMMENT 'Principal added or removed (membership changes)',
  source_ip    STRING    COMMENT 'IP the request came from',
  user_agent   STRING    COMMENT 'Client used',
  audit_level  STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL',
  request_params MAP<STRING, STRING> COMMENT 'Raw payload, for evidence'
)
COMMENT 'Group creation, deletion and membership changes (createGroup, removeGroup, addPrincipalToGroup, addPrincipalsToGroup, removePrincipalFromGroup). MITRE T1098 Account Manipulation. Groups carry entitlements and UC grants, so adding a principal to the right group is privilege escalation without ever touching an admin flag -- cross-check group_name against your admin and data-access groups. Use for: group changes, who was added to a group, group membership, new groups created, deleted groups, who joined an admin group, addPrincipalToGroup, group audit.'
RETURN
  SELECT
    a.event_time,
    a.action_name,
    CASE WHEN a.action_name IN ('createGroup','removeGroup')
         THEN 'GROUP_LIFECYCLE' ELSE 'MEMBERSHIP' END,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    COALESCE(a.request_params['targetGroupName'],
             a.request_params['target_group_name'],
             a.request_params['targetGroupId']),
    COALESCE(a.request_params['targetUserName'],
             a.request_params['target_user_name'],
             a.request_params['principals']),
    a.source_ip_address,
    a.user_agent,
    a.audit_level,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.action_name IN ('createGroup', 'removeGroup', 'addPrincipalToGroup',
                          'addPrincipalsToGroup', 'removePrincipalFromGroup')
    AND a.event_time BETWEEN start_time AND end_time;

-- --------------------------------------------------------------------------
-- Non-SSO login. Port of behavioral/non_sso_login_detected.py.
--
-- The notebook keeps SUCCESSFUL logins whose authentication_method is NOT
-- BROWSER_BYO_IDP_SAML -- i.e. an identity that bypassed the configured IdP.
-- Verified live: samlLogin (339) and tokenLogin (6.1M) both occur. tokenLogin
-- dominates by volume, which is why the notebook's action list matters: it does
-- NOT include tokenLogin, so API token traffic does not drown the signal.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_non_sso_login(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time   TIMESTAMP COMMENT 'When the login happened (UTC)',
  action       STRING    COMMENT 'login / certLogin / jwtLogin / mfaLogin / samlLogin / passwordVerifyAuthentication',
  actor        STRING    COMMENT 'Identity that logged in',
  auth_method  STRING    COMMENT 'Authentication method used -- anything but BROWSER_BYO_IDP_SAML bypassed your IdP',
  workspace_id STRING    COMMENT 'Workspace logged into',
  source_ip    STRING    COMMENT 'IP the login came from',
  user_agent   STRING    COMMENT 'Client used',
  audit_level  STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL'
)
COMMENT 'Successful logins that did NOT use the configured SAML IdP (authentication_method is not BROWSER_BYO_IDP_SAML). MITRE T1078 Valid Accounts. These bypass IdP-enforced MFA and conditional access, so they are the logins your identity provider never saw. Use for: non-SSO logins, logins that bypassed SSO, password logins, who logged in without SSO, SSO bypass, authentication method anomalies, local logins.'
RETURN
  SELECT
    a.event_time,
    a.action_name,
    a.user_identity.email,
    a.request_params['authentication_method'],
    CAST(a.workspace_id AS STRING),
    a.source_ip_address,
    a.user_agent,
    a.audit_level
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.action_name IN ('login', 'certLogin', 'jwtLogin', 'mfaLogin',
                          'passwordVerifyAuthentication', 'samlLogin')
    AND COALESCE(a.request_params['authentication_method'], '') <> 'BROWSER_BYO_IDP_SAML'
    AND a.response.status_code = 200
    AND a.event_time BETWEEN start_time AND end_time;

-- --------------------------------------------------------------------------
-- Databricks employee logon. Port of event-based/databricks_employee_logon.py.
-- Keyed on authentication_method = GENIE_AUTH (the Databricks support-access
-- path), WORKSPACE_LEVEL, successful only.
--
-- Not inherently suspicious -- it is how Databricks support assists you, gated
-- by customerApprovedWSLoginExpirationTime. It matters because it should
-- CORRELATE with an open support ticket. Pair with
-- detect_config_changes_high_priority, which surfaces changes to that approval
-- window.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_databricks_employee_logon(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time   TIMESTAMP COMMENT 'When the logon happened (UTC)',
  action       STRING    COMMENT 'Audit action name',
  actor        STRING    COMMENT 'Databricks employee identity',
  auth_method  STRING    COMMENT 'GENIE_AUTH -- the support-access path',
  workspace_id STRING    COMMENT 'Workspace accessed',
  source_ip    STRING    COMMENT 'IP the logon came from',
  user_agent   STRING    COMMENT 'Client used'
)
COMMENT 'Databricks employee (support) logons into your workspace via GENIE_AUTH. Expected during an open support engagement and gated by the customer-approved access window; unexplained occurrences should be reconciled against your support tickets. Use for: Databricks employee access, support logins, did Databricks staff access our workspace, GENIE_AUTH, vendor access, third-party access to our workspace.'
RETURN
  SELECT
    a.event_time,
    a.action_name,
    a.user_identity.email,
    a.request_params['authentication_method'],
    CAST(a.workspace_id AS STRING),
    a.source_ip_address,
    a.user_agent
  FROM system.access.audit AS a
  WHERE a.service_name = 'accounts'
    AND a.action_name IN ('login', 'certLogin', 'jwtLogin', 'mfaLogin',
                          'passwordVerifyAuthentication', 'samlLogin')
    AND a.request_params['authentication_method'] = 'GENIE_AUTH'
    AND a.response.status_code = 200
    AND a.audit_level = 'WORKSPACE_LEVEL'
    AND a.event_time BETWEEN start_time AND end_time;

-- --------------------------------------------------------------------------
-- SSO configuration changed. Port of event-based/sso_config_changed.py.
-- --------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ${CATALOG}.${SCHEMA}.detect_sso_config_changed(
  start_time TIMESTAMP COMMENT 'Start of the search window (inclusive)',
  end_time   TIMESTAMP COMMENT 'End of the search window (inclusive)'
)
RETURNS TABLE (
  event_time  TIMESTAMP COMMENT 'When the change was made (UTC)',
  action      STRING    COMMENT 'Audit action name',
  status      STRING    COMMENT 'Success or Failure',
  actor       STRING    COMMENT 'Identity that made the change',
  source_ip   STRING    COMMENT 'IP the request came from',
  user_agent  STRING    COMMENT 'Client used',
  audit_level STRING    COMMENT 'ACCOUNT_LEVEL or WORKSPACE_LEVEL',
  request_params MAP<STRING, STRING> COMMENT 'What changed in the SSO/IdP configuration'
)
COMMENT 'Single sign-on / identity provider configuration changed. MITRE T1556 Modify Authentication Process, T1484 Domain or Tenant Policy Modification. Repointing SSO at an attacker-controlled IdP, or disabling it, subverts authentication for every user at once -- among the highest-impact changes in the account. Use for: SSO changes, identity provider changed, SAML configuration, who changed SSO settings, authentication configuration changes, IdP modified.'
RETURN
  SELECT
    a.event_time,
    a.action_name,
    CASE WHEN a.response.status_code = 200 THEN 'Success' ELSE 'Failure' END,
    a.user_identity.email,
    a.source_ip_address,
    a.user_agent,
    a.audit_level,
    a.request_params
  FROM system.access.audit AS a
  WHERE a.event_time BETWEEN start_time AND end_time
    AND (
      lower(a.action_name) LIKE '%sso%'
      OR lower(a.action_name) LIKE '%samlconfig%'
      OR lower(a.action_name) LIKE '%identityprovider%'
      OR (a.action_name = 'workspaceConfEdit'
          AND lower(COALESCE(a.request_params['workspaceConfKeys'], '')) LIKE '%sso%')
    );
