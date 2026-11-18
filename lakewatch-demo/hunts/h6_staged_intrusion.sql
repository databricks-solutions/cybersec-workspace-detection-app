-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Hunt 6: the staged intrusion, in order (`MATCH_RECOGNIZE`)
-- MAGIC
-- MAGIC **Blog stages:** 1 to 5, as one ordered sequence.
-- MAGIC
-- MAGIC **What it looks for:** the stages of the attack in the right order, not one event at a time.
-- MAGIC
-- MAGIC - **6a, one identity** (stages 1 to 3). First, a PAT login from a new IP: the token did not
-- MAGIC   use this IP in the 14 days before. Then discovery calls of 5 or more different kinds.
-- MAGIC   Then `listScopes`, and then the harvest: `listSecrets` and `getSecret` in any order (all lists
-- MAGIC   first, or one scope at a time, with more `listScopes` or discovery calls between them). The
-- MAGIC   identity must read secrets in 2 or more scopes, and at least one read must succeed. All of it
-- MAGIC   happens within 30 minutes.
-- MAGIC - **6b, two identities on one IP** (stages 3 to 5): secret reads, then a login of a
-- MAGIC   *different* identity that is a service principal (SP), then privileged actions of that SP
-- MAGIC   (create a function, add a member to a group, create a token, export a file).
-- MAGIC
-- MAGIC **Why it matters:** each step alone is common. People list catalogs, jobs read secrets, admins
-- MAGIC add group members. The order is what makes it an attack. `MATCH_RECOGNIZE` matches a pattern
-- MAGIC of steps over the rows of each actor (6a) or each IP (6b), sorted by time.
-- MAGIC
-- MAGIC **Expected result:** 6a returns `maria.lopez@corp.example`, 6b returns `maria.lopez` and
-- MAGIC `sp-etl-prod` on the same attacker IP, with the scopes and keys that were read.
-- MAGIC
-- MAGIC This is a hunt only: the Lakewatch rule API does not accept `MATCH_RECOGNIZE`. The rules
-- MAGIC `ada_secret_harvest_chain` and `ada_identity_pivot_chain` find the same thing with joins.
-- MAGIC Set the `catalog` and `schema` widgets to the demo schema.

-- COMMAND ----------

-- MAGIC %python
-- MAGIC # The queries read the catalog and schema of the demo from these widgets.
-- MAGIC dbutils.widgets.text("catalog", "", "Catalog")
-- MAGIC dbutils.widgets.text("schema", "databricks_audit_demo", "Schema")

-- COMMAND ----------

-- 6a. One identity: new-IP PAT login -> discovery{5,} -> listScopes -> harvest+, all in 30 min.
--     The harvest is any mix of listScopes, listSecrets, getSecret and more discovery calls. So the order of
--     the secret calls does not matter: all lists first and then all reads, or list and read one scope at a
--     time, or list the scopes again in the middle. listSecrets is not a discovery call here, it is part of
--     the harvest. The outer WHERE keeps a match only when it has 5 or more DIFFERENT discovery actions
--     (5 x listCatalogs is not enough), at least one successful read (status 200), and reads in 2 or more
--     scopes. The new-IP flag is computed before the match (14 days of logins per token and IP). Only the
--     rows of the pattern stay in the input, because the rows of a match must be next to each other.
-- EXPECT: maria.lopez
WITH ev AS (
  SELECT event_time, user_identity.email AS actor, source_ip_address AS src_ip, user_agent, action_name,
         request_params.authenticationMethod AS auth_method, request_params.tokenId AS token_id,
         request_params.scope AS scope, request_params.key AS key, response.status_code AS status
  FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`')
  WHERE event_time >= (SELECT max(event_time) FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`'))
                      - INTERVAL 15 DAYS
),
flagged AS (
  SELECT *,
         action_name = 'tokenLogin' AND auth_method = 'API_EXT_PAT_TOKEN' AND status = 200
           AND coalesce(lag(event_time) OVER (PARTITION BY action_name, token_id, src_ip ORDER BY event_time)
                          < event_time - INTERVAL 14 DAYS, true) AS new_ip_login
  FROM ev
),
steps AS (
  SELECT * FROM flagged
  WHERE event_time >= (SELECT max(event_time) FROM ev) - INTERVAL 24 HOURS
    AND (new_ip_login
         OR action_name IN ('listScopes', 'listSecrets', 'listMetastores', 'listCatalogs', 'listSchemas',
                            'listExternalLocations', 'listStorageCredentials', 'listRepos',
                            'listWorkspaceConfigurations', 'listNetworkConfigurations',
                            'listStorageConfigurations', 'getSecret'))
)
SELECT m.actor, p.display_name, m.src_ip, m.token_id, m.access_at, m.discovery_at, m.discovery_calls,
       m.discovery_actions, m.list_scopes_at, m.list_secrets_at, m.first_read_at, m.last_read_at,
       m.scopes_listed, m.scopes_read, m.secrets_read, m.denied_reads
FROM steps
MATCH_RECOGNIZE (
  PARTITION BY actor
  ORDER BY event_time
  MEASURES FIRST(auth_new_ip.event_time) AS access_at,
           FIRST(auth_new_ip.src_ip) AS src_ip,
           FIRST(auth_new_ip.token_id) AS token_id,
           FIRST(discovery.event_time) AS discovery_at,
           COUNT(discovery.event_time) AS discovery_calls,
           array_sort(collect_set(discovery.action_name)) AS discovery_actions,
           FIRST(list_scopes.event_time) AS list_scopes_at,
           FIRST(list_secrets.event_time) AS list_secrets_at,
           FIRST(get_secret.event_time) AS first_read_at,
           LAST(get_secret.event_time) AS last_read_at,
           array_sort(collect_set(list_secrets.scope)) AS scopes_listed,
           array_sort(collect_set(get_secret.scope)) AS scopes_read,
           array_sort(collect_set(concat(get_secret.scope, '/', get_secret.key))) AS secrets_read,
           count_if(get_secret.status = 200) AS good_reads,
           count_if(get_secret.status <> 200) AS denied_reads
  ONE ROW PER MATCH
  AFTER MATCH SKIP PAST LAST ROW
  PATTERN (auth_new_ip discovery{5,} list_scopes (list_scopes | list_secrets | get_secret | more_discovery)+)
  DEFINE auth_new_ip    AS new_ip_login,
         discovery      AS action_name IN ('listScopes', 'listMetastores', 'listCatalogs', 'listSchemas',
                                           'listExternalLocations', 'listStorageCredentials', 'listRepos',
                                           'listWorkspaceConfigurations', 'listNetworkConfigurations',
                                           'listStorageConfigurations')
                           AND event_time <= FIRST(auth_new_ip.event_time) + INTERVAL 30 MINUTES,
         list_scopes    AS action_name = 'listScopes'
                           AND event_time <= FIRST(auth_new_ip.event_time) + INTERVAL 30 MINUTES,
         list_secrets   AS action_name = 'listSecrets'
                           AND event_time <= FIRST(auth_new_ip.event_time) + INTERVAL 30 MINUTES,
         get_secret     AS action_name = 'getSecret'
                           AND event_time <= FIRST(auth_new_ip.event_time) + INTERVAL 30 MINUTES,
         more_discovery AS action_name IN ('listMetastores', 'listCatalogs', 'listSchemas', 'listExternalLocations',
                                           'listStorageCredentials', 'listRepos', 'listWorkspaceConfigurations',
                                           'listNetworkConfigurations', 'listStorageConfigurations')
                           AND event_time <= FIRST(auth_new_ip.event_time) + INTERVAL 30 MINUTES
) AS m
LEFT JOIN IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`principals`') AS p ON p.email = m.actor
WHERE size(m.discovery_actions) >= 5 AND m.good_reads >= 1 AND size(m.scopes_read) >= 2
ORDER BY m.access_at

-- COMMAND ----------

-- 6b. Two identities on one IP: getSecret+ -> other*? -> SP login (a different actor) -> SP privileged
--     actions+. The input keeps only secret reads, logins and the privileged actions, so the SP's list calls
--     do not break the run. `other` has its own DEFINE: an undefined `other` matches any row and takes
--     the last secret read away from get_secret+.
-- EXPECT: -> sp-etl-prod
WITH ev AS (
  SELECT event_time, user_identity.email AS actor, source_ip_address AS src_ip, user_agent, action_name,
         request_params.scope AS scope, request_params.key AS key, response.status_code AS status,
         CASE WHEN user_identity.email RLIKE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                OR identity_metadata.acting_resource_type ILIKE '%service principal%'
              THEN 'sp' ELSE 'user' END AS actor_kind
  FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`')
  WHERE event_time >= (SELECT max(event_time) FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`'))
                      - INTERVAL 24 HOURS
    AND source_ip_address IS NOT NULL
    AND action_name IN ('getSecret', 'tokenLogin', 'oidcTokenAuthorization',
                        'createFunction', 'addPrincipalToGroup', 'generateDbToken', 'workspaceExport')
)
SELECT concat(pr.display_name, ' -> ', ps.display_name) AS chain, m.src_ip, m.readers[0] AS reader, pr.display_name AS reader_name, m.first_read_at, m.last_read_at,
       m.secrets_read, m.denied_reads, m.sp, ps.display_name AS sp_name, m.sp_auth_at, m.sp_user_agent,
       m.first_priv_at, m.last_priv_at, m.sp_actions
FROM ev
MATCH_RECOGNIZE (
  PARTITION BY src_ip
  ORDER BY event_time
  MEASURES collect_set(get_secret.actor) AS readers,
           FIRST(get_secret.event_time) AS first_read_at,
           LAST(get_secret.event_time) AS last_read_at,
           collect_set(concat(get_secret.scope, '/', get_secret.key)) AS secrets_read,
           count_if(get_secret.status <> 200) AS denied_reads,
           FIRST(sp_auth.actor) AS sp,
           FIRST(sp_auth.event_time) AS sp_auth_at,
           FIRST(sp_auth.user_agent) AS sp_user_agent,
           FIRST(sp_priv.event_time) AS first_priv_at,
           LAST(sp_priv.event_time) AS last_priv_at,
           collect_list(sp_priv.action_name) AS sp_actions
  ONE ROW PER MATCH
  AFTER MATCH SKIP PAST LAST ROW
  PATTERN (get_secret+ other*? sp_auth sp_priv+)
  DEFINE get_secret AS action_name = 'getSecret',
         other      AS action_name <> 'getSecret'
                       AND NOT (actor_kind = 'sp' AND action_name IN ('tokenLogin', 'oidcTokenAuthorization')),
         sp_auth    AS action_name IN ('tokenLogin', 'oidcTokenAuthorization') AND status = 200
                       AND actor_kind = 'sp' AND actor <> LAST(get_secret.actor)
                       AND event_time <= LAST(get_secret.event_time) + INTERVAL 6 HOURS,
         sp_priv    AS action_name IN ('createFunction', 'addPrincipalToGroup', 'generateDbToken', 'workspaceExport')
                       AND actor = FIRST(sp_auth.actor)
) AS m
LEFT JOIN IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`principals`') AS pr ON pr.email = m.readers[0]
LEFT JOIN IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`principals`') AS ps ON ps.email = m.sp
ORDER BY m.first_read_at
