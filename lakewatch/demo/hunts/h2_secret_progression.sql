-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Hunt 2: secret access progression
-- MAGIC
-- MAGIC **Blog stage:** 3 (secret harvest).
-- MAGIC
-- MAGIC **What it looks for:** an identity that lists the secret scopes, lists the keys in a scope, and
-- MAGIC then reads keys from that same scope, often across several scopes, with some reads denied.
-- MAGIC
-- MAGIC **Why it matters:** jobs read the one secret they need by name. They do not list scopes and keys
-- MAGIC first. "List, then read" over several scopes, with a denied read in the middle, is somebody who
-- MAGIC looks for credentials. The CI service principal lists scopes every night but reads nothing: that is
-- MAGIC the normal contrast in query 1.
-- MAGIC
-- MAGIC **Expected result:** `maria.lopez@corp.example` lists three scopes and reads a key from each of
-- MAGIC them within 3 minutes. The read from `shared-infra` is denied, and then she reads the same key,
-- MAGIC `sp-etl-prod-client-secret`, from `etl-prod`.
-- MAGIC
-- MAGIC Set the `catalog` and `schema` widgets to the demo schema.

-- COMMAND ----------

-- MAGIC %python
-- MAGIC # The queries read the catalog and schema of the demo from these widgets.
-- MAGIC dbutils.widgets.text("catalog", "", "Catalog")
-- MAGIC dbutils.widgets.text("schema", "databricks_audit_demo", "Schema")

-- COMMAND ----------

-- 1. Overview: secret API use per identity in the last 24 hours of data.
FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`')
|> WHERE event_time >= (SELECT max(event_time) FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`'))
                       - INTERVAL 24 HOURS
   AND service_name = 'secrets' AND action_name IN ('listScopes', 'listSecrets', 'getSecret')
|> AGGREGATE count_if(action_name = 'listScopes') AS list_scopes,
             count(DISTINCT CASE WHEN action_name = 'listSecrets' THEN request_params.scope END) AS scopes_listed,
             count(DISTINCT CASE WHEN action_name = 'getSecret' THEN request_params.scope END) AS scopes_read,
             count_if(action_name = 'getSecret') AS reads,
             count_if(action_name = 'getSecret' AND response.status_code <> 200) AS denied_reads
   GROUP BY user_identity.email AS actor
|> WHERE scopes_listed > 0 OR denied_reads > 0
|> AS s
|> LEFT JOIN IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`principals`') AS p ON p.email = s.actor
|> SELECT s.actor, p.display_name, p.kind, s.list_scopes, s.scopes_listed, s.scopes_read, s.reads, s.denied_reads
|> ORDER BY scopes_listed DESC, scopes_read DESC, denied_reads DESC
|> LIMIT 20

-- COMMAND ----------

-- 2. The progression per scope: the identity lists the keys of a scope and reads from the same scope
--    within one hour.
-- EXPECT: maria.lopez
FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`')
|> WHERE event_time >= (SELECT max(event_time) FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`'))
                       - INTERVAL 24 HOURS
   AND service_name = 'secrets' AND action_name IN ('listSecrets', 'getSecret')
|> AGGREGATE min(CASE WHEN action_name = 'listSecrets' THEN event_time END) AS first_listed,
             min(CASE WHEN action_name = 'getSecret' THEN event_time END) AS first_read,
             collect_set(CASE WHEN action_name = 'getSecret' AND response.status_code = 200
                              THEN request_params.key END) AS keys_read,
             collect_set(CASE WHEN action_name = 'getSecret' AND response.status_code <> 200
                              THEN request_params.key END) AS keys_denied,
             collect_set(source_ip_address) AS source_ips
   GROUP BY user_identity.email AS actor, request_params.scope AS scope
|> WHERE first_listed IS NOT NULL AND first_read BETWEEN first_listed AND first_listed + INTERVAL 1 HOUR
|> AS s
|> LEFT JOIN IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`principals`') AS p ON p.email = s.actor
|> SELECT s.actor, p.display_name, s.scope, s.first_listed, s.first_read, s.keys_read, s.keys_denied, s.source_ips
|> ORDER BY first_listed
|> LIMIT 20
