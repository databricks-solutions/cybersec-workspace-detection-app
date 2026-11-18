-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Hunt 1: discovery bursts
-- MAGIC
-- MAGIC **Blog stage:** 2 (discovery).
-- MAGIC
-- MAGIC **What it looks for:** one identity that calls many different "list" APIs in the same minute:
-- MAGIC secret scopes, catalogs, schemas, external locations, storage credentials, repos, and account
-- MAGIC configurations.
-- MAGIC
-- MAGIC **Why it matters:** an attacker with a stolen token does not know the workspace. The first thing
-- MAGIC they do is to look around, fast and with a script. People and jobs call one or two of these APIs
-- MAGIC at a time. A burst of three or more different ones in one minute is rare.
-- MAGIC
-- MAGIC **Expected result:** `maria.lopez@corp.example` calls six different discovery APIs in 35 seconds
-- MAGIC from an attacker IP.
-- MAGIC
-- MAGIC The time window is the last 24 hours of the data (not of the clock), so the hunt works at any time
-- MAGIC after a reset. Set the `catalog` and `schema` widgets to the demo schema.

-- COMMAND ----------

-- MAGIC %python
-- MAGIC # The queries read the catalog and schema of the demo from these widgets.
-- MAGIC dbutils.widgets.text("catalog", "", "Catalog")
-- MAGIC dbutils.widgets.text("schema", "databricks_audit_demo", "Schema")

-- COMMAND ----------

-- Discovery calls per identity per minute. Keep the minutes with 3 or more different actions.
-- EXPECT: maria.lopez
FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`')
|> WHERE event_time >= (SELECT max(event_time) FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`'))
                       - INTERVAL 24 HOURS
   AND action_name IN ('listScopes', 'listSecrets', 'listMetastores', 'listCatalogs', 'listSchemas',
                       'listExternalLocations', 'listStorageCredentials', 'listRepos',
                       'listWorkspaceConfigurations', 'listNetworkConfigurations', 'listStorageConfigurations')
|> AGGREGATE count(*) AS calls, count(DISTINCT action_name) AS distinct_actions,
             min(event_time) AS first_call, max(event_time) AS last_call,
             collect_set(action_name) AS actions, collect_set(source_ip_address) AS source_ips,
             collect_set(user_agent) AS user_agents
   GROUP BY user_identity.email AS actor, date_trunc('MINUTE', event_time) AS minute
|> WHERE distinct_actions >= 3
|> AS b
|> LEFT JOIN IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`principals`') AS p ON p.email = b.actor
|> SELECT b.actor, p.display_name, p.kind, b.minute, b.calls, b.distinct_actions, b.first_call, b.last_call,
          b.actions, b.source_ips, b.user_agents
|> ORDER BY distinct_actions DESC, calls DESC
|> LIMIT 20
