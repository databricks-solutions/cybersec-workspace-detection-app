-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Hunt 4: everyone who used this IP
-- MAGIC
-- MAGIC **Blog stage:** 4 (pivot to a service principal). This is the pivot behind the
-- MAGIC `ada_identity_pivot_chain` alert.
-- MAGIC
-- MAGIC **What it looks for:** source IPs that a person and a service principal (SP) both used in the
-- MAGIC last 24 hours, where somebody read secrets. Then all identities and actions on the top IP.
-- MAGIC
-- MAGIC **Why it matters:** the attacker reads the client secret of an SP with a stolen user token, then
-- MAGIC logs in as the SP from the same machine. One IP that both a user and an SP use is unusual: people
-- MAGIC work from office, VPN or laptop ranges, and SPs run on Databricks clusters or on build
-- MAGIC servers (CI).
-- MAGIC
-- MAGIC **Expected result:** one IP (`203.0.113.x`) that `maria.lopez@corp.example` (secret reads) and
-- MAGIC `sp-etl-prod` (new user agent `curl/8.7.1`, functions, admin group, token, export) both used.
-- MAGIC
-- MAGIC Set the `catalog` and `schema` widgets to the demo schema.

-- COMMAND ----------

-- MAGIC %python
-- MAGIC # The queries read the catalog and schema of the demo from these widgets.
-- MAGIC dbutils.widgets.text("catalog", "", "Catalog")
-- MAGIC dbutils.widgets.text("schema", "databricks_audit_demo", "Schema")

-- COMMAND ----------

-- 1. IPs that a user and an SP both used in the last 24 hours of data, the ones with secret reads first.
FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`')
|> WHERE event_time >= (SELECT max(event_time) FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`'))
                       - INTERVAL 24 HOURS
   AND source_ip_address IS NOT NULL
|> EXTEND CASE WHEN user_identity.email RLIKE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                 OR identity_metadata.acting_resource_type ILIKE '%service principal%'
               THEN 'sp' ELSE 'user' END AS actor_kind
|> AGGREGATE count(DISTINCT CASE WHEN actor_kind = 'user' THEN user_identity.email END) AS users,
             count(DISTINCT CASE WHEN actor_kind = 'sp' THEN user_identity.email END) AS sps,
             count_if(action_name = 'getSecret') AS secret_reads, count(*) AS events,
             min(event_time) AS first_seen, max(event_time) AS last_seen
   GROUP BY source_ip_address AS src_ip
|> WHERE users >= 1 AND sps >= 1
|> ORDER BY secret_reads DESC, events DESC
|> LIMIT 20

-- COMMAND ----------

-- 2. Everyone who used the top IP of query 1 (a user read secrets there and an SP also used it):
--    one row per identity, with what it did and with which user agent.
-- EXPECT: sp-etl-prod
WITH recent AS (
  FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`')
  |> WHERE event_time >= (SELECT max(event_time) FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`'))
                         - INTERVAL 24 HOURS
     AND source_ip_address IS NOT NULL
  |> EXTEND CASE WHEN user_identity.email RLIKE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                   OR identity_metadata.acting_resource_type ILIKE '%service principal%'
                 THEN 'sp' ELSE 'user' END AS actor_kind
),
pivot_ip AS (
  FROM recent
  |> AGGREGATE count_if(actor_kind = 'user' AND action_name = 'getSecret' AND response.status_code = 200) AS user_reads,
               count(DISTINCT CASE WHEN actor_kind = 'sp' THEN user_identity.email END) AS sps
     GROUP BY source_ip_address AS src_ip
  |> WHERE user_reads > 0 AND sps > 0
  |> ORDER BY user_reads DESC
  |> LIMIT 1
)
FROM recent AS e
|> JOIN pivot_ip AS ip ON ip.src_ip = e.source_ip_address
|> AGGREGATE min(e.event_time) AS first_seen, max(e.event_time) AS last_seen, count(*) AS events,
             collect_set(e.action_name) AS actions, collect_set(e.user_agent) AS user_agents
   GROUP BY ip.src_ip AS src_ip, e.user_identity.email AS actor, e.actor_kind AS actor_kind
|> AS a
|> LEFT JOIN IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`principals`') AS p ON p.email = a.actor
|> SELECT a.src_ip, a.actor, p.display_name, a.actor_kind, a.first_seen, a.last_seen, a.events, a.actions, a.user_agents
|> ORDER BY first_seen
