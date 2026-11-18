-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Hunt 5: a new SP user agent soon after a secret read
-- MAGIC
-- MAGIC **Blog stage:** 4 (pivot to a service principal). This is the other way to link the two
-- MAGIC identities: by time, not by IP.
-- MAGIC
-- MAGIC **What it looks for:** a service principal (SP) that uses a user agent for the first time (not
-- MAGIC seen for this SP in the 14 days before), less than 2 hours after another identity read a
-- MAGIC secret.
-- MAGIC
-- MAGIC **Why it matters:** an attacker can read the SP secret from one IP and use it from another, so
-- MAGIC the IP join of hunt 4 finds nothing. The tool still changes: SPs run the same job code every
-- MAGIC day, so a new client (here `curl`) is rare. The time link is weaker than the IP link: many
-- MAGIC people read secrets every hour. So the query also looks at the key names: when somebody read a
-- MAGIC key whose name contains the SP name, that SP comes first in the result.
-- MAGIC
-- MAGIC **Expected result:** `sp-etl-prod` with `curl/8.7.1`, one hour after
-- MAGIC `maria.lopez@corp.example` read `etl-prod/sp-etl-prod-client-secret`. The stolen credential of
-- MAGIC `sp-reporting` (a blocked replay, scenario S2) also shows here, with no key that names it.
-- MAGIC
-- MAGIC Set the `catalog` and `schema` widgets to the demo schema.

-- COMMAND ----------

-- MAGIC %python
-- MAGIC # The queries read the catalog and schema of the demo from these widgets.
-- MAGIC dbutils.widgets.text("catalog", "", "Catalog")
-- MAGIC dbutils.widgets.text("schema", "databricks_audit_demo", "Schema")

-- COMMAND ----------

-- New SP user agents in the last 24 hours of data, with the secret reads by other identities in the
-- 2 hours before. No IP join.
-- EXPECT: sp-etl-prod / curl
WITH ev AS (
  FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`')
  |> WHERE event_time >= (SELECT max(event_time) FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`'))
                         - INTERVAL 15 DAYS
  |> SELECT event_time, user_identity.email AS actor, user_agent, action_name, source_ip_address AS src_ip,
            request_params.scope AS scope, request_params.key AS key, response.status_code AS status,
            CASE WHEN user_identity.email RLIKE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                   OR identity_metadata.acting_resource_type ILIKE '%service principal%'
                 THEN 'sp' ELSE 'user' END AS actor_kind
),
win AS (SELECT max(event_time) - INTERVAL 24 HOURS AS start FROM ev),
sp_new_ua AS (
  -- first use of each (SP, user agent) pair; the pair is new when it starts inside the window
  FROM ev
  |> WHERE actor_kind = 'sp' AND user_agent IS NOT NULL
  |> AGGREGATE min(event_time) AS first_seen, min_by(action_name, event_time) AS first_action,
               min_by(src_ip, event_time) AS first_ip
     GROUP BY actor, user_agent
  |> WHERE first_seen >= (SELECT start FROM win)
),
reads AS (
  FROM ev
  |> WHERE action_name = 'getSecret' AND status = 200
     AND event_time >= (SELECT start FROM win) - INTERVAL 2 HOURS
)
FROM sp_new_ua AS s
|> JOIN reads AS r
     ON r.actor <> s.actor AND r.event_time < s.first_seen AND r.event_time >= s.first_seen - INTERVAL 2 HOURS
|> LEFT JOIN IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`principals`') AS p ON p.email = s.actor
|> AGGREGATE count(*) AS reads_before, count(DISTINCT r.actor) AS readers,
             collect_set(CASE WHEN r.key ILIKE '%' || p.display_name || '%'
                              THEN concat(r.actor, ' read ', r.scope, '/', r.key) END) AS reads_naming_sp,
             max(r.event_time) AS last_read
   GROUP BY s.actor AS sp, p.display_name AS sp_name, s.user_agent AS new_user_agent,
            s.first_seen AS first_seen, s.first_action AS first_action, s.first_ip AS first_ip
|> SELECT concat(sp_name, ' / ', new_user_agent) AS finding, *
|> ORDER BY size(reads_naming_sp) DESC, first_seen
|> LIMIT 20
