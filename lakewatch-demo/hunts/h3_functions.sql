-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Hunt 3: new and short-lived functions
-- MAGIC
-- MAGIC **Blog stages:** 4 (execution) and 6 (clean up).
-- MAGIC
-- MAGIC **What it looks for:** (1) Unity Catalog functions created by an identity that did not create
-- MAGIC any function in the 14 days before, and (2) functions that somebody deletes less than 24 hours
-- MAGIC after they were created.
-- MAGIC
-- MAGIC **Why it matters:** a function written in Python runs its code on the cluster or
-- MAGIC warehouse of whoever calls it. An attacker can
-- MAGIC hide a command runner (`subprocess`, `os.popen`) or a download (`requests.get`) in a "utility"
-- MAGIC function, use it, and delete it to hide the trace. Functions in normal work live for weeks.
-- MAGIC
-- MAGIC **Expected result:** `sp-etl-prod` creates three functions in `ops_tools.helpers` from an attacker
-- MAGIC IP. The bodies call `subprocess`, `requests` and `os.popen`. It deletes
-- MAGIC `ops_tools.helpers.util_parse_json` 25 minutes after it created it.
-- MAGIC
-- MAGIC `createFunction` and `deleteFunction` are account-level rows: the workspace is in
-- MAGIC `request_params.workspace_id`, not in `workspace_id`. Set the `catalog` and `schema` widgets to the
-- MAGIC demo schema.

-- COMMAND ----------

-- MAGIC %python
-- MAGIC # The queries read the catalog and schema of the demo from these widgets.
-- MAGIC dbutils.widgets.text("catalog", "", "Catalog")
-- MAGIC dbutils.widgets.text("schema", "databricks_audit_demo", "Schema")

-- COMMAND ----------

-- 1. First-seen function creators: functions created in the last 24 hours of data by an identity that
--    created no function in the 14 days before that window.
WITH fn AS (
  FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`')
  |> WHERE service_name = 'unityCatalog' AND action_name = 'createFunction' AND response.status_code = 200
  |> SELECT event_time, user_identity.email AS actor, source_ip_address AS src_ip, user_agent,
            request_params.workspace_id AS workspace_id,
            concat_ws('.', get_json_object(request_params.function_info, '$.catalog_name'),
                      get_json_object(request_params.function_info, '$.schema_name'),
                      get_json_object(request_params.function_info, '$.name')) AS function_name,
            get_json_object(request_params.function_info, '$.routine_definition') AS body
),
win AS (
  SELECT max(event_time) - INTERVAL 24 HOURS AS start
  FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`')
),
recent AS (
  FROM fn |> WHERE event_time >= (SELECT start FROM win)
),
baseline AS (
  FROM fn |> WHERE event_time < (SELECT start FROM win) AND event_time >= (SELECT start FROM win) - INTERVAL 14 DAYS
)
FROM recent AS r
|> LEFT ANTI JOIN baseline AS b ON b.actor = r.actor
|> LEFT JOIN IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`principals`') AS p ON p.email = r.actor
|> SELECT r.event_time, r.actor, p.display_name, r.function_name, r.workspace_id, r.src_ip, r.user_agent, r.body
|> ORDER BY event_time
|> LIMIT 20

-- COMMAND ----------

-- 2. Short-lived functions: deleted in the last 24 hours of data, less than 24 hours after creation.
-- EXPECT: sp-etl-prod
WITH created AS (
  FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`')
  |> WHERE service_name = 'unityCatalog' AND action_name = 'createFunction' AND response.status_code = 200
  |> SELECT event_time AS created_at, user_identity.email AS creator, source_ip_address AS src_ip,
            concat_ws('.', get_json_object(request_params.function_info, '$.catalog_name'),
                      get_json_object(request_params.function_info, '$.schema_name'),
                      get_json_object(request_params.function_info, '$.name')) AS function_name
),
deleted AS (
  FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`')
  |> WHERE service_name = 'unityCatalog' AND action_name = 'deleteFunction' AND response.status_code = 200
  |> SELECT event_time AS deleted_at, user_identity.email AS deleter, request_params.full_name_arg AS function_name
)
FROM created AS c
|> JOIN deleted AS d
     ON d.function_name = c.function_name AND d.deleted_at > c.created_at
        AND d.deleted_at <= c.created_at + INTERVAL 24 HOURS
|> WHERE d.deleted_at >= (SELECT max(event_time) FROM IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`audit`'))
                         - INTERVAL 24 HOURS
|> LEFT JOIN IDENTIFIER('`' || :catalog || '`.`' || :schema || '`.`principals`') AS p ON p.email = c.creator
|> SELECT c.function_name, c.creator, p.display_name AS creator_name, d.deleter, c.src_ip,
          c.created_at, d.deleted_at, timestampdiff(MINUTE, c.created_at, d.deleted_at) AS lifetime_minutes
|> ORDER BY lifetime_minutes
|> LIMIT 20
