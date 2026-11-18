CREATE OR REPLACE VIEW `{{catalog}}`.`{{schema}}`.`demo_signals` AS
SELECT
  regexp_extract(s.rule_name, '([^.]+)$', 1) AS rule,
  get_json_object(s.context, '$.stage') AS stage,
  get_json_object(s.context, '$.actor') AS actor,
  get_json_object(s.context, '$.actor_kind') AS actor_kind,
  get_json_object(s.context, '$.src_ip') AS src_ip,
  get_json_object(s.context, '$.token_id') AS token_id,
  get_json_object(s.context, '$.session_id') AS session_id,
  s.event_time,
  s.created_at,
  s.summary,
  p.display_name AS actor_name
FROM `{{catalog}}`.`__lakewatch`.`signals` s
LEFT JOIN `{{catalog}}`.`{{schema}}`.`principals` p
  ON p.email = get_json_object(s.context, '$.actor')
WHERE startswith(s.rule_name, '{{catalog}}.{{schema}}.')
