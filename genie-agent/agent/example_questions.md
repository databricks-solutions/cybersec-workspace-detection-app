# Example questions — seed the agent's Example SQL Queries

Per the Genie Agents docs, Example SQL Queries are "SQL queries that serve as
reference answers for common questions." Add these so the agent learns the
mapping from analyst phrasing to the right trusted function.

These are drawn from a **real customer incident** — a compromise where the
attacker modified the IP allow list and the customer asked for "a detailed
changelog (including actual change diff) of configuration in the Databricks
panel/service itself." Phrase examples the way analysts actually ask under
pressure, not the way a schema is documented.

Replace `<catalog>` with your catalog name.

---

## Incident response — IP access lists

**"Who changed our IP allow list, and what did they change it to?"**
```sql
SELECT * FROM <catalog>.security_detections.detect_ip_access_list_changes(
  TIMESTAMP'2026-08-01 00:00:00', current_timestamp())
ORDER BY event_time DESC
```

**"Show me the full allow-list changelog with before and after values"**
```sql
SELECT event_time, actor, action, list_label, list_type,
       previous_value, new_value, source_ip, user_agent
FROM <catalog>.security_detections.detect_ip_access_list_changes(
  TIMESTAMP'2026-08-01 00:00:00', current_timestamp())
ORDER BY list_label, event_time
```

**"Were there failed attempts to change the IP allow list?"**
```sql
SELECT * FROM <catalog>.security_detections.detect_ip_acl_validation_failures(
  TIMESTAMP'2026-08-01 00:00:00', current_timestamp())
ORDER BY event_time DESC
```

**"Did the denial rate drop after the allow list was widened?"**
```sql
-- Corroborates WHEN a widening took effect: denials should fall at that moment.
SELECT date_trunc('HOUR', event_time) AS hour, count(*) AS denials
FROM <catalog>.security_detections.detect_denied_ip_logon_attempts(
  TIMESTAMP'2026-08-01 00:00:00', current_timestamp())
GROUP BY 1 ORDER BY 1
```

## Incident response — configuration and evasion

**"What security settings changed in the last two weeks?"**
```sql
SELECT * FROM <catalog>.security_detections.detect_config_changes_high_priority(
  current_timestamp() - INTERVAL 14 DAYS, current_timestamp())
ORDER BY event_time DESC
```

**"Did anyone turn off audit logging?"**
```sql
-- Run this FIRST in any investigation. If it fires, every detection after that
-- timestamp has a visibility gap.
SELECT * FROM <catalog>.security_detections.detect_config_changes_high_priority(
  current_timestamp() - INTERVAL 90 DAYS, current_timestamp())
WHERE severity LIKE 'CRITICAL%'
ORDER BY event_time
```

**"What changed at the account level?"**
```sql
SELECT * FROM <catalog>.security_detections.detect_config_changes_account_level(
  current_timestamp() - INTERVAL 30 DAYS, current_timestamp())
ORDER BY event_time DESC
```

## Pivots — the questions that follow a finding

**"What else did this user do around that time?"**
```sql
SELECT event_time, service_name, action_name, source_ip_address, user_agent,
       response.status_code
FROM system.access.audit
WHERE user_identity.email = 'suspect@example.com'
  AND event_time BETWEEN TIMESTAMP'2026-08-15 00:00:00'
                     AND TIMESTAMP'2026-08-16 00:00:00'
ORDER BY event_time
```

**"What else came from that IP?"**
```sql
SELECT event_time, user_identity.email AS actor, service_name, action_name,
       user_agent, response.status_code
FROM system.access.audit
WHERE source_ip_address = '203.0.113.42'
  AND event_time >= current_timestamp() - INTERVAL 30 DAYS
ORDER BY event_time
```

**"Which config changes came from automation vs the console?"**
```sql
-- user_agent separates Terraform/CLI/SDK from console clicks. A change from an
-- unexpected client is a signal on its own.
SELECT user_agent, count(*) AS changes, min(event_time) AS first_seen,
       max(event_time) AS last_seen
FROM <catalog>.security_detections.detect_config_changes_high_priority(
  current_timestamp() - INTERVAL 30 DAYS, current_timestamp())
GROUP BY user_agent ORDER BY changes DESC
```

## Discovery — when an expected event is missing

**"What audit actions actually exist in my environment?"**
```sql
-- Run before concluding "it didn't happen". Action names vary by
-- configuration and feature enablement.
SELECT audit_level, service_name, action_name, count(*) AS events
FROM system.access.audit
WHERE event_time >= current_timestamp() - INTERVAL 30 DAYS
GROUP BY 1,2,3 ORDER BY events DESC
```

**"Which IP-related actions exist?"**
```sql
SELECT audit_level, service_name, action_name, count(*) AS events
FROM system.access.audit
WHERE event_time >= current_timestamp() - INTERVAL 30 DAYS
  AND lower(action_name) LIKE '%ip%'
GROUP BY 1,2,3 ORDER BY events DESC
```

---

## A note on benchmarks

The docs describe **Benchmarks** as test questions for evaluating accuracy, "not
used for learning context." Good benchmark candidates here are the questions
where a wrong query returns **zero rows** rather than an error — those are the
dangerous ones, because empty output reads as "nothing happened":

- "Who changed the IP allow list?" — must not filter `audit_level='ACCOUNT_LEVEL'`
- "Show me the change diff" — must reconstruct via `LAG`, not return only the new value
- "Were there failed IP ACL changes?" — must include `accountIpAclsValidationFailed`
