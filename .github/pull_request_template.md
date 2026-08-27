## What

<!-- What does this change, in one or two sentences? -->

## Why

<!-- What gap does it close, or what was wrong? -->

## Tested on real data

<!-- REQUIRED for any detection change. A detection that returns fewer rows than
     it should is worse than no detection: during an incident an empty result
     reads as "nothing happened". Reading the code cannot catch that. -->

- [ ] Executed against a live workspace over a window known to contain activity
- [ ] Row count observed: <!-- e.g. "47 rows over 90 days, 6 distinct actors" -->
- [ ] Every `request_params` key verified against live data
      (`SELECT action_name, map_keys(request_params) FROM system.access.audit WHERE …`)
      — they do **not** match the REST API field names, and a wrong key returns
      `NULL` rather than erroring
- [ ] `service_name` filter checked for over-narrowness
      (`runCommand` is ~500× more common under `jobs` than `notebook`)
- [ ] False positives named in the `dscc` YAML block
- [ ] High-volume output aggregated rather than row-per-event

## Genie Agent (if applicable)

- [ ] Ported to a UC SQL function in `genie-agent/functions/`
- [ ] **Both** install paths tested — notebook (DBR) and CLI (DBSQL) use different
      engines and are not interchangeable
- [ ] Function `COMMENT` ends with a `Use for:` list of real analyst phrasings
      (that text is what Genie matches a question against)

## Checks

- [ ] No real audit data, credentials, tokens, or customer identifiers committed
      (placeholder emails; RFC5737 IPs — `192.0.2.0/24`, `198.51.100.0/24`,
      `203.0.113.0/24`)
- [ ] No environment-specific allowlist baked in — shipping one silently hides
      real activity in every other account
- [ ] `docs/detection_tracker.md` and `lib/threat_model_mappings.py` updated if a
      detection was added
