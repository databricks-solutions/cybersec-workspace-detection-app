# Facts from system.access.audit (checked 2026-11-12)

Source: aggregate-only queries on a real Databricks workspace, 7 days (`profile.json`, 2 workspaces with the widest action mix) and 2-3 day checks for the shapes below. No identities, IPs, ids or parameter values are written here. Everything is descriptive.

## Conventions that differ from the Global Constraints

1. **Service principals have more than one form.** Rows of SPs show `user_identity.email` as:
   - a UUID (the application id) and no `identity_metadata.acting_resource_type`. This is the form the constraint assumes. It is common for `tokenLogin`, `oidcTokenAuthorization`, `getSecret`, `clusters.create`, `workspaceExport`;
   - an email-like or name string (`local@domain` shape) with `identity_metadata.acting_resource_type` set to values such as `Application Service Principal`, `AI Agent Service Principal`, `Browser Fleet Application Service Principal`. A rule that uses only the UUID regex misses these SPs;
   - an empty string on some `clusters.create` rows (system-created clusters).
   `user_identity.subject_name` was NULL in every sampled row. For the demo data keep UUID emails for SPs (`actor_kind = sp` per the regex) and optionally set `acting_resource_type` on some rows to show the second form.
2. **`identity_metadata` is not absent for `tokenLogin` / `oidcTokenAuthorization`.** The struct exists, `run_by` and the display names are NULL, `run_as` equals `user_identity.email`. Most other actions have `run_by` = `run_as` = actor, plus the `*_display_name` fields. `acting_resource_type` is usually NULL.
3. **`session_id`** is NULL on all `tokenLogin` / `oidcTokenAuthorization` rows and on all ACCOUNT_LEVEL Unity Catalog rows (`createFunction`, `deleteFunction`). It is present on about half of the other workspace rows. Rules that need a session must use only rows that have one.
4. **`generateDbToken` `request_params`** had no `tokenScopes` in the observed row (keys: `tokenCreatedBy`, `tokenExpirationTime`, `tokenHash`, `userId`). Treat `tokenScopes` as optional.
5. **`getSecret` failures** use code 3002 (secret or scope does not exist) and 1004 (permission denied). Both occur, 3002 is by far the most common. A failed `getSecret` has a `use_simplified_error_handling` key in `request_params` in addition to `scope`, `key`.
6. **A job `runNow` failure** is code 1004 with a text like "Job N does not exist".

## Workspace and audit level

- ACCOUNT_LEVEL rows have `workspace_id = '0'` (the string zero). The real workspace is in `request_params.workspace_id` for all Unity Catalog rows (`createFunction`, `deleteFunction`, `listCatalogs`, `listExternalLocations`, `listStorageCredentials`), together with `metastore_id`.
- `accounts.addPrincipalToGroup` is also ACCOUNT_LEVEL with `workspace_id = '0'` but has NO `request_params.workspace_id`. A WORKSPACE_LEVEL variant exists too, but it is very rare.
- `accounts.tokenLogin` and `accounts.oidcTokenAuthorization` are WORKSPACE_LEVEL in a workspace and also exist as ACCOUNT_LEVEL rows with `workspace_id = '0'` in small numbers.
- `accounts.IpAccessDenied` is **service `accounts`**, WORKSPACE_LEVEL, code 403, error text "Current IP is not allowed", `request_params` keys `path`, `user`, `userId`. Its identity is often an SP (acting resource types set).
- The profile scope was: all rows of the chosen workspaces, plus ACCOUNT_LEVEL rows whose `request_params.workspace_id` is one of them, plus these account-wide because they carry no workspace key: `addPrincipalToGroup`, `generateDbToken`, `listStorageCredentials`. For these three, `per_actor_per_day` is therefore account-wide.

## Scenario actions

All 20 actions occur in the chosen workspaces. Nothing needed widening for presence. Failure codes below were checked wider (all workspaces, 3-10 days, aggregate only) because the chosen workspaces had few failures.

| service.action | audit_level | `request_params` keys (observed) | codes |
|---|---|---|---|
| accounts.tokenLogin | WORKSPACE | authenticationMethod, tokenId, user | 200 |
| accounts.oidcTokenAuthorization | WORKSPACE (+ small ACCOUNT) | authenticationMethod, tokenId, user | 200 |
| accounts.IpAccessDenied | WORKSPACE | path, user, userId | 403 |
| accounts.addPrincipalToGroup | ACCOUNT | endpoint, targetGroupId, targetGroupName, targetUserId, targetUserName | 200 |
| accounts.generateDbToken | WORKSPACE | tokenCreatedBy, tokenExpirationTime, tokenHash, userId (tokenScopes optional) | 200 |
| secrets.listScopes | WORKSPACE | none (empty map) | 200 |
| secrets.listSecrets | WORKSPACE | scope | 200 |
| secrets.getSecret | WORKSPACE | scope, key (+ use_simplified_error_handling on failure) | 200, 3002, 1004 |
| unityCatalog.listCatalogs | ACCOUNT | metastore_id, workspace_id, max_results, page_token, include_browse, include_unbound, unbound_only, browse_only, omit_authorized_paths, include_delta_sharing_attributes, include_manifest_capabilities | 200 |
| unityCatalog.listExternalLocations | ACCOUNT | metastore_id, workspace_id, max_results, page_token, include_browse, include_unbound | 200 |
| unityCatalog.listStorageCredentials | ACCOUNT | metastore_id, workspace_id, max_results, page_token | 200 |
| unityCatalog.createFunction | ACCOUNT | function_info, include_manifest_capabilities, metastore_id, workspace_id | 200, 400 |
| unityCatalog.deleteFunction | ACCOUNT | full_name_arg, metastore_id, workspace_id | 200 |
| repos.listRepos | WORKSPACE | path_prefix | 200 |
| workspace.workspaceExport | WORKSPACE | notebookFullPath, workspaceExportFormat, workspaceExportDirectDownload | 200 |
| clusters.create | WORKSPACE | many cluster settings, for example cluster_name, node_type_id, num_workers, spark_version, data_security_mode, single_user_name, spark_conf, custom_tags, init_scripts, autotermination_minutes, aws_attributes | 200, 500 |
| jobs.submitRun | WORKSPACE | run_name, tasks, notebook_task, existing_cluster_id, environments, timeout_seconds, idempotency_token, workflow_context | 200, 1000, 1004 |
| jobs.runNow | WORKSPACE | job_id, job_parameters, idempotency_token, only | 200, 1004 |
| databrickssql.startWarehouse | WORKSPACE | id | 200, 3002 |
| notebook.importNotebook | WORKSPACE | path, workspaceExportFormat | 200, 3002 |

## Names and shapes

- **Start warehouse:** service `databrickssql`, action `startWarehouse` (`request_params`: `id`). A rare second action `databrickssql.startEndpoint` exists. Use `startWarehouse`. There is no separate serverless-run action; a serverless run is `jobs.submitRun` / `runNow` with `environments`.
- **`createFunction` `function_info`** is a JSON string. Top-level keys: `name`, `catalog_name`, `schema_name`, `specific_name`, `comment`, `data_type`, `full_data_type`, `input_params`, `return_params` (rare), `routine_body`, `routine_definition`, `routine_dependencies`, `parameter_style`, `is_deterministic`, `is_null_call`, `security_type`, `sql_data_access`. The function name is `function_info.name`; catalog and schema are separate keys.
- **Denied `getSecret`:** code 1004, `error_message` generic form: `PERMISSION_DENIED: User <principal id> does not have secret-scopes.secrets/get permission on scope <scope> to perform this action.` A missing secret is code 3002 with `RESOURCE_DOES_NOT_EXIST: Failed to get secret <key> for scope <scope>.`; a missing scope is `RESOURCE_DOES_NOT_EXIST: Scope <scope> does not exist!`. In the demo, a denied read on a restricted scope should use 1004.
- **Failed `clusters.create`:** code 500, text `DatabricksServiceException: ...` for example `REQUEST_LIMIT_EXCEEDED: Exceeded serverless compute rate limits`, or `BAD_REQUEST: ...`. The failed row has far fewer `request_params` keys than a successful one.
- **Failed `jobs.submitRun`:** code 1000 `INVALID_PARAMETER_VALUE: ...` (bad compute or environment settings) or code 1004 `PERMISSION_DENIED: ...` (for example "Cannot bind the service principal provided in 'run_as' field ... to the job" or "... is not authorized to use or monitor this SQL Endpoint").
- **Failed `createFunction`:** code 400, `DatabricksServiceException: RESOURCE_ALREADY_EXISTS: Routine or Model '<name>' already exists`.
- **Failed `startWarehouse` / `importNotebook`:** code 3002.
- Status codes are Databricks codes (200, 400, 403, 500, 1000, 1004, 3002), not only HTTP codes. In `profile.json` the `status_class` values are `2xx`, `4xx`, `5xx` and `app_error` (code 600 and above).
- `source_ip_address` was set on nearly all rows. A few ACCOUNT_LEVEL `listCatalogs` rows have it empty or NULL.

## User agent families

First token of `user_agent`, share of all rows (full list in `profile.json`): none/empty (largest), Apache-HttpClient, unknown (literal text), grpc-python, Go-http-client, armeria, python-requests, a Genie background agent, cli, PyDatabricksSqlConnector, Fluent-Bit, Mozilla (browser), wsfs, Delta-Sharing-Spark, goofys, zerobus SDKs, tonic, python-httpx. Families under 0.05% are grouped as `other`. Version and build strings are removed.
