# Contributing to the Databricks Detection Tool

Thank you for your interest in contributing! We welcome contributions from the
community, and we accept PRs pursuant to a CLA.

This repo is **public and customer-facing**: people install these detections into
their own Databricks accounts and act on the results during real investigations.
That shapes the testing expectations below.

## Getting Started

Before you begin:

1. **Check existing issues** — look through
   [GitHub Issues](https://github.com/databricks-solutions/cybersec-workspace-detection-app/issues)
   to see if your bug report or feature request already exists
2. **Read the README** — [README.md](README.md) covers the four ways to use the
   tool, including the [Genie Agent](genie-agent/README.md)
3. **Understand the structure** — review the codebase organization below

### Project Structure

```
cybersec-workspace-detection-app/
├── base/
│   ├── detections/
│   │   ├── event-based/     # High-confidence alerts (24-hour window)
│   │   └── behavioral/      # Threat hunting (30-day window)
│   └── notebooks/           # Generated investigation notebooks
├── lib/                     # Shared library (@detect decorator, enrichment,
│                            #   threat model mappings, notebook generators)
├── genie-agent/             # Natural-language investigation surface
│   ├── functions/           # UC SQL functions (the Genie trusted assets)
│   ├── agent/               # Instructions, examples, space template
│   ├── deploy/              # install_notebook (recommended) + install.py (CLI)
│   └── docs/                # DEPLOY.md, PORTING.md
├── docs/                    # detection_tracker.md — the detection inventory
└── metadata/                # App manifest metadata
```

## Development Setup

### Prerequisites

- A Databricks workspace with **Unity Catalog** enabled
- `SELECT` on `system.access.audit` (an account admin runs
  `ALTER METASTORE ENABLE SCHEMA system.access;` once per metastore)
- A SQL warehouse, or any cluster (serverless works)
- Git

### Local Setup

```bash
git clone https://github.com/databricks-solutions/cybersec-workspace-detection-app.git
cd cybersec-workspace-detection-app
```

Detections are Databricks notebooks that run against your workspace's audit
tables — there is no local Python package to install. The most convenient loop is
to add this repo as a **Git folder** in your workspace and run the notebooks
directly (Workspace → Create → Git folder).

## How to Contribute

We welcome:

1. **Bug Fixes** — fix issues in existing detections
2. **New Detections** — new security detections or coverage gaps
3. **Documentation** — improve or add documentation
4. **Genie Agent coverage** — port detections to the natural-language surface

### The one rule that matters most

**A detection that returns fewer rows than it should is worse than no detection.**

During an incident, an empty result reads as *"nothing happened."* A filter that
silently misses events, or a `request_params` key that does not exist, produces
exactly that — a confident, clean-looking answer that is wrong. Several bugs found
in this repo were of that shape, and **none would have been caught by reading the
code**.

So: **run your detection against real audit data before opening a PR.**

### Reporting Bugs

Please include:

- Clear description of what happened vs. what you expected
- Steps to reproduce
- Environment details (Databricks runtime, cloud provider, workspace type)
- Error messages and stack traces
- **Row counts**, if a detection returned more or fewer results than expected

**Security vulnerabilities** should be reported to `bugbounty@databricks.com` —
see [SECURITY.md](SECURITY.md). Do not open a public issue.

### Suggesting Features

Explain the use case, how you envision it working, and who benefits. For a new
detection, say what an analyst would *do* with a hit.

## Adding a Detection

Detections live in `base/detections/{event-based,behavioral}/` as notebooks with a
`dscc` YAML metadata block. Copy an existing one — that metadata is machine-read
(the Genie Agent's catalog is generated from it), so keep the shape.

Fill in honestly:

- `severity` / `fidelity` — a triage hint, not a verdict
- `taxonomy` — MITRE technique(s)
- `false_positives` — what will legitimately fire this. Every detection has some;
  naming them is what makes it usable
- `objective` — what an analyst learns from a hit

Then update `lib/threat_model_mappings.py` and `docs/detection_tracker.md`.

### Verify against live data before you open the PR

1. **Execute it** over a window you know contains activity, and note the row count
   in your PR description.
2. **Verify every `request_params` key against live data.** They do **not** match
   the REST API field names, and a wrong key returns `NULL` rather than erroring:
   ```sql
   SELECT action_name, map_keys(request_params)
   FROM system.access.audit
   WHERE action_name = '<your action>' LIMIT 5
   ```
3. **Check your `service_name` filter is not too narrow.** Measured on a real
   workspace, `runCommand` appears **396,612** times under `service_name='jobs'`
   and **776** times under `'notebook'` — a detection filtering only `notebook`
   misses 99.8% of command executions, including anything an attacker scheduled as
   a job.
4. **Aggregate high-volume detections.** One returned **242,738 rows from 6
   actors** before being aggregated per actor and day. Anything that large is
   unreadable and will truncate.
5. **Do not bake your own account's allowlist into a shipped detection.** One
   notebook excludes a specific `user_agent` and source IP for a known internal
   job; shipping that pattern silently hides real activity in every other
   customer's account. Return the columns and let the caller filter.

## Adding to the Genie Agent

To make a detection answerable in natural language, port it to a UC SQL function
in `genie-agent/functions/`. Read
[`genie-agent/docs/PORTING.md`](genie-agent/docs/PORTING.md) first — it documents
traps that fail obscurely:

- A SQL UDF body **cannot begin with a top-level `WITH`** (wrap the CTE in a
  subquery)
- `IN (SELECT explode(...))` creates on a SQL warehouse but **fails** inside a UDF
  body on DBR — use `array_contains(transform(split(...)))`
- **Fully qualify** function names; a bare `CREATE FUNCTION` can land in
  `hive_metastore`, where it cannot reference `system.access.audit`

**Test both install paths.** The notebook installer (DBR) and the CLI installer
(DBSQL) use different engines and are not interchangeable — a real bug affected one
and not the other.

Each function's `COMMENT` must end with a `Use for:` list of real analyst
phrasings. That text is what Genie matches a question against, so it is
load-bearing, not documentation.

## Pull Request Process

### Branch Naming

- `feature/add-token-abuse-detection`
- `bugfix/fix-service-name-filter`
- `docs/update-install-guide`

### Submitting a Pull Request

1. Fork the repository and create your branch from `main`
2. Make your changes — clear code, updated docs
3. Commit with a descriptive message
4. Push to your fork and open a PR with a clear description

The PR template asks what you tested and on what data. **"Ran over 90 days on a
live workspace, 47 rows, no false positives" is worth more than any description of
the logic.**

### Commit Message Format

- `feat: add new detection`
- `fix: resolve bug`
- `docs: update documentation`
- `chore: repo maintenance`

### Pull Request Review

- At least one maintainer must approve the PR
- Documentation must be updated if needed
- `.github/CODEOWNERS` auto-requests the right reviewers

## Code Style

- Follow PEP 8 conventions
- Meaningful variable and function names
- Docstrings on public functions
- Handle errors appropriately
- **Never commit sensitive data** — credentials, tokens, real audit data, or
  customer identifiers

Secret scanning with push protection is enabled and will block a push containing a
recognised secret, but it cannot recognise everything. Sanitise your examples: use
placeholder emails and RFC5737 documentation IPs (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`) rather than real ones from your own logs.

## License and CLA

By contributing to this project, you agree to the Contributor License Agreement
(CLA). All pull requests require CLA acceptance before merging.

This project is licensed under the Databricks License. See [LICENSE](LICENSE) for
details, and [NOTICE](NOTICE) for attribution.

## Getting Help

- **GitHub Issues** — bug reports and feature requests
- **Security Issues** — bugbounty@databricks.com

Thank you for contributing! 🔒
