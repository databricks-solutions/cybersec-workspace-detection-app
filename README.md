# Databricks Workspace Detection App

A collection of security detection notebooks for Databricks workspaces that analyze the `system.access.audit` table to identify potential security threats and suspicious activities.

## Overview

This detection app provides 30+ pre-built security detection notebooks designed for security operations teams to monitor Databricks workspace activities. The detections cover various security scenarios including:

- **Authentication & Access Control**: Token creation/deletion, MFA changes, SSO configuration changes
- **User Management**: Account creation/deletion, role modifications, group changes
- **Session Security**: Session hijacking detection, multi-device login patterns
- **Administrative Activity**: Privilege escalation, admin activity spikes
- **Audit & Compliance**: Verbose logging changes, audit configuration tampering

## Features

- **Coverage**: 30+ detection scenarios covering major security use cases
- **Production Ready**: Designed for batch execution via Databricks workflows
- **Configurable**: Customizable time ranges and detection parameters
- **Audit Table Focus**: Leverages Databricks `system.access.audit` table for comprehensive visibility
- **Unity Catalog Compatible**: Designed for Unity Catalog enabled accounts
- **MITRE ATT&CK Mapped**: Many detections include MITRE ATT&CK framework mappings for threat intelligence

## Detection Categories

### Authentication & Identity
- Access Token Created/Deleted
- MFA Key Added/Deleted  
- Non-SSO Login Detection
- User Password Changes
- SSO Configuration Changes

### User & Group Management
- User Account Created/Deleted
- Group Created/Deleted
- Principal Added/Removed from Groups
- User Role Modifications

### Session Security
- Session Hijacking Detection (Multiple IPs/Devices)
- High Session Count Detection
- Frequent Login Patterns
- Multi-Device Session Reuse

### Administrative Monitoring
- Spike in Table Admin Activity
- Databricks Employee Logon Detection
- Verbose Audit Logging Disabled

### Network & Access Control
- Attempted Logon from Denied IP
- Token Scanning Activity Detection

### Data Exfiltration & Movement
- Potential Data Movement via SQL Queries
- Potential Data Movement via Workspace Downloads
- Potential Data Movement via Explicit Credentials

### Configuration & Policy Monitoring
- High Priority Configuration Changes
- Workspace-Level Configuration Changes
- Account-Level Configuration Changes

### Secrets & Credential Management
- Secret Scanning Activity Detection
- Admin User Account Changes

## Enhanced Detection Capabilities

The latest version includes advanced detection scenarios that go beyond basic audit monitoring:

- **Data Exfiltration Detection**: Identifies potential data movement attempts using SQL queries, workspace downloads, and explicit credentials
- **Configuration Tampering**: Monitors for unauthorized changes to security-critical workspace and account configurations
- **Secret Enumeration**: Detects reconnaissance activities targeting secret scopes and credential harvesting
- **Admin Privilege Escalation**: Tracks administrative privilege changes and group membership modifications
- **Comprehensive Coverage**: Integrates both `system.access.audit` and `system.query.history` tables for complete visibility

## Installation

### Prerequisites
- Databricks workspace with Unity Catalog enabled
- Access to `system.access.audit` table
- Appropriate permissions to create and run workflows

### Setup
1. **Import the App**: Add the detection notebooks to your Databricks workspace
2. **Configure Workflows**: Set up Databricks workflows for each detection
3. **Adjust Parameters**: Modify start/end times and detection parameters as needed
4. **Schedule Execution**: Configure trigger schedules matching your lookback periods

### Configuration Notes
- Detection searches rely on access to the audit table
- Designed for batch mode execution using workflows
- Ensure trigger schedules match lookback periods for full coverage
- Avoid duplicate events by properly configuring execution intervals

## Usage

### Running Individual Detections
Each detection notebook can be run independently with configurable time parameters:

```python
# Example: Run access token detection for last 24 hours
result = access_token_created(
    earliest="2025-01-01T00:00:00",
    latest="2025-01-02T00:00:00"
)
```

### Workflow Integration
Detections are designed to be integrated into Databricks workflows for automated security monitoring:

1. **Batch Processing**: Run detections on scheduled intervals
2. **Alert Generation**: Output results to detection or alerts tables
3. **Ad-hoc Analysis**: Generate dataframes for manual investigation

### Output Formats
- **DataFrame Output**: Structured data for further analysis
- **Standardized Schema**: Consistent column naming across all detections
- **Audit Trail**: Complete event details with timestamps and metadata

## Architecture

### Core Components
- **Detection Notebooks**: Individual security detection logic
- **Common Library**: Shared utilities and enrichment functions
- **Audit Table Integration**: Direct queries against `system.access.audit`

### Dependencies
- **PySpark**: Core data processing framework
- **GeoIP2**: IP address geolocation capabilities
- **NetAddr**: IP address manipulation utilities

## How to get help

Databricks support doesn't cover this content. For questions or bugs, please open a GitHub issue and the team will help on a best effort basis.


## License

&copy; 2025 Databricks, Inc. All rights reserved. The source in this notebook is provided subject to the Databricks License [https://databricks.com/db-license-source]. All included or referenced third party libraries are subject to the licenses set forth below.

| library                                | description             | license    | source                                              |
|----------------------------------------|-------------------------|------------|-----------------------------------------------------|
| geoip2                                 | IP address geolocation | Apache 2.0 | https://github.com/maxmind/GeoIP2-python          |
| netaddr                                | IP address manipulation| BSD        | https://github.com/netaddr/netaddr                 |
