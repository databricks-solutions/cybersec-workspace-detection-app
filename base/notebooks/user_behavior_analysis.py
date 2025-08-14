# Databricks notebook source
# MAGIC %md
# MAGIC # Beta - User Behavior Analysis Generator
# MAGIC 
# MAGIC This notebook generates a new investigative notebook focused on the behavior of 
# MAGIC a specific user across multiple security detections. The new notebook will be
# MAGIC stored in the same folder as this notebook, and can be run to analyze the user's behavior.
# MAGIC 
# MAGIC **Parameters:**
# MAGIC - `user_email`: Email address of the user to analyze
# MAGIC - `time_range_days`: Number of days to look back (default: 30)

# COMMAND ----------

# Widget parameters for interactive execution
dbutils.widgets.text("user_email", "", "User Email Address")
dbutils.widgets.text("time_range_days", "30", "Time Range (days)")

# Get parameters
user_email = dbutils.widgets.get("user_email")
time_range_days = int(dbutils.widgets.get("time_range_days"))

if not user_email:
    raise ValueError("Please provide a user email address")

print(f"Generating user behavior analysis notebook for: {user_email}")
print(f"Time range: {time_range_days} days")
print()

# COMMAND ----------

# MAGIC %pip install pyyaml

# COMMAND ----------

import os
import re
import yaml
import glob
from datetime import datetime, timedelta
from typing import Dict, Tuple, Any
from pyspark.sql.functions import col
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.workspace import ImportFormat, Language
import io
w = WorkspaceClient()
cwd = os.getcwd().replace("/base/notebooks", "")
# COMMAND ----------

# MAGIC %md
# MAGIC ## Dynamic Detection Discovery

# COMMAND ----------

def parse_detection_file(file_path: str) -> Dict[str, Any]:
    """Parse a detection file to extract metadata and function information"""
    with w.workspace.download(os.path.join(cwd, file_path)) as f:
        content = f.read().decode()
    # Extract the YAML metadata from the markdown cell
    yaml_match = re.search(r'```yaml\s*(.*?)```', content, re.DOTALL)
    if not yaml_match:
        print(f"Warning: No YAML metadata found in {file_path}")
        return None
    yaml_content = yaml_match.group(1).replace("# MAGIC ", "")
    try:
        metadata = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        print(f"Warning: Failed to parse YAML in {file_path}: {e}")
        return None
    
    # Extract function definition and parameters
    func_match = re.search(r'@detect.*?\ndef\s+(\w+)\s*\((.*?)\):', content, re.DOTALL)
    if not func_match:
        print(f"Warning: No detection function found in {file_path}")
        return None
    
    function_name = func_match.group(1)
    params_str = func_match.group(2)
    
    full_function_match = re.search(r'(@detect.*?)# COMMAND -------', content, re.DOTALL)
    if not full_function_match:
        print(f"Warning: No full function found in {file_path}")
        return None
    full_function = full_function_match.group(1)
    user_replaced = False
    if 'spark.table("system.access.audit")' in full_function:
        full_function = full_function.replace('spark.table("system.access.audit")', 'spark.table("system.access.audit").filter(col("user_identity.email") == "{}")'.format(user_email))
        user_replaced = True
    if 'spark.table("system.query.history")' in full_function:
        full_function = full_function.replace('spark.table("system.query.history")', 'spark.table("system.query.history").filter(col("executed_as") == "{}")'.format(user_email))
        user_replaced = True
    if not user_replaced:
        print(f"Warning: No user filter inserted into {file_path}")
        return None

    # Parse parameters
    params = []
    defaults = {}
    if params_str.strip():
        # Split by comma but handle nested parentheses
        param_parts = re.findall(r'(\w+)(?:\s*:\s*\w+)?(?:\s*=\s*([^,]+))?(?:,|$)', params_str)
        for param_name, default_value in param_parts:
            params.append(param_name)
            if default_value:
                # Clean up default value
                default_value = default_value.strip()
                if default_value.startswith('"') and default_value.endswith('"'):
                    defaults[param_name] = default_value[1:-1]
                elif default_value == 'None':
                    defaults[param_name] = None
                elif default_value.isdigit():
                    defaults[param_name] = int(default_value)
                else:
                    defaults[param_name] = default_value
    # Extract detection info from metadata
    detection_info = metadata.get('dscc', {}).get('detection', {})
    
    return {
        "file_path": file_path,
        "file_name": os.path.basename(file_path).replace('.py', ''),
        "function_name": function_name,
        "full_function": full_function,
        "name": detection_info.get('name', function_name.replace('_', ' ').title()),
        "description": detection_info.get('description', '').strip(),
        "objective": detection_info.get('objective', '').strip(),
        "false_positives": detection_info.get('false_positives', '').strip(),
        "severity": detection_info.get('severity', '').strip(),
        "fidelity": detection_info.get('fidelity', '').strip(),
        "params": params,
        "defaults": defaults,
        "metadata": metadata
    }

def discover_detections(base_path: str = "base/detections") -> Dict[str, Dict]:
    """Dynamically discover all detection files and parse their metadata"""
    
    detections = {}
    detection_files = glob.glob(os.path.join(cwd, base_path, "*"))
    
    print(f"Discovering detections in {base_path}...")
    print(f"Found {len(detection_files)} detection files")
    
    for file_path in detection_files:
        detection_info = parse_detection_file(file_path)
        if detection_info:
            detection_name = detection_info["file_name"]
            detections[detection_name] = detection_info
            print(f"  ✓ Loaded: {detection_name}")
    
    print(f"\nSuccessfully loaded {len(detections)} detections")
    return detections

# COMMAND ----------

# MAGIC %md
# MAGIC ## Helper Functions

# COMMAND ----------

def format_time_range(days: int) -> Tuple[str, str]:
    """Format time range for detection functions"""
    latest = datetime.now()
    earliest = latest - timedelta(days=days)
    
    return (
        earliest.strftime("%Y-%m-%d %H:%M:%S"),
        latest.strftime("%Y-%m-%d %H:%M:%S")
    )

def generate_detection_code(detection_name: str, config: Dict, user_email: str, earliest: str, latest: str) -> str:
    """Generate PySpark code for a specific detection"""
    
    # Build the function call with parameters
    params = []
    for param in config.get("params", []):
        if param == "earliest":
            params.append(f'earliest="{earliest}"')
        elif param == "latest":
            params.append(f'latest="{latest}"')
        elif param in config.get("defaults", {}):
            default_value = config["defaults"][param]
            if default_value is not None:
                if isinstance(default_value, str):
                    params.append(f'{param}="{default_value}"')
                else:
                    params.append(f'{param}={default_value}')
    
    function_call = f"{config['function_name']}({', '.join(params)})"
    
    # Generate the code
    code = f"""# Run detection: {config.get('name', detection_name)}

{config['full_function']}

try:
    result_df = {function_call}
    
    # Check if we have results
    if result_df is not None and result_df.count() > 0:
        print(f"✓ Found {{result_df.count()}} events")
        display(result_df)
        detection_triggered = True
    else:
        print(f"○ No events in the specified time range")
        detection_triggered = False
        
except Exception as e:
    print(f"✗ Error running detection: {{e}}")
    detection_triggered = False
"""
    
    return code

# COMMAND ----------

# MAGIC %md
# MAGIC ## Generate User-Specific Analysis Notebook

# COMMAND ----------

def generate_user_notebook(user_email: str, time_range_days: int = 30, all_detections: dict = None) -> str:
    """Generate a complete notebook for analyzing a specific user's behavior"""
    
    # Discover all detections
    all_detections = all_detections or discover_detections()
    
    earliest, latest = format_time_range(time_range_days)
    
    # Sort detections alphabetically by name for consistent ordering
    sorted_detections = sorted(
        all_detections.items(),
        key=lambda x: x[1].get("name", x[0])
    )
    
    # Define magic command prefix as a variable to avoid confusion
    magic = "# MAGIC"
    command = "# COMMAND ----------"
    notebook_content = f"""# Databricks notebook source
{magic} %md
{magic} # User Behavior Analysis Report
{magic} 
{magic} **User:** {user_email}  
{magic} **Analysis Period:** {earliest} to {latest} ({time_range_days} days)  
{magic} **Total Detections Included:** {len(all_detections)}  
{magic} **Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

{command}

{magic} %md
{magic} ## Setup and Configuration

{command}

{magic} %run ./lib/common

{command}

from pyspark.sql.functions import col, count, when, max as spark_max, min as spark_min
from datetime import datetime, timedelta
import pandas as pd

# Analysis parameters
USER_EMAIL = "{user_email}"
EARLIEST = "{earliest}"
LATEST = "{latest}"
TIME_RANGE_DAYS = {time_range_days}

print(f"Analyzing user behavior for: {{USER_EMAIL}}")
print(f"Time range: {{EARLIEST}} to {{LATEST}}")
print("=" * 60)

{command}

{magic} %md
{magic} ## Recent Statistics

{command}

{magic} %md
{magic} ### IP Addresses
{magic}
{magic} The report below will show the IP Addresses that have been used by the time period. If there is a small number of IPs before any suspect period, followed by a new IP during a suspect period, it is prudent to review that IP address. 

{command}

display(spark.sql(f'''
select 
    min(event_time) as earliest, 
    max(event_time) as latest, 
    count(*) as total_events, 
    count(distinct service_name || action_name) as num_unique_actions, 
    source_ip_address 
from system.access.audit 
where user_identity.email = '{{USER_EMAIL}}' and event_time between '{{EARLIEST}}' and '{{LATEST}}' 
group by all 
order by earliest desc
'''))

{command}

{magic} %md
{magic} ### Token Usage
{magic}
{magic} The report below will show the Personal Access Tokens or OAuth tokens that have been used in the time period. This can provide context about normal vs abnormal activity.

{command}

display(spark.sql(f'''
select 
  min(event_time) as earliest, 
  max(event_time) as latest, 
  count(*) as total_events, 
  count(distinct source_ip_address) as num_source_ips, 
  count(distinct user_agent) as num_useragents, 
  request_params.tokenId 
from system.access.audit where 
  action_name == "tokenLogin" and 
  request_params.authenticationMethod!='API_INT_PAT_TOKEN' and  -- filters out internal actions from a notebook / job
  user_identity.email = '{{USER_EMAIL}}' and event_time between '{{EARLIEST}}' and '{{LATEST}}' 
group by all 
order by earliest desc
'''))

{command}

{magic} %md 
{magic} ### API Actions

{command}

display(spark.sql(f'''
select 
  min(event_time) as earliest, 
  max(event_time) as latest, 
  count(*) as total_events, 
  service_name, 
  action_name,  
  count(distinct source_ip_address) as num_source_ips, 
  count(distinct user_agent) as num_useragents
from system.access.audit 
where user_identity.email = '{{USER_EMAIL}}' and event_time between '{{EARLIEST}}' and '{{LATEST}}' 
group by all 
order by earliest desc
'''))

{command}

{magic} %md 
{magic} ### Billing Usage
{magic}
{magic} We suggest viewing a stacked area chart of SKU usage over time to identify any spikes.

{command}

display(spark.sql(f'''
select 
  usage_date,
  sku_name,
  sum(usage_quantity) as DBU_used
from system.billing.usage
where 
  usage_unit="DBU" and
  identity_metadata.created_by = '{{USER_EMAIL}}' and usage_start_time between '{{EARLIEST}}' and '{{LATEST}}'
group by all
'''))

{command}

{magic} %md
{magic} ## Detection Analysis
{magic} 
{magic} Analyzing user activity across {len(all_detections)} security detections.

{command}

# Initialize summary statistics
summary_stats = {{
    "user": USER_EMAIL,
    "analysis_period": f"{{EARLIEST}} to {{LATEST}}",
    "total_detections": {len(all_detections)},
    "findings": 0,
    "detections_triggered": []
}}

detection_triggered = False

"""
    
    # Add all detections
    fields = [
        {"field": "description", "label": "Description"},
        {"field": "objective", "label": "Objective"},
        {"field": "fidelity", "label": "Fidelity"},
        {"field": "category", "label": "Category"},
        {"field": "taxonomy", "label": "Taxonomy"},
        {"field": "platform", "label": "Platform"},
        {"field": "version", "label": "Version"},
        {"field": "false_positives", "label": "False Positives"},
        {"field": "severity", "label": "Severity"},
    ]
    for detection_name, config in sorted_detections:
        # Get clean display name
        display_name = config.get('name', detection_name.replace('_', ' ').title())
        description = config.get('description', 'No description available')
        objective = config.get('objective', '')
        
        notebook_content += f"""
{command}

{magic} %md
{magic} ### {display_name}
{magic} 
"""
        for field in fields:
            if config.get(field["field"], '').strip():
                notebook_content += f"""{magic} **{field["label"]}:** {config.get(field["field"], '').strip()}

"""
        notebook_content += f"""{magic} **Detection File:** `{detection_name}.py`

{command}

{generate_detection_code(detection_name, config, user_email, earliest, latest)}

# Update summary statistics if detection triggered
if detection_triggered:
    summary_stats["findings"] += 1
    summary_stats["detections_triggered"].append(f"{display_name}")

"""
    
    # Add summary section
    notebook_content += f"""
{command}

{magic} %md
{magic} ## Analysis Summary

{command}

# Display final summary statistics
print("=" * 60)
print("USER BEHAVIOR ANALYSIS SUMMARY")
print("=" * 60)
print(f"User: {{summary_stats['user']}}")
print(f"Analysis Period: {{summary_stats['analysis_period']}}")
print(f"Total Detections Analyzed: {{summary_stats['total_detections']}}")
print(f"Total Findings: {{summary_stats['findings']}}")
print("-" * 60)

if summary_stats["findings"] == 0:
    print("✓ RESULT: No suspicious activity detected for this user")
else:
    print(f"⚠️ RESULT: {{summary_stats['findings']}} detection(s) triggered - review required")
    print()
    print("Detections that triggered:")
    for detection in summary_stats["detections_triggered"]:
        print(f"  • {{detection}}")

{command}

{magic} %md
{magic} ---
{magic} *Report generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} using User Behavior Analysis Framework*
"""
    
    return notebook_content

# COMMAND ----------

# MAGIC %md
# MAGIC ## Main Execution

# COMMAND ----------

# Discover available detections
print("Discovering available detections...")
all_detections = discover_detections()

print(f"\nTotal detections available: {len(all_detections)}")

# COMMAND ----------

# # Generate the notebook content
notebook_content = generate_user_notebook(
    user_email=user_email,
    time_range_days=time_range_days,
    all_detections=all_detections
)

# Create output file name
output_filename = f"user_analysis_{user_email.replace('@', '_at_').replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
output_path = os.path.join(cwd, "generated", output_filename)

# Save the notebook
w.workspace.upload(output_path, io.BytesIO(notebook_content.encode('utf-8')), format=ImportFormat.SOURCE, language=Language.PYTHON)

print()
print("=" * 60)
print("✅ User-specific notebook generated successfully!")
print(f"📁 Saved to: {output_path}")
print(f"📊 Will analyze {len(all_detections)} detections")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Detection Summary

# COMMAND ----------

# Display summary of what will be analyzed
detection_list = []
for name, det in all_detections.items():
    detection_list.append({
        "Detection": det.get('name', name),
        "Description": det.get('description', 'No description')[:100] + "..." if len(det.get('description', '')) > 100 else det.get('description', 'No description'),
        "File": f"{name}.py"
    })

summary_df = spark.createDataFrame(detection_list)

print(f"Detections that will be included in the analysis ({len(all_detections)} total):")
display(summary_df.orderBy(col("Detection")))
