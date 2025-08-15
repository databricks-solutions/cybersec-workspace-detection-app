# Databricks notebook source
# MAGIC %run ../../lib/common

# COMMAND ----------

# MAGIC %md
# MAGIC # Run all detection notebooks
# MAGIC
# MAGIC Example: 
# MAGIC
# MAGIC `workspace_dir="/Workspace/Users/<USER_EMAIL>/cybersec-workspace-detection-app/base/detections"
# MAGIC run_all_detections(workspace_dir=workspace_dir, earliest="2025-06-15 12:00:00", latest="2025-06-16 12:00:00")`

# COMMAND ----------
import os

workspace_dir = os.getcwd() + "/base/detections"

run_all_detections(workspace_dir=workspace_dir, earliest="2025-06-15 12:00:00", latest="2025-06-16 12:00:00")

# COMMAND ----------