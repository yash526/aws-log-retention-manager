"""
AWS CloudWatch Log Retention Auto-Enforcer (Lambda)
===================================================
Automatically sets retention policy on newly created CloudWatch Log Groups.

Triggered via EventBridge on AWS CloudTrail event:
  - EventSource: logs.amazonaws.com
  - EventName: CreateLogGroup

Author: Yash Trivedi
License: MIT
"""

import os
import boto3
from botocore.exceptions import ClientError

DEFAULT_RETENTION_DAYS = int(os.environ.get("DEFAULT_RETENTION_DAYS", "14"))
EXCLUDE_PREFIXES = [p.strip() for p in os.environ.get("EXCLUDE_PREFIXES", "/aws/cloudtrail").split(",") if p.strip()]

logs_client = boto3.client("logs")


def lambda_handler(event, context):
    print(f"[*] Received event: {event}")

    # Extract log group name from CloudTrail event or direct test payload
    detail = event.get("detail", {})
    request_params = detail.get("requestParameters", {})
    log_group_name = request_params.get("logGroupName") or event.get("logGroupName")

    if not log_group_name:
        print("[!] No logGroupName found in event payload. Nothing to do.")
        return {"statusCode": 400, "message": "Missing logGroupName"}

    # Check exclusions
    for prefix in EXCLUDE_PREFIXES:
        if log_group_name.startswith(prefix):
            print(f"[*] Skipping excluded log group: {log_group_name} (matched prefix: {prefix})")
            return {"statusCode": 200, "message": f"Skipped: matches excluded prefix {prefix}"}

    print(f"[*] Applying {DEFAULT_RETENTION_DAYS}-day retention to: {log_group_name}")

    try:
        logs_client.put_retention_policy(
            logGroupName=log_group_name,
            retentionInDays=DEFAULT_RETENTION_DAYS
        )
        print(f"[✓] Successfully set {DEFAULT_RETENTION_DAYS}d retention on {log_group_name}")
        return {
            "statusCode": 200,
            "message": f"Enforced {DEFAULT_RETENTION_DAYS}d retention on {log_group_name}"
        }
    except ClientError as e:
        error_msg = e.response.get("Error", {}).get("Message", str(e))
        print(f"[✗] Failed to set retention on {log_group_name}: {error_msg}")
        raise e
