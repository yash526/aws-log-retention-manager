#!/usr/bin/env python3
"""
AWS CloudWatch Log Retention Manager
====================================
Audits and enforces customizable retention policies across AWS CloudWatch log groups.
Eliminates unbounded 'Never Expire' log storage waste.

Features:
  - User-configurable retention days (default: 7, or customized via --days)
  - Validation against discrete AWS CloudWatch allowed retention tiers
  - DRY-RUN by default with clear before-and-after cost savings preview
  - Filter by log group prefix (e.g. /aws/lambda/, /aws/ecs/) or audit all groups
  - Multi-region or single-region scanning
  - Generates summary reports in Console Table, CSV, or JSON

Author: Yash Trivedi
License: MIT
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Ensure stdout handles UTF-8 on Windows command prompts
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# Discrete valid retention tiers accepted by AWS PutRetentionPolicy API:
VALID_RETENTION_TIERS = [
    1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180,
    365, 400, 545, 731, 1095, 1827, 2192, 2557, 2922, 3288, 3653
]

# Standard CloudWatch Logs storage pricing per GB/month (us-east-1 reference)
STORAGE_COST_PER_GB = 0.03


def validate_and_normalize_days(days: int) -> int:
    """
    Validates that the provided retention days matches an AWS CloudWatch allowed tier.
    If not exact, finds the nearest valid tier and advises the user.
    """
    if days in VALID_RETENTION_TIERS:
        return days

    # Find closest valid tier
    closest = min(VALID_RETENTION_TIERS, key=lambda x: abs(x - days))
    print(f"\n[!] Note: CloudWatch API does not support '{days}' days retention.")
    print(f"[*] Closest valid AWS retention tier is: {closest} days.")
    print(f"    Supported tiers: {VALID_RETENTION_TIERS}\n")
    return closest


def get_account_identifier(session: boto3.Session) -> str:
    """Retrieves account alias or 12-digit account ID."""
    try:
        iam = session.client("iam")
        aliases = iam.list_account_aliases().get("AccountAliases", [])
        if aliases:
            return aliases[0]
    except Exception:
        pass

    try:
        sts = session.client("sts")
        return sts.get_caller_identity().get("Account", "unknown-account")
    except Exception:
        return "unknown-account"


def scan_log_groups(
    client,
    prefix: Optional[str] = None,
    target_all_groups: bool = False
) -> List[Dict]:
    """
    Scans CloudWatch log groups in the given region.
    Filters to groups without retention (or all groups if target_all_groups is True).
    """
    paginator = client.get_paginator("describe_log_groups")
    kwargs = {}
    if prefix:
        kwargs["logGroupNamePrefix"] = prefix

    discovered = []
    for page in paginator.paginate(**kwargs):
        for lg in page.get("logGroups", []):
            current_retention = lg.get("retentionInDays")  # None = Never Expire
            if target_all_groups or current_retention is None:
                discovered.append({
                    "name": lg["logGroupName"],
                    "current_retention": current_retention,
                    "stored_bytes": lg.get("storedBytes", 0),
                    "stored_gb": lg.get("storedBytes", 0) / (1024 ** 3),
                    "created_at": datetime.fromtimestamp(lg.get("creationTime", 0) / 1000.0).strftime("%Y-%m-%d") if lg.get("creationTime") else "N/A",
                })
    return discovered


def apply_retention_policy(
    client,
    log_group_name: str,
    days: int,
    dry_run: bool = True
) -> Tuple[bool, str]:
    """Applies retention policy to a CloudWatch log group."""
    if dry_run:
        return True, f"Would set {days}d retention (DRY RUN)"

    try:
        client.put_retention_policy(
            logGroupName=log_group_name,
            retentionInDays=days
        )
        return True, f"Set to {days} days"
    except ClientError as e:
        error_msg = e.response.get("Error", {}).get("Message", str(e))
        return False, f"ERROR: {error_msg}"


def run_retention_manager(
    region: str,
    retention_days: int,
    prefix: Optional[str] = None,
    target_all_groups: bool = False,
    apply: bool = False,
    profile: Optional[str] = None
) -> List[Dict]:
    """Main execution orchestrator."""
    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(**session_kwargs)

    account_id = get_account_identifier(session)
    client = session.client("logs", region_name=region)

    dry_run = not apply
    mode_str = "APPLYING CHANGES (LIVE)" if apply else "DRY RUN (Preview Only)"

    print("=" * 80)
    print("  AWS CloudWatch Log Retention Manager")
    print("=" * 80)
    print(f"  Account     : {account_id}")
    print(f"  Region      : {region}")
    print(f"  Target Days : {retention_days} days")
    print(f"  Prefix      : {prefix if prefix else '(All log groups)'}")
    print(f"  Scope       : {'All groups' if target_all_groups else 'Only groups with Never Expire'}")
    print(f"  Mode        : {mode_str}")
    print("=" * 80 + "\n")

    log_groups = scan_log_groups(client, prefix=prefix, target_all_groups=target_all_groups)

    if not log_groups:
        print("  [OK] Great news: No log groups matching your criteria require retention updates!")
        return []

    print(f"[*] Found {len(log_groups)} log groups requiring attention.\n")

    total_stored_gb = sum(g["stored_gb"] for g in log_groups)
    est_monthly_cost = total_stored_gb * STORAGE_COST_PER_GB

    results = []
    print(f"{'Log Group':<55} {'Current':<14} {'Size':<10} {'Action / Status'}")
    print("-" * 105)

    for group in log_groups:
        lg_name = group["name"]
        curr_ret = f"{group['current_retention']}d" if group["current_retention"] else "Never Expire"
        size_str = f"{group['stored_gb']:.2f} GB" if group["stored_gb"] >= 0.01 else f"{group['stored_bytes'] / 1024:.1f} KB"

        success, status_msg = apply_retention_policy(
            client,
            log_group_name=lg_name,
            days=retention_days,
            dry_run=dry_run
        )

        display_name = lg_name if len(lg_name) <= 52 else lg_name[:49] + "..."
        icon = "  [OK]" if (success and not dry_run) else ("  [DRY]" if dry_run else "  [ERR]")
        print(f"{display_name:<55} {curr_ret:<14} {size_str:<10} {icon} {status_msg}")

        results.append({
            "LogGroup": lg_name,
            "Region": region,
            "CurrentRetention": curr_ret,
            "TargetRetentionDays": retention_days,
            "StoredBytes": group["stored_bytes"],
            "StoredGB": round(group["stored_gb"], 4),
            "Status": status_msg,
            "Success": success
        })

    print("-" * 105)
    print("\n" + "=" * 80)
    print("  FINOPS & STORAGE SUMMARY")
    print("=" * 80)
    print(f"  Log Groups Audited     : {len(log_groups)}")
    print(f"  Total Uncapped Storage : {total_stored_gb:.2f} GB")
    print(f"  Est. Monthly Storage   : ${est_monthly_cost:.2f}/month (~${est_monthly_cost * 12:.2f}/year)")
    print(f"  Enforced Retention     : {retention_days} days")

    if dry_run:
        print("\n  [!] This was a DRY RUN. No log groups were modified.")
        print(f"      To apply these retention policies, re-run with --apply:")
        print(f"      python set_log_retention.py --days {retention_days} --apply" + (f" --profile {profile}" if profile else ""))
    else:
        success_count = sum(1 for r in results if r["Success"])
        error_count = len(results) - success_count
        print(f"\n  [OK] Execution Complete: {success_count} updated successfully, {error_count} errors.")

    print("=" * 80 + "\n")
    return results


def export_results(results: List[Dict], filepath: str):
    """Exports audit results to CSV or JSON."""
    if not results:
        return

    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".json":
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    else:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            writer.writeheader()
            writer.writerows(results)
    print(f"[*] Audit results successfully exported to: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="Audit and set retention on AWS CloudWatch log groups with Never Expire.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Dry run: See what log groups have Never Expire (default 7 days):
  python set_log_retention.py

  # 2. Dry run with custom retention (e.g., 30 days):
  python set_log_retention.py --days 30

  # 3. Apply changes (set 14 days retention across /aws/lambda/ groups):
  python set_log_retention.py --days 14 --prefix /aws/lambda/ --apply

  # 4. Target all log groups (including those that already have a different retention):
  python set_log_retention.py --days 30 --all --apply

  # 5. Run against a specific AWS CLI profile and region, export to CSV:
  python set_log_retention.py --profile prod --region us-east-1 --days 90 --apply --output audit.csv

Available valid retention tiers for --days:
  1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1095, 1827, 2192, 2557, 2922, 3288, 3653
        """
    )

    parser.add_argument(
        "--days", "-d",
        type=int,
        default=7,
        help="Retention period in days (default: 7). Common choices: 7, 14, 30, 60, 90, 365."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually apply the retention changes (default is DRY RUN preview)."
    )
    parser.add_argument(
        "--prefix", "-p",
        type=str,
        default=None,
        help="Filter log groups by prefix (e.g. '/aws/lambda/' or '/aws/ecs/')."
    )
    parser.add_argument(
        "--all",
        action="store_true",
        dest="target_all",
        help="Target all log groups matching the filter, even if they already have retention set."
    )
    parser.add_argument(
        "--region", "-r",
        type=str,
        default="ap-south-1",
        help="AWS region to scan (default: ap-south-1)."
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="AWS CLI profile name to use."
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Optional file path to export results (.csv or .json)."
    )

    args = parser.parse_args()

    # Validate and normalize retention tier
    retention_days = validate_and_normalize_days(args.days)

    try:
        results = run_retention_manager(
            region=args.region,
            retention_days=retention_days,
            prefix=args.prefix,
            target_all_groups=args.target_all,
            apply=args.apply,
            profile=args.profile
        )

        if args.output and results:
            export_results(results, args.output)

    except NoCredentialsError:
        print("\n[!] Error: No AWS credentials found. Please configure AWS CLI credentials.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
