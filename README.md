# AWS CloudWatch Log Retention Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)](https://www.python.org/)
[![AWS: CloudWatch Logs](https://img.shields.io/badge/AWS-CloudWatch%20Logs-orange.svg)](https://aws.amazon.com/cloudwatch/)

An automated FinOps and operational governance tool to audit, estimate waste, and enforce customizable retention policies across AWS CloudWatch Log Groups. 

Eliminates the silent, compounding storage costs caused by AWS's default **"Never Expire"** log retention policy.

---

## The Problem: The "Never Expire" Trap

Whenever AWS services (AWS Lambda, Amazon ECS, Amazon EKS, API Gateway, AWS CodeBuild, or RDS) write logs, AWS automatically creates a CloudWatch Log Group with **Retention: Never Expire**.

```
Lambda Invocation / ECS Task ──► Creates Log Group ──► Default: Never Expire ──► Storage Bills Grow Indefinitely
```

- **CloudWatch Logs Storage:** Costs **$0.03/GB/month** ($0.36/GB/year) in standard regions.
- **The Compounding Effect:** Unlike runaway compute that spikes overnight, log storage ticks up monotonically month after month. In an active microservices architecture with hundreds of Lambdas and containers, 10 TB of stale logs silently bleeds **$3,600+ every year** for data nobody ever reads again.
- **The API Gotcha:** The AWS `PutRetentionPolicy` API only accepts discrete integer tiers (`[1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, ...]` days). Supplying an arbitrary number like 10 or 45 throws an `InvalidParameterValueException`.

This repository provides two complementary solutions:
1. **CLI Tool (`cli/set_log_retention.py`):** Audit existing log groups, preview storage waste, select custom retention windows, and remediate in bulk with safety dry-runs.
2. **Serverless Auto-Enforcer (`serverless/`):** An EventBridge rule + Lambda function that automatically applies retention to any new log group the moment it is created.

---

## Features

- **Customizable Retention Window:** Set whatever retention period suits your organization (e.g. 7 days for dev/lambdas, 30 days for staging, 90 days for prod).
- **AWS Tier Validation:** Automatically validates and snaps retention inputs to supported AWS CloudWatch API tiers.
- **Dry-Run by Default:** Inspect what will change and preview storage savings before modifying any AWS resources.
- **Scope & Prefix Filtering:** Target specific prefixes (e.g., `--prefix /aws/lambda/`) or audit all log groups across accounts and regions.
- **FinOps Savings Estimation:** Calculates total stored gigabytes and annualized cost reductions.
- **Multiple Output Formats:** Formats audit findings in human-readable console tables, CSV, or JSON.
- **Proactive Governance:** Includes a serverless SAM template to catch and remediate newly created log groups via CloudTrail events.

---

## Recommended Retention Tiers by Environment

| Workload / Environment | Recommended Retention | Rationale |
|---|---|---|
| **Development & Sandbox** | `7 days` | Ephemeral debugging; stack traces are irrelevant after a week. |
| **Serverless Lambda Functions** | `7 – 14 days` | High volume, low utility after initial troubleshooting. |
| **Staging & QA Environments** | `14 – 30 days` | Sufficient window for sprint regression testing. |
| **Production Application Logs** | `30 – 90 days` | Covers standard incident response and monthly audit cycles. |
| **Long-Term Compliance (SOC2 / HIPAA)** | `365+ days` | **Do not keep in CloudWatch!** Stream via Kinesis Firehose to S3 Glacier for a **90%+ cost drop**. |

---

## Quickstart

### 1. Installation

```bash
git clone https://github.com/your-username/aws-log-retention-manager.git
cd aws-log-retention-manager
pip install -r requirements.txt
```

### 2. Dry-Run Audit (Preview Only)

Scan all log groups with `Never Expire` in your default region with a proposed 7-day retention:

```bash
python cli/set_log_retention.py
```

### 3. Specify Custom Retention Days

Choose the exact retention window that fits your policy (e.g. 14 days, 30 days, 90 days):

```bash
# Preview 14 days retention
python cli/set_log_retention.py --days 14

# Preview 30 days retention on Lambda functions only
python cli/set_log_retention.py --days 30 --prefix /aws/lambda/
```

### 4. Apply Changes

Once you are satisfied with the preview, append `--apply`:

```bash
python cli/set_log_retention.py --days 14 --apply
```

### 5. Multi-Profile / Multi-Region Usage

```bash
python cli/set_log_retention.py --profile prod --region us-east-1 --days 30 --apply --output audit.csv
```

---

## CLI Options Reference

| Flag | Short | Default | Description |
|---|---|---|---|
| `--days` | `-d` | `7` | Retention period in days (e.g., 1, 3, 5, 7, 14, 30, 60, 90, 180, 365). |
| `--apply` | | `False` | Actually applies changes in AWS. Default is safe DRY RUN. |
| `--prefix` | `-p` | `None` | Restrict audit to log groups matching this prefix (e.g. `/aws/lambda/`). |
| `--all` | | `False` | Updates all matching groups, even if retention is already set. |
| `--region` | `-r` | `ap-south-1` | AWS region to scan. |
| `--profile` | | `None` | AWS CLI profile to use. |
| `--output` | `-o` | `None` | Path to export findings (.csv or .json). |

---

## Proactive Governance: Serverless Auto-Enforcer

To stop future log groups from ever being created with `Never Expire`, deploy the included AWS SAM template:

```bash
cd serverless
sam build
sam deploy --guided
```

This deploys an Amazon EventBridge rule that intercepts `CreateLogGroup` CloudTrail API calls and immediately applies your chosen retention policy (`DefaultRetentionDays`, e.g. 14 days) via Lambda.

---

## Architecture Diagram

```mermaid
flowchart TD
    subgraph Reactive Remediation (CLI)
        A[DevOps / FinOps Engineer] -->|Runs with --days N| B[set_log_retention.py]
        B -->|DescribeLogGroups| C[AWS CloudWatch Logs]
        B -->|PutRetentionPolicy (Validated Tiers)| C
        B -->|Outputs| D[CSV / JSON / Console Summary]
    end

    subgraph Proactive Remediation (Serverless)
        E[AWS Service: Lambda / ECS / API GW] -->|Auto-creates Log Group| C
        C -->|CreateLogGroup Event| F[AWS CloudTrail]
        F -->|Rule Match| G[Amazon EventBridge]
        G -->|Triggers| H[Auto-Enforcer Lambda]
        H -->|PutRetentionPolicy| C
    end
```

---

## License

This project is licensed under the [MIT License](LICENSE).
Author: **Yash Trivedi**
