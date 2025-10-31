"""
main.py — AWS Security Audit Orchestrator

This script runs selected AWS security checks and prints the results as JSON.
Modules currently supported:
  - Security Groups (EC2)
  - IAM MFA validation
  - S3 encryption and public access

You can control which checks run using CLI flags.
"""

import json
import argparse
import boto3
from modules.security_groups import check_open_security_groups
from modules.iam_checker import check_iam_mfa_status
from modules.s3_auditor import check_s3_encryption_and_public_access


def parse_args():
    """
    Parse command-line arguments so you can run individual checks easily.
    Example:
      python main.py --profile audit --region us-east-1 --include-s3 --pretty
    """
    parser = argparse.ArgumentParser(
        description="Run AWS Security Audit checks (SG, IAM, S3)."
    )

    # --- AWS connection options ---
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS CLI profile name (set up with `aws configure --profile <name>`)",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS region (e.g., us-east-1). S3 is global, others are regional.",
    )

    # --- Feature toggles ---
    parser.add_argument(
        "--include-iam", action="store_true", help="Include IAM MFA check"
    )
    parser.add_argument(
        "--include-s3",
        action="store_true",
        help="Include S3 encryption and public access checks",
    )
    parser.add_argument(
        "--pretty", action="store_true", help="Pretty-print JSON output"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # -------------------------------------------------------------------------
    # 🔐 AWS CREDENTIALS SECTION
    #
    # The safest way to provide credentials is via:
    #   1. AWS CLI profiles (`aws configure --profile audit`)
    #   2. Environment variables:
    #        export AWS_ACCESS_KEY_ID="YOUR_KEY"
    #        export AWS_SECRET_ACCESS_KEY="YOUR_SECRET"
    #        export AWS_REGION="us-east-1"
    #   3. IAM roles if running from EC2 / Lambda / Jenkins (no hardcoding needed)
    #
    # DO NOT hardcode credentials here.
    # -------------------------------------------------------------------------

    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    findings = []

    # --- EC2 Security Group checks ---
    ec2 = session.client("ec2")
    findings.extend(check_open_security_groups(ec2))

    # --- IAM MFA checks (optional) ---
    if args.include_iam:
        iam = session.client("iam")
        findings.extend(check_iam_mfa_status(iam))

    # --- S3 encryption & public access checks (optional) ---
    if args.include_s3:
        s3 = session.client("s3")
        findings.extend(check_s3_encryption_and_public_access(s3))

    # --- Output ---
    print(json.dumps(findings, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
