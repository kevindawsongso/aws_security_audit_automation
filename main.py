# main.py
import json
import argparse
import boto3
from modules.security_groups import check_open_security_groups
from modules.iam_checker import check_iam_mfa_status  # keep if you already added it
from modules.s3_auditor import check_s3_encryption_and_public_access

def parse_args():
    p = argparse.ArgumentParser(description="AWS security audit (SG + optional IAM + optional S3).")
    p.add_argument("--profile", default=None, help="AWS profile name")
    p.add_argument("--region", default=None, help="AWS region (affects EC2/IAM; S3 is global)")
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    p.add_argument("--include-iam", action="store_true", help="Also check IAM MFA status")
    p.add_argument("--include-s3", action="store_true", help="Also check S3 encryption/public access")
    return p.parse_args()

def main():
    a = parse_args()
    session = boto3.Session(profile_name=a.profile, region_name=a.region)

    findings = []

    # Security Groups
    ec2 = session.client("ec2")
    findings.extend(check_open_security_groups(ec2))

    # IAM (optional)
    if a.include_iam:
        iam = session.client("iam")
        findings.extend(check_iam_mfa_status(iam))

    # S3 (optional)
    if a.include_s3:
        s3 = session.client("s3")
        findings.extend(check_s3_encryption_and_public_access(s3))

    print(json.dumps(findings, indent=2 if a.pretty else None))

if __name__ == "__main__":
    main()
