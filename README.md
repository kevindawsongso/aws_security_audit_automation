# AWS Security Audit Automation

A Python-based tool that automates auditing of AWS resources for security misconfigurations.  
It scans for open Security Groups, missing IAM MFA, unencrypted or public S3 buckets, and missing EC2 tags — then generates detailed JSON and CSV reports for analysis.

---

## 🚀 Overview

Manual AWS security reviews are slow and error-prone.  
This project automates common audit checks using **Boto3**, giving quick insight into security posture across your AWS environment.

The script uses modular checks for:
- **Security Groups** — detect rules exposing ports to the internet  
- **IAM Users** — identify users without MFA  
- **S3 Buckets** — find unencrypted or publicly accessible storage  
- **EC2 Instances** — validate required tag compliance  

All findings are consolidated into timestamped reports under the `reports/` directory.

---

## 🧩 Project Structure

aws-security-auditor/
├── main.py # Main orchestrator
├── modules/
│ ├── security_groups.py # Security Group checks
│ ├── iam_checker.py # IAM MFA status
│ ├── s3_auditor.py # S3 encryption/public access checks
│ └── tag_validator.py # EC2 tag compliance
├── reports/ # Output directory (JSON/CSV)
├── requirements.txt
└── README.md

markdown
Copy code

---

## ⚙️ Prerequisites

- Python 3.8 or higher  
- AWS account with **programmatic access**  
- AWS CLI configured with credentials (e.g. `vscodeuser` profile)  
- Read-only permissions for:
  - EC2 (`DescribeSecurityGroups`)
  - IAM (`ListUsers`, `GetUser`, `ListMFADevices`)
  - S3 (`ListBuckets`, `GetBucketEncryption`, `GetBucketAcl`)
  - SecurityHub (`GetFindings` optional)