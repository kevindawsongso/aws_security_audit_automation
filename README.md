# AWS Security Audit Automation

A Python-based tool that automates auditing of AWS resources for common security misconfigurations.  
It identifies open Security Groups, missing IAM MFA, unencrypted or public S3 buckets, and missing EC2 tags.  
Results are exported to both JSON and CSV for analysis or further automation.

---

## Overview

This project streamlines AWS security reviews by using Boto3 to gather configuration data directly from your AWS environment.  
Each module performs a specific audit and returns standardized findings that can be aggregated into a comprehensive security report.