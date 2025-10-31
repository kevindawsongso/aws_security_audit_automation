# modules/iam_checker.py
from typing import List, Dict
from botocore.exceptions import ClientError

def check_iam_mfa_status(iam_client) -> List[Dict]:
    """
    Returns a list of findings for IAM users without an MFA device.
    """
    findings: List[Dict] = []
    try:
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                try:
                    mfa = iam_client.list_mfa_devices(UserName=username)
                    if not mfa.get("MFADevices"):
                        findings.append({
                            "Type": "IAM No MFA",
                            "Service": "IAM",
                            "Resource": username,
                            "Severity": "MEDIUM",
                            "Description": f"User {username} does not have MFA configured"
                        })
                except ClientError as ce:
                    findings.append({
                        "Type": "Error",
                        "Service": "IAM",
                        "Resource": username,
                        "Severity": "LOW",
                        "Description": f"Error checking MFA for {username}: {ce}"
                    })
    except ClientError as e:
        findings.append({
            "Type": "Error",
            "Service": "IAM",
            "Resource": "ListUsers",
            "Severity": "LOW",
            "Description": f"Error listing IAM users: {e}"
        })
    return findings
