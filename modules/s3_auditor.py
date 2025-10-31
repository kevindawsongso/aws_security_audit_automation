# modules/s3_auditor.py
from typing import List, Dict
from botocore.exceptions import ClientError

def _bucket_public_via_acl(acl: dict) -> bool:
    """
    Returns True if the ACL grants access to AllUsers or AuthenticatedUsers.
    """
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        # AWS uses well-known group URIs that end with AllUsers / AuthenticatedUsers
        if uri.endswith("AllUsers") or uri.endswith("AuthenticatedUsers"):
            return True
    return False

def check_s3_encryption_and_public_access(s3_client) -> List[Dict]:
    """
    Produces findings for:
      - Buckets without default server-side encryption
      - Buckets missing/weak Public Access Block configuration
      - Buckets publicly exposed via ACL
      - (Informational) Buckets that have a bucket policy (flag to review)
    """
    findings: List[Dict] = []
    try:
        buckets = s3_client.list_buckets().get("Buckets", [])
    except ClientError as e:
        findings.append({
            "Type": "Error",
            "Service": "S3",
            "Resource": "list_buckets",
            "Severity": "LOW",
            "Description": f"Error listing buckets: {e}",
        })
        return findings

    for b in buckets:
        name = b["Name"]

        # 1) Default encryption
        try:
            s3_client.get_bucket_encryption(Bucket=name)
        except getattr(s3_client, "exceptions", object()).ServerSideEncryptionConfigurationNotFoundError:  # type: ignore[attr-defined]
            findings.append({
                "Type": "Unencrypted S3 Bucket",
                "Service": "S3",
                "Resource": name,
                "Severity": "HIGH",
                "Description": f"Bucket {name} has no default server-side encryption",
            })
        except ClientError as ce:
            findings.append({
                "Type": "Error",
                "Service": "S3",
                "Resource": name,
                "Severity": "LOW",
                "Description": f"Error reading encryption for {name}: {ce}",
            })

        # 2) Public Access Block (PAB)
        try:
            pab = s3_client.get_public_access_block(Bucket=name)
            cfg = pab.get("PublicAccessBlockConfiguration", {})
            all_on = all([
                cfg.get("BlockPublicAcls"),
                cfg.get("IgnorePublicAcls"),
                cfg.get("BlockPublicPolicy"),
                cfg.get("RestrictPublicBuckets"),
            ])
            if not all_on:
                findings.append({
                    "Type": "Weak Public Access Block",
                    "Service": "S3",
                    "Resource": name,
                    "Severity": "HIGH",
                    "Description": f"Bucket {name} PublicAccessBlock is not fully enabled",
                })
        except ClientError:
            # No PAB set is risky by default
            findings.append({
                "Type": "No Public Access Block",
                "Service": "S3",
                "Resource": name,
                "Severity": "HIGH",
                "Description": f"Bucket {name} has no PublicAccessBlock configuration",
            })

        # 3) ACL exposure
        try:
            acl = s3_client.get_bucket_acl(Bucket=name)
            if _bucket_public_via_acl(acl):
                findings.append({
                    "Type": "Public S3 Bucket (ACL)",
                    "Service": "S3",
                    "Resource": name,
                    "Severity": "CRITICAL",
                    "Description": f"Bucket {name} ACL grants public access",
                })
        except ClientError as ce:
            findings.append({
                "Type": "Error",
                "Service": "S3",
                "Resource": name,
                "Severity": "LOW",
                "Description": f"Error reading ACL for {name}: {ce}",
            })

        # 4) Bucket policy present (flag for manual review)
        try:
            s3_client.get_bucket_policy(Bucket=name)
            findings.append({
                "Type": "Bucket Policy Present",
                "Service": "S3",
                "Resource": name,
                "Severity": "LOW",
                "Description": f"Bucket {name} has a policy — review for wildcards/public principals",
            })
        except ClientError:
            # No policy is fine; skip
            pass

    return findings
