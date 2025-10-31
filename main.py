import json
import boto3
from modules.security_groups import check_open_security_groups

def main():
    session = boto3.Session(profile_name="vscodeuser", region_name="us-east-1")
    ec2 = session.client("ec2")
    findings = check_open_security_groups(ec2)
    print(json.dumps(findings, indent=2))

if __name__ == "__main__":
    main()
