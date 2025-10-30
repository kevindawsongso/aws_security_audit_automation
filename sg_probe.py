# sg_probe.py
import boto3
from botocore.exceptions import ClientError

PROFILE = "vscodeuser"       # change if you used a different profile
REGION  = "us-east-1"   # change if your stuff lives elsewhere

def main():
    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    ec2 = session.client("ec2")
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        open_findings = []
        total = 0

        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                total += 1
                gid = sg.get("GroupId")
                name = sg.get("GroupName")

                for rule in sg.get("IpPermissions", []):
                    proto = rule.get("IpProtocol", "All")
                    fp = rule.get("FromPort", "All")
                    tp = rule.get("ToPort", fp)

                    for r4 in rule.get("IpRanges", []):
                        if r4.get("CidrIp") == "0.0.0.0/0":
                            open_findings.append((gid, name, proto, fp, tp, "IPv4"))

                    for r6 in rule.get("Ipv6Ranges", []):
                        if r6.get("CidrIpv6") == "::/0":
                            open_findings.append((gid, name, proto, fp, tp, "IPv6"))

        print(f"Security groups scanned: {total}")
        if not open_findings:
            print("No world-open rules found. Nice.")
        else:
            print("World-open rules:")
            for gid, name, proto, fp, tp, fam in open_findings:
                port = f"{fp}-{tp}" if fp != tp else fp
                print(f"  {gid} ({name}) | {fam} | proto={proto} port={port}")

    except ClientError as e:
        print(f"AWS error: {e}")

if __name__ == "__main__":
    main()
