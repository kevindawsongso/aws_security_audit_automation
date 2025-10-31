"""Security group audit helpers."""

from __future__ import annotations

from typing import Any, Dict, List

from botocore.exceptions import ClientError


def check_open_security_groups(ec2_client) -> List[Dict[str, Any]]:
    """
    Return security group rules that expose resources to the world.

    The function scans all security groups in the caller's account/region and
    reports IPv4 (`0.0.0.0/0`) or IPv6 (`::/0`) rules.
    """
    findings: List[Dict[str, Any]] = []

    try:
        paginator = ec2_client.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                group_id = sg.get("GroupId")
                group_name = sg.get("GroupName")

                for rule in sg.get("IpPermissions", []):
                    proto = rule.get("IpProtocol", "All")
                    from_port = rule.get("FromPort", "All")
                    to_port = rule.get("ToPort", from_port)

                    for ipv4 in rule.get("IpRanges", []):
                        if ipv4.get("CidrIp") == "0.0.0.0/0":
                            findings.append(
                                {
                                    "group_id": group_id,
                                    "group_name": group_name,
                                    "ip_protocol": proto,
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "ip_version": "IPv4",
                                }
                            )

                    for ipv6 in rule.get("Ipv6Ranges", []):
                        if ipv6.get("CidrIpv6") == "::/0":
                            findings.append(
                                {
                                    "group_id": group_id,
                                    "group_name": group_name,
                                    "ip_protocol": proto,
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "ip_version": "IPv6",
                                }
                            )
    except ClientError as error:
        # Surface AWS errors to the caller; higher-level code can decide how to handle them.
        raise error

    return findings

