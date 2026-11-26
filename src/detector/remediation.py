"""Optional automatic fixes. Off by default (AUTO_REMEDIATE=false).

Only two safe, reversible fixes are implemented:
  EC2-001  revoke the internet-facing ingress rule that was just added
  S3-001/2/3  turn S3 Block Public Access back on for the bucket
Everything else is alert-only, because an automatic change to IAM or
CloudTrail can lock people out or break production.
"""

from __future__ import annotations

import logging

import boto3
from botocore.exceptions import ClientError

from detector.rules import Finding

logger = logging.getLogger(__name__)


def _revoke_open_ingress(finding: Finding) -> str:
    ec2 = boto3.client("ec2", region_name=finding.region or None)
    group_id = finding.context["group_id"]
    revoked = []
    for item in finding.context["exposed"]:
        perm = item["permission"]
        ip_perm = {"IpProtocol": str(perm.get("ipProtocol"))}
        if perm.get("fromPort") is not None:
            ip_perm["FromPort"] = perm["fromPort"]
            ip_perm["ToPort"] = perm["toPort"]
        v4 = [c for c in item["cidrs"] if ":" not in c]
        v6 = [c for c in item["cidrs"] if ":" in c]
        if v4:
            ip_perm["IpRanges"] = [{"CidrIp": c} for c in v4]
        if v6:
            ip_perm["Ipv6Ranges"] = [{"CidrIpv6": c} for c in v6]
        key = str(ip_perm)
        if key in revoked:
            continue
        ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[ip_perm])
        revoked.append(key)
    return f"revoked {len(revoked)} internet-facing rule(s) on {group_id}"


def _block_public_access(finding: Finding) -> str:
    s3 = boto3.client("s3")
    bucket = finding.context["bucket"]
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return f"Block Public Access turned on for {bucket}"


ACTIONS = {
    "EC2-001": _revoke_open_ingress,
    "S3-001": _block_public_access,
    "S3-002": _block_public_access,
    "S3-003": _block_public_access,
}


def apply(finding: Finding) -> str | None:
    action = ACTIONS.get(finding.rule_id)
    if action is None:
        return None
    try:
        return action(finding)
    except ClientError as exc:
        logger.error("remediation failed for %s: %s", finding.rule_id, exc)
        return f"FAILED: {exc.response.get('Error', {}).get('Code', 'unknown error')}"
