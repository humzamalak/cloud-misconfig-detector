"""Detection rules for risky AWS configuration changes.

Each rule takes one CloudTrail event (the ``detail`` object of an EventBridge
"AWS API Call via CloudTrail" event) and returns a ``Finding`` or ``None``.
Rules are pure functions: they do not call AWS. This keeps them easy to test.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# Ports that must never be open to the whole internet.
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    6379: "Redis",
    27017: "MongoDB",
}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
PUBLIC_S3_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    resource: str
    remediation: str
    event_name: str = ""
    actor: str = ""
    account: str = ""
    region: str = ""
    event_time: str = ""
    # Data a remediation action needs (for example the security group rule).
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


Rule = Callable[[dict[str, Any]], Finding | None]
RULES: dict[str, list[Rule]] = {}


def rule(*event_names: str) -> Callable[[Rule], Rule]:
    """Register a rule for one or more CloudTrail event names."""

    def wrap(fn: Rule) -> Rule:
        for name in event_names:
            RULES.setdefault(name, []).append(fn)
        return fn

    return wrap


def _params(detail: dict[str, Any]) -> dict[str, Any]:
    return detail.get("requestParameters") or {}


def _items(value: Any) -> list[Any]:
    """CloudTrail wraps lists as {"items": [...]}. Return the plain list."""
    if isinstance(value, dict):
        return value.get("items") or []
    if isinstance(value, list):
        return value
    return []


# ---------------------------------------------------------------- EC2 / VPC


@rule("AuthorizeSecurityGroupIngress")
def open_sensitive_port(detail: dict[str, Any]) -> Finding | None:
    params = _params(detail)
    group_id = params.get("groupId", "unknown")
    exposed: list[dict[str, Any]] = []
    for perm in _items(params.get("ipPermissions")):
        from_port = perm.get("fromPort")
        to_port = perm.get("toPort")
        protocol = str(perm.get("ipProtocol", ""))
        cidrs = [r.get("cidrIp") for r in _items(perm.get("ipRanges"))]
        cidrs += [r.get("cidrIpv6") for r in _items(perm.get("ipv6Ranges"))]
        open_cidrs = [c for c in cidrs if c in OPEN_CIDRS]
        if not open_cidrs:
            continue
        all_ports = protocol == "-1" or from_port is None
        for port, name in SENSITIVE_PORTS.items():
            if all_ports or (from_port <= port <= to_port):
                exposed.append({"port": port, "service": name, "cidrs": open_cidrs, "permission": perm})
    if not exposed:
        return None
    services = ", ".join(sorted({f"{e['service']} ({e['port']})" for e in exposed}))
    return Finding(
        rule_id="EC2-001",
        severity="CRITICAL" if any(e["port"] in (22, 3389) for e in exposed) else "HIGH",
        title=f"Security group opens {services} to the internet",
        resource=group_id,
        remediation="Remove the 0.0.0.0/0 or ::/0 rule. Use SSM Session Manager or a VPN instead of public SSH/RDP.",
        context={"group_id": group_id, "exposed": exposed},
    )


@rule("DeleteFlowLogs")
def flow_logs_deleted(detail: dict[str, Any]) -> Finding | None:
    # The request shape differs between API versions, so keep the raw parameters for the alert.
    return Finding(
        rule_id="EC2-002",
        severity="MEDIUM",
        title="VPC flow logs deleted",
        resource=json.dumps(_params(detail), sort_keys=True)[:200] or "unknown",
        remediation="Recreate the flow logs. Without them you cannot investigate network incidents.",
    )


# ---------------------------------------------------------------------- S3


@rule("DeleteBucketPublicAccessBlock")
def s3_public_access_block_removed(detail: dict[str, Any]) -> Finding | None:
    bucket = _params(detail).get("bucketName", "unknown")
    return Finding(
        rule_id="S3-001",
        severity="HIGH",
        title="S3 Block Public Access removed from bucket",
        resource=bucket,
        remediation="Turn Block Public Access back on for the bucket.",
        context={"bucket": bucket},
    )


@rule("PutBucketPublicAccessBlock")
def s3_public_access_block_weakened(detail: dict[str, Any]) -> Finding | None:
    params = _params(detail)
    bucket = params.get("bucketName", "unknown")
    config = params.get("PublicAccessBlockConfiguration") or {}
    keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    off = [k for k in keys if config.get(k) is False]
    if not off:
        return None
    return Finding(
        rule_id="S3-002",
        severity="HIGH",
        title=f"S3 Block Public Access weakened ({', '.join(off)} set to false)",
        resource=bucket,
        remediation="Set all four Block Public Access settings to true.",
        context={"bucket": bucket},
    )


@rule("PutBucketAcl")
def s3_public_acl(detail: dict[str, Any]) -> Finding | None:
    params = _params(detail)
    bucket = params.get("bucketName", "unknown")
    canned = params.get("x-amz-acl", [])
    canned = [canned] if isinstance(canned, str) else canned  # CloudTrail logs this header as a list
    public = any(str(c).lower() in ("public-read", "public-read-write", "authenticated-read") for c in canned)
    acl = params.get("AccessControlPolicy", {}).get("AccessControlList", {})
    grants = acl.get("Grant", [])
    if isinstance(grants, dict):
        grants = [grants]
    for grant in grants:
        uri = (grant.get("Grantee") or {}).get("URI")
        if uri in PUBLIC_S3_GRANTEES:
            public = True
    if not public:
        return None
    return Finding(
        rule_id="S3-003",
        severity="HIGH",
        title="S3 bucket ACL grants public access",
        resource=bucket,
        remediation="Set the bucket ACL to private and set Object Ownership to 'Bucket owner enforced'.",
        context={"bucket": bucket},
    )


@rule("PutBucketPolicy")
def s3_public_policy(detail: dict[str, Any]) -> Finding | None:
    params = _params(detail)
    bucket = params.get("bucketName", "unknown")
    policy = params.get("bucketPolicy") or {}
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            return None
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        principal = stmt.get("Principal")
        is_public = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"]))
        if stmt.get("Effect") == "Allow" and is_public and not stmt.get("Condition"):
            return Finding(
                rule_id="S3-004",
                severity="HIGH",
                title="S3 bucket policy allows access by anyone (Principal '*', no condition)",
                resource=bucket,
                remediation="Restrict the Principal, or add a condition such as aws:SourceArn or aws:PrincipalOrgID.",
                context={"bucket": bucket},
            )
    return None


# --------------------------------------------------------------------- IAM


@rule("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy")
def admin_policy_attached(detail: dict[str, Any]) -> Finding | None:
    params = _params(detail)
    arn = params.get("policyArn", "")
    if arn not in ADMIN_POLICY_ARNS:
        return None
    target = params.get("userName") or params.get("roleName") or params.get("groupName") or "unknown"
    return Finding(
        rule_id="IAM-001",
        severity="HIGH",
        title=f"Privileged managed policy {arn.rsplit('/', 1)[-1]} attached",
        resource=target,
        remediation="Confirm the change was approved. Prefer least-privilege policies scoped to the task.",
    )


@rule("PutUserPolicy", "PutRolePolicy", "PutGroupPolicy")
def wildcard_inline_policy(detail: dict[str, Any]) -> Finding | None:
    params = _params(detail)
    doc = params.get("policyDocument") or {}
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return None
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if stmt.get("Effect") == "Allow" and "*" in actions and "*" in resources:
            target = params.get("userName") or params.get("roleName") or params.get("groupName") or "unknown"
            return Finding(
                rule_id="IAM-002",
                severity="CRITICAL",
                title="Inline policy allows Action '*' on Resource '*'",
                resource=target,
                remediation="Replace the inline policy with a least-privilege policy.",
            )
    return None


@rule("CreateAccessKey")
def root_access_key(detail: dict[str, Any]) -> Finding | None:
    if (detail.get("userIdentity") or {}).get("type") != "Root":
        return None
    return Finding(
        rule_id="IAM-003",
        severity="CRITICAL",
        title="Access key created for the root user",
        resource="root",
        remediation="Delete the root access key now. Use IAM Identity Center or IAM roles instead.",
    )


@rule("ConsoleLogin")
def console_login_without_mfa(detail: dict[str, Any]) -> Finding | None:
    extra = detail.get("additionalEventData") or {}
    result = (detail.get("responseElements") or {}).get("ConsoleLogin")
    if result != "Success" or extra.get("MFAUsed") != "No":
        return None
    # SSO and federated sign-ins report MFAUsed "No" because MFA is checked by the identity provider.
    if (detail.get("userIdentity") or {}).get("type") not in ("Root", "IAMUser"):
        return None
    is_root = (detail.get("userIdentity") or {}).get("type") == "Root"
    return Finding(
        rule_id="IAM-004",
        severity="CRITICAL" if is_root else "MEDIUM",
        title=("Root" if is_root else "IAM user") + " console sign-in without MFA",
        resource=(detail.get("userIdentity") or {}).get("arn", "unknown"),
        remediation="Turn on MFA for this identity. Add an IAM policy that denies actions without MFA.",
    )


# -------------------------------------------------------------- CloudTrail


@rule("StopLogging", "DeleteTrail")
def cloudtrail_disabled(detail: dict[str, Any]) -> Finding | None:
    name = _params(detail).get("name", "unknown")
    return Finding(
        rule_id="CT-001",
        severity="CRITICAL",
        title=f"CloudTrail logging stopped ({detail.get('eventName')})",
        resource=name,
        remediation="Start logging again. Treat this as a possible attempt to hide activity and review recent events.",
        context={"trail": name},
    )


@rule("UpdateTrail")
def cloudtrail_weakened(detail: dict[str, Any]) -> Finding | None:
    params = _params(detail)
    issues = []
    if params.get("isMultiRegionTrail") is False:
        issues.append("multi-region turned off")
    if params.get("enableLogFileValidation") is False:
        issues.append("log file validation turned off")
    if params.get("kmsKeyId") == "":
        issues.append("KMS encryption removed")
    if not issues:
        return None
    return Finding(
        rule_id="CT-002",
        severity="HIGH",
        title="CloudTrail trail weakened: " + ", ".join(issues),
        resource=params.get("name", "unknown"),
        remediation="Restore multi-region logging, log file validation and KMS encryption.",
    )


# --------------------------------------------------------------------- RDS


@rule("CreateDBInstance", "ModifyDBInstance")
def rds_public(detail: dict[str, Any]) -> Finding | None:
    params = _params(detail)
    if params.get("publiclyAccessible") is not True:
        return None
    return Finding(
        rule_id="RDS-001",
        severity="HIGH",
        title="RDS instance set to publicly accessible",
        resource=params.get("dBInstanceIdentifier", "unknown"),
        remediation="Set PubliclyAccessible to false and reach the database from inside the VPC.",
    )


# ------------------------------------------------------------------ public


def evaluate(detail: dict[str, Any]) -> list[Finding]:
    """Run every rule registered for the event name. Skip failed API calls."""
    if detail.get("errorCode"):
        return []
    findings = []
    for fn in RULES.get(detail.get("eventName", ""), []):
        finding = fn(detail)
        if finding is None:
            continue
        identity = detail.get("userIdentity") or {}
        finding.event_name = detail.get("eventName", "")
        finding.actor = identity.get("arn") or identity.get("principalId") or "unknown"
        finding.account = detail.get("recipientAccountId", "")
        finding.region = detail.get("awsRegion", "")
        finding.event_time = detail.get("eventTime", "")
        findings.append(finding)
    return findings


def watched_events() -> list[str]:
    return sorted(RULES)
