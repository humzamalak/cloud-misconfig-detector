import json
from pathlib import Path

import pytest

from detector.rules import evaluate, watched_events

EVENTS = Path(__file__).parent / "events"


def load(name):
    return json.loads((EVENTS / f"{name}.json").read_text())["detail"]


@pytest.mark.parametrize(
    "event, rule_id, severity",
    [
        ("sg_open_ssh", "EC2-001", "CRITICAL"),
        ("sg_all_traffic_v6", "EC2-001", "CRITICAL"),
        ("s3_pab_deleted", "S3-001", "HIGH"),
        ("s3_public_acl", "S3-003", "HIGH"),
        ("s3_public_policy", "S3-004", "HIGH"),
        ("iam_admin_attached", "IAM-001", "HIGH"),
        ("iam_wildcard_inline", "IAM-002", "CRITICAL"),
        ("root_access_key", "IAM-003", "CRITICAL"),
        ("root_login_no_mfa", "IAM-004", "CRITICAL"),
        ("cloudtrail_stopped", "CT-001", "CRITICAL"),
        ("rds_public", "RDS-001", "HIGH"),
    ],
)
def test_risky_events_raise_a_finding(event, rule_id, severity):
    findings = evaluate(load(event))
    assert [f.rule_id for f in findings] == [rule_id]
    assert findings[0].severity == severity
    assert findings[0].account == "111122223333"
    assert findings[0].actor


def test_https_open_to_internet_is_not_a_finding():
    assert evaluate(load("sg_open_https")) == []


def test_failed_api_calls_are_ignored():
    assert evaluate(load("failed_call")) == []


def test_unknown_event_is_ignored():
    assert evaluate({"eventName": "DescribeInstances"}) == []


def test_port_range_covering_ssh_is_detected():
    detail = load("sg_open_ssh")
    perm = detail["requestParameters"]["ipPermissions"]["items"][0]
    perm["fromPort"], perm["toPort"] = 0, 1024
    assert evaluate(detail)[0].rule_id == "EC2-001"


def test_private_cidr_is_not_a_finding():
    detail = load("sg_open_ssh")
    detail["requestParameters"]["ipPermissions"]["items"][0]["ipRanges"]["items"][0]["cidrIp"] = "10.0.0.0/8"
    assert evaluate(detail) == []


def test_bucket_policy_with_condition_is_not_a_finding():
    detail = load("s3_public_policy")
    detail["requestParameters"]["bucketPolicy"]["Statement"][0]["Condition"] = {
        "StringEquals": {"aws:PrincipalOrgID": "o-example"}
    }
    assert evaluate(detail) == []


def test_sso_login_is_not_flagged():
    detail = load("root_login_no_mfa")
    detail["userIdentity"] = {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_x/me",
    }
    assert evaluate(detail) == []


def test_pab_partially_disabled():
    detail = {
        "eventName": "PutBucketPublicAccessBlock",
        "requestParameters": {
            "bucketName": "b",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True,
            },
        },
    }
    assert evaluate(detail)[0].rule_id == "S3-002"


def test_watched_events_match_eventbridge_rule():
    """Every event the rules handle must be in the EventBridge pattern in Terraform."""
    tf = (Path(__file__).parents[1] / "terraform" / "events.tf").read_text()
    missing = [name for name in watched_events() if f'"{name}"' not in tf]
    assert missing == []


def test_trail_weakened():
    detail = {
        "eventName": "UpdateTrail",
        "requestParameters": {"name": "org-trail", "isMultiRegionTrail": False, "enableLogFileValidation": False},
    }
    [finding] = evaluate(detail)
    assert finding.rule_id == "CT-002"
    assert "multi-region" in finding.title and "validation" in finding.title


def test_trail_update_without_weakening_is_ignored():
    assert evaluate({"eventName": "UpdateTrail", "requestParameters": {"name": "t", "isMultiRegionTrail": True}}) == []


def test_flow_logs_deleted():
    detail = {"eventName": "DeleteFlowLogs", "requestParameters": {"flowLogIds": ["fl-1"]}}
    assert evaluate(detail)[0].rule_id == "EC2-002"


def test_scoped_policy_is_not_flagged():
    detail = {
        "eventName": "AttachRolePolicy",
        "requestParameters": {"roleName": "app", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
    }
    assert evaluate(detail) == []


def test_scoped_inline_policy_is_not_flagged():
    doc = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}]}
    assert evaluate({"eventName": "PutUserPolicy", "requestParameters": {"userName": "u", "policyDocument": doc}}) == []


def test_iam_user_login_without_mfa_is_medium():
    detail = {
        "eventName": "ConsoleLogin",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/dev"},
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
    }
    assert evaluate(detail)[0].severity == "MEDIUM"


def test_non_root_access_key_is_not_flagged():
    assert evaluate({"eventName": "CreateAccessKey", "userIdentity": {"type": "IAMUser"}}) == []


def test_private_rds_is_not_flagged():
    assert evaluate({"eventName": "CreateDBInstance", "requestParameters": {"publiclyAccessible": False}}) == []
