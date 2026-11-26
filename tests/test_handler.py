import json
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from detector import handler

EVENTS = Path(__file__).parent / "events"


def load(name):
    return json.loads((EVENTS / f"{name}.json").read_text())


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-2")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        sns = boto3.client("sns")
        sqs = boto3.client("sqs")
        topic = sns.create_topic(Name="findings")["TopicArn"]
        queue_url = sqs.create_queue(QueueName="inbox")["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn)
        monkeypatch.setenv("SNS_TOPIC_ARN", topic)
        monkeypatch.setattr(handler, "_sns", None)

        def received():
            msgs = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10).get("Messages", [])
            return [json.loads(m["Body"]) for m in msgs]

        yield received


def test_finding_is_published_to_sns(aws):
    result = handler.lambda_handler(load("sg_open_ssh"))
    assert result["findings"] == ["EC2-001"]
    [msg] = aws()
    assert msg["Subject"].startswith("[CRITICAL] Security group opens SSH (22)")
    assert "sg-0123456789abcdef0" in msg["Message"]
    assert "arn:aws:iam::111122223333:user/dev" in msg["Message"]


def test_min_severity_filters_findings(aws, monkeypatch):
    monkeypatch.setenv("MIN_SEVERITY", "CRITICAL")
    assert handler.lambda_handler(load("s3_public_acl"))["findings"] == []
    assert aws() == []


def test_safe_event_publishes_nothing(aws):
    assert handler.lambda_handler(load("sg_open_https"))["findings"] == []
    assert aws() == []


def test_auto_remediation_revokes_open_ssh(aws, monkeypatch):
    monkeypatch.setenv("AUTO_REMEDIATE", "true")
    ec2 = boto3.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    perm = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[perm])

    event = load("sg_open_ssh")
    event["detail"]["requestParameters"]["groupId"] = sg
    handler.lambda_handler(event)

    rules = ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]["IpPermissions"]
    assert rules == []
    [msg] = aws()
    assert "Auto-remediation: revoked 1" in msg["Message"]


def test_auto_remediation_restores_block_public_access(aws, monkeypatch):
    monkeypatch.setenv("AUTO_REMEDIATE", "true")
    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="customer-data", CreateBucketConfiguration={"LocationConstraint": "eu-west-2"})
    handler.lambda_handler(load("s3_pab_deleted"))
    config = s3.get_public_access_block(Bucket="customer-data")["PublicAccessBlockConfiguration"]
    assert all(config.values())


def test_remediation_is_off_by_default(aws):
    handler.lambda_handler(load("s3_pab_deleted"))
    [msg] = aws()
    assert "Auto-remediation" not in msg["Message"]
