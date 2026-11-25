"""Lambda entry point: EventBridge (CloudTrail API call) -> rules -> SNS.

Environment variables:
  SNS_TOPIC_ARN    topic that receives findings (required)
  MIN_SEVERITY     LOW | MEDIUM | HIGH | CRITICAL (default MEDIUM)
  AUTO_REMEDIATE   "true" to undo some changes automatically (default "false")
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3

from detector import remediation
from detector.rules import SEVERITY_ORDER, Finding, evaluate

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

_sns = None


def _sns_client():
    global _sns
    if _sns is None:
        _sns = boto3.client("sns")
    return _sns


def _format(finding: Finding, remediated: str | None) -> tuple[str, str]:
    subject = f"[{finding.severity}] {finding.title}"[:100]
    lines = [
        f"Rule:        {finding.rule_id}",
        f"Severity:    {finding.severity}",
        f"Finding:     {finding.title}",
        f"Resource:    {finding.resource}",
        f"API call:    {finding.event_name}",
        f"Actor:       {finding.actor}",
        f"Account:     {finding.account}",
        f"Region:      {finding.region}",
        f"Time (UTC):  {finding.event_time}",
        "",
        f"Fix:         {finding.remediation}",
    ]
    if remediated:
        lines += ["", f"Auto-remediation: {remediated}"]
    return subject, "\n".join(lines)


def lambda_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    detail = event.get("detail") or {}
    min_level = SEVERITY_ORDER.get(os.environ.get("MIN_SEVERITY", "MEDIUM").upper(), 2)
    auto = os.environ.get("AUTO_REMEDIATE", "false").lower() == "true"
    topic = os.environ["SNS_TOPIC_ARN"]

    findings = [f for f in evaluate(detail) if SEVERITY_ORDER[f.severity] >= min_level]
    published = []
    for finding in findings:
        remediated = remediation.apply(finding) if auto else None
        subject, message = _format(finding, remediated)
        _sns_client().publish(
            TopicArn=topic,
            Subject=subject,
            Message=message,
            MessageAttributes={
                "severity": {"DataType": "String", "StringValue": finding.severity},
                "rule_id": {"DataType": "String", "StringValue": finding.rule_id},
            },
        )
        # Structured log line: query it with CloudWatch Logs Insights.
        logger.info(json.dumps({"finding": finding.to_dict(), "remediated": remediated}, default=str))
        published.append(finding.rule_id)

    return {"event": detail.get("eventName"), "findings": published}
