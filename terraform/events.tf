locals {
  # Keep this list in line with src/detector/rules.py (a unit test checks it).
  watched_events = [
    "AttachGroupPolicy",
    "AttachRolePolicy",
    "AttachUserPolicy",
    "AuthorizeSecurityGroupIngress",
    "ConsoleLogin",
    "CreateAccessKey",
    "CreateDBInstance",
    "DeleteBucketPublicAccessBlock",
    "DeleteFlowLogs",
    "DeleteTrail",
    "ModifyDBInstance",
    "PutBucketAcl",
    "PutBucketPolicy",
    "PutBucketPublicAccessBlock",
    "PutGroupPolicy",
    "PutRolePolicy",
    "PutUserPolicy",
    "StopLogging",
    "UpdateTrail",
  ]

  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
    detail = {
      eventName = local.watched_events
    }
  })

  forward_global_events = var.region != "us-east-1"
  home_bus_arn          = "arn:${data.aws_partition.current.partition}:events:${var.region}:${data.aws_caller_identity.current.account_id}:event-bus/default"
}

resource "aws_cloudwatch_event_rule" "risky_changes" {
  name          = "${var.name}-risky-changes"
  description   = "Risky configuration changes recorded by CloudTrail"
  event_pattern = local.event_pattern
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.risky_changes.name
  target_id = "detector"
  arn       = aws_lambda_function.detector.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 4
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.risky_changes.arn
}

# ------------------------------------------- us-east-1 -> home region forward

resource "aws_cloudwatch_event_rule" "global_forward" {
  count         = local.forward_global_events ? 1 : 0
  provider      = aws.us_east_1
  name          = "${var.name}-forward-global"
  description   = "Forward global-service events (IAM, sign-in) to ${var.region}"
  event_pattern = local.event_pattern
}

resource "aws_cloudwatch_event_target" "global_forward" {
  count     = local.forward_global_events ? 1 : 0
  provider  = aws.us_east_1
  rule      = aws_cloudwatch_event_rule.global_forward[0].name
  target_id = "home-region-bus"
  arn       = local.home_bus_arn
  role_arn  = aws_iam_role.forwarder[0].arn
}

data "aws_iam_policy_document" "events_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "forwarder" {
  count              = local.forward_global_events ? 1 : 0
  name               = "${var.name}-event-forwarder"
  assume_role_policy = data.aws_iam_policy_document.events_assume.json
}

resource "aws_iam_role_policy" "forwarder" {
  count = local.forward_global_events ? 1 : 0
  name  = "put-events-home-region"
  role  = aws_iam_role.forwarder[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "events:PutEvents"
      Resource = local.home_bus_arn
    }]
  })
}
