data "archive_file" "detector" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/detector.zip"
  excludes    = ["**/__pycache__/**"]
}

resource "aws_cloudwatch_log_group" "detector" {
  #checkov:skip=CKV_AWS_158:Logs hold findings only, no secrets; default encryption is used.
  #checkov:skip=CKV_AWS_338:Retention is configurable; 30 days is enough for a demo.
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "detector" {
  #checkov:skip=CKV_AWS_117:The function calls only public AWS APIs; a VPC adds NAT cost and no security benefit here.
  #checkov:skip=CKV_AWS_272:Code signing is out of scope for this demo.
  #checkov:skip=CKV_AWS_173:Environment variables hold no secrets.
  function_name                  = var.name
  description                    = "Checks CloudTrail API calls for risky configuration changes"
  role                           = aws_iam_role.detector.arn
  runtime                        = "python3.12"
  handler                        = "detector.handler.lambda_handler"
  filename                       = data.archive_file.detector.output_path
  source_code_hash               = data.archive_file.detector.output_base64sha256
  timeout                        = 30
  memory_size                    = 128
  reserved_concurrent_executions = 10

  environment {
    variables = {
      SNS_TOPIC_ARN  = aws_sns_topic.findings.arn
      MIN_SEVERITY   = var.min_severity
      AUTO_REMEDIATE = tostring(var.auto_remediate)
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.detector]
}

# Failed events (from EventBridge or from the async Lambda invoke) land here.
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name}-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = aws_kms_key.this.arn
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.risky_changes.arn } }
    }]
  })
}

resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${var.name}-errors"
  alarm_description   = "The detector Lambda failed. Findings may be missed."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.detector.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.findings.arn]
}

resource "aws_cloudwatch_metric_alarm" "dlq" {
  alarm_name          = "${var.name}-dlq-not-empty"
  alarm_description   = "Events are in the dead-letter queue. Check the Lambda logs."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.findings.arn]
}

# ------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "detector" {
  name               = "${var.name}-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "detector" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.detector.arn}:*"]
  }

  statement {
    sid       = "Publish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.findings.arn]
  }

  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }

  statement {
    sid       = "UseKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.this.arn]
  }

  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }

  # Only added when auto-remediation is on.
  dynamic "statement" {
    for_each = var.auto_remediate ? [1] : []
    content {
      sid       = "Remediate"
      actions   = ["ec2:RevokeSecurityGroupIngress", "s3:PutBucketPublicAccessBlock"]
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "detector" {
  name   = "detector"
  role   = aws_iam_role.detector.id
  policy = data.aws_iam_policy_document.detector.json
}
