resource "aws_sns_topic" "findings" {
  name              = "${var.name}-findings"
  kms_master_key_id = aws_kms_key.this.arn
}

resource "aws_sns_topic_policy" "findings" {
  arn = aws_sns_topic.findings.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "CloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.findings.arn
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.findings.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
