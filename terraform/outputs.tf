output "sns_topic_arn" {
  description = "Subscribe more endpoints (Slack via Chatbot, SMS, HTTPS) to this topic."
  value       = aws_sns_topic.findings.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.detector.function_name
}

output "event_rule_name" {
  value = aws_cloudwatch_event_rule.risky_changes.name
}

output "dlq_url" {
  value = aws_sqs_queue.dlq.url
}

output "trail_name" {
  value = var.create_trail ? aws_cloudtrail.this[0].name : null
}
