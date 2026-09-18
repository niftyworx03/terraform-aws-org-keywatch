output "organization_id" {
  description = "The organization this trail covers."
  value       = data.aws_organizations_organization.current.id
}

output "covered_account_count" {
  description = "Accounts the organization trail logs today. New accounts are picked up automatically."
  value       = length(data.aws_organizations_organization.current.accounts)
}

output "alert_topic_arn" {
  description = "Topic both functions and all alarms publish to. The email subscription needs manual confirmation."
  value       = aws_sns_topic.alerts.arn
}

output "trail_log_group" {
  description = "CloudWatch Logs group receiving every account's management events."
  value       = aws_cloudwatch_log_group.trail.name
}

output "heartbeat_function_name" {
  description = "Invoke this manually to test without waiting for the top of the hour."
  value       = aws_lambda_function.heartbeat.function_name
}

output "alerter_function_name" {
  description = "Triggered by the subscription filter, not directly."
  value       = aws_lambda_function.alerter.function_name
}

output "guardduty_detector_id" {
  description = "Null unless create_guardduty_detector is true."
  value       = try(aws_guardduty_detector.this[0].id, null)
}

output "billable_components" {
  description = "What in this stack can actually cost money."
  value = {
    guardduty        = var.create_guardduty_detector ? "enabled, bills per account" : "disabled"
    s3_trail_storage = "pennies, bounded by trail_retention_days=${var.trail_retention_days}"
    everything_else  = "within always-free tiers"
  }
}
