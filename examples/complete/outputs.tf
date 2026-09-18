output "organization_id" {
  description = "The organization the trail covers."
  value       = module.keywatch.organization_id
}

output "covered_account_count" {
  description = "Accounts logging into the trail today. New accounts join automatically."
  value       = module.keywatch.covered_account_count
}

output "alert_topic_arn" {
  description = "Topic carrying both alerts and the digest."
  value       = module.keywatch.alert_topic_arn
}

output "trail_log_group" {
  description = "Log group receiving every account's management events."
  value       = module.keywatch.trail_log_group
}

output "heartbeat_function_name" {
  description = "Invoke this to test the digest without waiting for the hour."
  value       = module.keywatch.heartbeat_function_name
}

output "alerter_function_name" {
  description = "Invoked by the subscription filter rather than directly."
  value       = module.keywatch.alerter_function_name
}

output "billable_components" {
  description = "What in this stack can cost money."
  value       = module.keywatch.billable_components
}
