variable "alert_email" {
  description = "Inbox that receives sensitive-call alerts and the hourly digest. Do not commit this."
  type        = string
}

variable "monitored_access_key_ids" {
  description = <<-EOT
    Long-lived access key IDs to narrow alerting to, across any account in the
    organization. Leave empty to cover every principal, which is the right
    default when you own all the accounts.
  EOT
  type        = list(string)
  default     = []
}

variable "dangerous_event_names" {
  description = <<-EOT
    CloudTrail eventNames that alert immediately rather than waiting for the
    hourly digest. Four families: identity persistence and privilege escalation,
    anti-forensics, organization-level change, and anything that costs money or
    exposes data.

    This list is evaluated in the Lambda, not in the subscription filter,
    because CloudWatch Logs caps filter patterns at 1024 characters.
  EOT
  type        = list(string)
  default = [
    # Persistence and privilege escalation
    "CreateUser",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "AttachUserPolicy",
    "PutUserPolicy",
    "CreateRole",
    "AttachRolePolicy",
    "PutRolePolicy",
    "UpdateAssumeRolePolicy",
    "AddUserToGroup",
    "CreatePolicyVersion",
    "DeactivateMFADevice",
    "UpdateAccountPasswordPolicy",

    # Anti-forensics: blinding the controls this stack depends on
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
    "DeleteDetector",
    "UpdateDetector",
    "DeleteFlowLogs",
    "DeleteLogGroup",
    "DeleteSubscriptionFilter",
    "StopConfigurationRecorder",

    # Organization-level changes, only meaningful in a multi-account setup
    "LeaveOrganization",
    "RemoveAccountFromOrganization",
    "DeletePolicy",
    "DetachPolicy",

    # Cost and data exposure
    "RunInstances",
    "RequestSpotInstances",
    "CreateKeyPair",
    "CreateFunction",
    "PutBucketPolicy",
    "PutBucketAcl",
    "DeleteBucketPolicy",
    "DeletePublicAccessBlock",
    "ModifySnapshotAttribute",
  ]
}

variable "subscription_filter_pattern" {
  description = <<-EOT
    Pre-filter applied by CloudWatch Logs before the alerter Lambda runs. Keeps
    invocations off the read-only majority of CloudTrail volume.

    The NOT EXISTS clause matters: readOnly is documented as optional, and an
    event missing the field would otherwise never reach the Lambda at all.
  EOT
  type        = string
  default     = "{ $.readOnly IS FALSE || $.readOnly NOT EXISTS }"
}

variable "create_guardduty_detector" {
  description = "Create a GuardDuty detector in this account. Set false if one already exists."
  type        = bool
  default     = false
}

variable "enable_guardduty_alerts" {
  description = <<-EOT
    Create the rule that mails GuardDuty findings. Defaults off because GuardDuty
    is the only billable component here, and enabling it organization-wide bills
    per member account rather than once.
  EOT
  type        = bool
  default     = false
}

variable "guardduty_auto_enable_members" {
  description = <<-EOT
    Make this account the organization's GuardDuty delegated administrator and
    auto-enable member accounts. Only meaningful when create_guardduty_detector
    is true, and it multiplies cost by the number of accounts.
  EOT
  type        = bool
  default     = false
}

variable "min_guardduty_severity" {
  description = "Lowest GuardDuty severity that emails you. 4 is MEDIUM, 7 is HIGH."
  type        = number
  default     = 4
}

variable "heartbeat_schedule" {
  description = "When the digest runs. Default is the top of every hour."
  type        = string
  default     = "cron(0 * * * ? *)"
}

variable "heartbeat_always_send" {
  description = <<-EOT
    Send the digest even when no account had activity. This is what makes silence
    meaningful. Set false to only mail on activity, at the cost of losing the
    dead-man's-switch property.
  EOT
  type        = bool
  default     = true
}

variable "heartbeat_lookback_hours" {
  description = "Width of each digest window. Should match the schedule interval."
  type        = number
  default     = 1
}

variable "heartbeat_lag_minutes" {
  description = <<-EOT
    How far the digest window trails real time. CloudTrail takes a few minutes to
    deliver into CloudWatch Logs, so a window ending at 'now' would drop the most
    recent calls and the next run would start after them.
  EOT
  type        = number
  default     = 15
}

variable "trail_retention_days" {
  description = "How long trail objects live in S3 before expiring."
  type        = number
  default     = 90
}

variable "log_retention_days" {
  description = <<-EOT
    Retention on the trail's CloudWatch Logs group. This bounds the window the
    hourly digest can look back over, so keep it comfortably above
    heartbeat_lookback_hours.
  EOT
  type        = number
  default     = 30
}

variable "lambda_log_retention_days" {
  description = "Retention for the two functions' own execution logs."
  type        = number
  default     = 14
}

variable "tags" {
  description = <<-EOT
    Tags applied to every taggable resource this module creates.

    Merges with any provider-level default_tags rather than replacing them, so
    callers can use either mechanism or both.
  EOT
  type        = map(string)
  default     = {}
}

variable "name_prefix" {
  description = "Prefix for every resource name so this stays identifiable."
  type        = string
  default     = "org-keywatch"
}
