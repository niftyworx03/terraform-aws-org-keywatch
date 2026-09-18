# Optional, and the only billable component here. GuardDuty baselines normal API
# usage per account, so it answers "was the key used by someone who is not me" —
# the question a hand-written list of event names cannot answer.
#
# Enabling it organization-wide bills per member account, so cost scales with
# the number of accounts rather than staying flat. Hence the default of off.

resource "aws_guardduty_detector" "this" {
  count = var.create_guardduty_detector ? 1 : 0

  enable = true

  # Applies to updates of existing findings; brand new findings publish at once.
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = var.tags
}

resource "aws_guardduty_organization_admin_account" "this" {
  count = var.create_guardduty_detector && var.guardduty_auto_enable_members ? 1 : 0

  admin_account_id = data.aws_caller_identity.current.account_id
}

resource "aws_guardduty_organization_configuration" "this" {
  count = var.create_guardduty_detector && var.guardduty_auto_enable_members ? 1 : 0

  detector_id                      = aws_guardduty_detector.this[0].id
  auto_enable_organization_members = "ALL"

  depends_on = [aws_guardduty_organization_admin_account.this]
}

# With a delegated administrator, member account findings surface here too, so
# this single rule covers the organization.
resource "aws_cloudwatch_event_rule" "guardduty_finding" {
  count = var.enable_guardduty_alerts ? 1 : 0

  name        = "${var.name_prefix}-guardduty-finding"
  description = "GuardDuty findings at or above severity ${var.min_guardduty_severity}."

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.min_guardduty_severity] }]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "guardduty_finding" {
  count = var.enable_guardduty_alerts ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_finding[0].name
  target_id = "sns-alerts"
  arn       = aws_sns_topic.alerts.arn

  # Raw finding JSON is unreadable in a phone mail client at 2am.
  input_transformer {
    input_paths = {
      findingType = "$.detail.type"
      severity    = "$.detail.severity"
      account     = "$.detail.accountId"
      findingArea = "$.detail.region"
      occurred    = "$.time"
      summary     = "$.detail.description"
    }

    input_template = <<-EOT
      "GuardDuty finding: <findingType>"
      ""
      "Severity : <severity>"
      "When     : <occurred>"
      "Account  : <account> in <findingArea>"
      ""
      "<summary>"
      ""
      "If this involves an access key you do not recognise, deactivate it now:"
      "  aws iam update-access-key --access-key-id AKIA_YOUR_KEY --status Inactive"
    EOT
  }
}
