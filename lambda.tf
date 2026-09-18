# Both functions ship in one zip and share common.py; they differ only by
# handler. Packaging them separately would mean duplicating the parsing code.

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/.build/lambda.zip"
  excludes    = ["__pycache__", "__pycache__/*"]
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

locals {
  # Passed to both functions so each can recognise, and skip, calls made by
  # this stack itself. Must list every role the stack creates, not just the
  # two Lambda ones: CloudTrail assumes trail_to_logs to write into the very
  # log group these functions read, so omitting it makes the monitor report
  # its own plumbing and the management account never reports a quiet hour.
  self_role_arns = join(",", [
    aws_iam_role.alerter.arn,
    aws_iam_role.heartbeat.arn,
    aws_iam_role.trail_to_logs.arn,
  ])

  common_env = {
    SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
    ACCESS_KEY_IDS = join(",", var.monitored_access_key_ids)
    SELF_ROLE_ARNS = local.self_role_arns
  }
}

# Account name resolution turns a bare account id into its account alias in
# every email. Only resolvable from the management account, and the code
# degrades to bare ids if the permission is absent.
data "aws_iam_policy_document" "describe_org" {
  statement {
    sid       = "ResolveAccountNames"
    actions   = ["organizations:ListAccounts"]
    resources = ["*"]
  }
}
