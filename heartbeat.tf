# The hourly digest, and the dead-man's switch that watches it.

resource "aws_iam_role" "heartbeat" {
  name               = "${var.name_prefix}-heartbeat"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "heartbeat" {
  source_policy_documents = [data.aws_iam_policy_document.describe_org.json]

  statement {
    sid     = "ReadTrailLogGroup"
    actions = ["logs:FilterLogEvents"]

    # Scoped to the trail's group only, not every log group in the account.
    resources = ["${aws_cloudwatch_log_group.trail.arn}:*"]
  }

  statement {
    sid       = "PublishDigest"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid = "WriteOwnLogs"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${aws_cloudwatch_log_group.heartbeat.arn}:*"]
  }
}

resource "aws_iam_role_policy" "heartbeat" {
  name   = "${var.name_prefix}-heartbeat"
  role   = aws_iam_role.heartbeat.id
  policy = data.aws_iam_policy_document.heartbeat.json
}

resource "aws_cloudwatch_log_group" "heartbeat" {
  name              = "/aws/lambda/${var.name_prefix}-heartbeat"
  retention_in_days = var.lambda_log_retention_days

  tags = var.tags
}

resource "aws_lambda_function" "heartbeat" {
  function_name = "${var.name_prefix}-heartbeat"
  role          = aws_iam_role.heartbeat.arn
  handler       = "heartbeat.lambda_handler"
  runtime       = "python3.12"
  timeout       = 120
  memory_size   = 256

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = merge(local.common_env, {
      LOG_GROUP_NAME = aws_cloudwatch_log_group.trail.name
      LOOKBACK_HOURS = tostring(var.heartbeat_lookback_hours)
      LAG_MINUTES    = tostring(var.heartbeat_lag_minutes)
      ALWAYS_SEND    = tostring(var.heartbeat_always_send)
    })
  }

  tags = var.tags

  depends_on = [
    aws_iam_role_policy.heartbeat,
    aws_cloudwatch_log_group.heartbeat,
  ]
}

resource "aws_cloudwatch_event_rule" "heartbeat" {
  name                = "${var.name_prefix}-heartbeat"
  description         = "Runs the organization-wide access key digest on a fixed schedule."
  schedule_expression = var.heartbeat_schedule

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "heartbeat" {
  rule      = aws_cloudwatch_event_rule.heartbeat.name
  target_id = "heartbeat-lambda"
  arn       = aws_lambda_function.heartbeat.arn
}

resource "aws_lambda_permission" "heartbeat" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.heartbeat.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.heartbeat.arn
}

# The digest tells you the organization is quiet. This tells you the digest is
# quiet, which is the failure the digest cannot report on itself.
resource "aws_cloudwatch_metric_alarm" "heartbeat_missing" {
  alarm_name          = "${var.name_prefix}-heartbeat-missing"
  alarm_description   = "The hourly organization digest has not run for two hours."
  namespace           = "AWS/Lambda"
  metric_name         = "Invocations"
  statistic           = "Sum"
  period              = 7200
  evaluation_periods  = 1
  comparison_operator = "LessThanThreshold"
  threshold           = 1

  # No datapoints means the function never ran, which is the condition itself.
  treat_missing_data = "breaching"

  dimensions = {
    FunctionName = aws_lambda_function.heartbeat.function_name
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  tags = var.tags
}

# Covers both functions: a silently failing alerter is worse than a noisy one,
# because nothing else would reveal it.
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = {
    heartbeat = aws_lambda_function.heartbeat.function_name
    alerter   = aws_lambda_function.alerter.function_name
  }

  alarm_name          = "${var.name_prefix}-${each.key}-errors"
  alarm_description   = "The ${each.key} function ran but failed."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = each.value
  }

  alarm_actions = [aws_sns_topic.alerts.arn]

  tags = var.tags
}
