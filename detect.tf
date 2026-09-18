# Near-real-time alerting on a short list of actions that are rare-to-never
# across these accounts, so a match is high signal.

resource "aws_iam_role" "alerter" {
  name               = "${var.name_prefix}-alerter"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "alerter" {
  source_policy_documents = [data.aws_iam_policy_document.describe_org.json]

  statement {
    sid       = "PublishAlert"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid = "WriteOwnLogs"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    # No CreateLogGroup: the group is declared below, so the function does not
    # need permission to create arbitrary ones.
    resources = ["${aws_cloudwatch_log_group.alerter.arn}:*"]
  }
}

resource "aws_iam_role_policy" "alerter" {
  name   = "${var.name_prefix}-alerter"
  role   = aws_iam_role.alerter.id
  policy = data.aws_iam_policy_document.alerter.json
}

resource "aws_cloudwatch_log_group" "alerter" {
  name              = "/aws/lambda/${var.name_prefix}-alerter"
  retention_in_days = var.lambda_log_retention_days

  tags = var.tags
}

resource "aws_lambda_function" "alerter" {
  function_name = "${var.name_prefix}-alerter"
  role          = aws_iam_role.alerter.arn
  handler       = "alerter.lambda_handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = merge(local.common_env, {
      DANGEROUS_EVENTS = join(",", var.dangerous_event_names)
    })
  }

  tags = var.tags

  depends_on = [
    aws_iam_role_policy.alerter,
    aws_cloudwatch_log_group.alerter,
  ]
}

resource "aws_lambda_permission" "alerter" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alerter.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "mutating" {
  name            = "${var.name_prefix}-mutating"
  log_group_name  = aws_cloudwatch_log_group.trail.name
  filter_pattern  = var.subscription_filter_pattern
  destination_arn = aws_lambda_function.alerter.arn

  depends_on = [aws_lambda_permission.alerter]
}
