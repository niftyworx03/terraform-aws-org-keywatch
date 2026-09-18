# One organization trail replaces a trail per account. It is also the free one:
# each AWS account gets a single free copy of management events, and this trail
# is that copy for every member. Any member account holding its own trail turns
# this into a billable second copy for that account.

locals {
  trail_name = "${var.name_prefix}-org-trail"
  trail_arn  = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"
  org_id     = data.aws_organizations_organization.current.id
}

resource "aws_s3_bucket" "trail" {
  bucket = "${var.name_prefix}-trail-${data.aws_caller_identity.current.account_id}"

  # Personal organization: terraform destroy should actually finish.
  force_destroy = true

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket = aws_s3_bucket.trail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    apply_server_side_encryption_by_default {
      # Deliberately not SSE-KMS. A customer managed key costs $1/month, which
      # would be the largest line item in an otherwise free-tier stack.
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = var.trail_retention_days
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    actions = ["s3:PutObject"]

    # Two paths, and missing the second is the classic organization-trail
    # failure: member account logs land under the org id, not the management
    # account id, so a single-path policy silently drops every member account.
    resources = [
      "${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
      "${aws_s3_bucket.trail.arn}/AWSLogs/${local.org_id}/*",
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

# The CloudWatch Logs copy is what makes central detection possible. S3 alone
# would only support batch analysis after the fact.
resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${var.name_prefix}-org"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

data "aws_iam_policy_document" "trail_to_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trail_to_logs" {
  name               = "${var.name_prefix}-trail-to-logs"
  assume_role_policy = data.aws_iam_policy_document.trail_to_logs_assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "trail_to_logs" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    # Member accounts each get their own stream, named <account-id>_CloudTrail_<region>.
    resources = ["${aws_cloudwatch_log_group.trail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "trail_to_logs" {
  name   = "${var.name_prefix}-trail-to-logs"
  role   = aws_iam_role.trail_to_logs.id
  policy = data.aws_iam_policy_document.trail_to_logs.json
}

resource "aws_cloudtrail" "org" {
  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.trail.id

  is_organization_trail = true

  # Multi-region is the point, not a nicety: a stolen key is most useful in a
  # region its owner never looks at.
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_logs.arn

  tags = var.tags

  depends_on = [
    aws_s3_bucket_policy.trail,
    aws_iam_role_policy.trail_to_logs,
  ]
}
