# S3 Bucket for CloudTrail Audit Logs
resource "aws_s3_bucket" "audit_trail" {
  count         = var.enable_cloudtrail ? 1 : 0
  bucket        = "${var.project_name}-cloudtrail-${var.environment}-${random_id.suffix.hex}"
  force_destroy = var.environment != "prod"

  tags = {
    Name = "${var.project_name}-cloudtrail-${var.environment}"
  }
}

resource "aws_s3_bucket_public_access_block" "audit_trail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.audit_trail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit_trail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.audit_trail[0].id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Policy allowing CloudTrail to deliver logs to the S3 bucket
data "aws_iam_policy_document" "cloudtrail_s3_policy" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    actions = [
      "s3:GetBucketAcl"
    ]
    resources = [
      aws_s3_bucket.audit_trail[0].arn
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject"
    ]
    resources = [
      "${aws_s3_bucket.audit_trail[0].arn}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
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
  }
}

resource "aws_s3_bucket_policy" "audit_trail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.audit_trail[0].id
  policy = data.aws_iam_policy_document.cloudtrail_s3_policy[0].json

  depends_on = [aws_s3_bucket_ownership_controls.audit_trail]
}

# CloudWatch Log Group for real-time audit log streaming
resource "aws_cloudwatch_log_group" "kms_audit" {
  count             = var.enable_cloudtrail ? 1 : 0
  name              = "/aws/cloudtrail/${var.project_name}-kms-audit-${var.environment}"
  retention_in_days = 30

  tags = {
    Name = "${var.project_name}-kms-audit-logs-${var.environment}"
  }
}

# IAM Role for CloudTrail to write to CloudWatch Logs
data "aws_iam_policy_document" "cloudtrail_assume_role" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_cw_role" {
  count              = var.enable_cloudtrail ? 1 : 0
  name               = "${var.project_name}-cloudtrail-cw-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume_role[0].json
}

data "aws_iam_policy_document" "cloudtrail_cw_policy" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "${aws_cloudwatch_log_group.kms_audit[0].arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "cloudtrail_cw_policy" {
  count  = var.enable_cloudtrail ? 1 : 0
  name   = "${var.project_name}-cloudtrail-cw-policy-${var.environment}"
  role   = aws_iam_role.cloudtrail_cw_role[0].id
  policy = data.aws_iam_policy_document.cloudtrail_cw_policy[0].json
}

# The CloudTrail resource capturing KMS and Management events
resource "aws_cloudtrail" "vaultgate_trail" {
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = "${var.project_name}-audit-trail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.audit_trail[0].id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
  is_multi_region_trail         = false
  enable_logging                = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.kms_audit[0].arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw_role[0].arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [
    aws_s3_bucket_policy.audit_trail,
    aws_iam_role_policy.cloudtrail_cw_policy
  ]

  tags = {
    Name = "${var.project_name}-audit-trail-${var.environment}"
  }
}
