# Trust policy allowing the current user/role or container service to assume the gateway role
data "aws_iam_policy_document" "gateway_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type = "AWS"
      identifiers = [
        data.aws_caller_identity.current.arn
      ]
    }
  }

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type = "Service"
      identifiers = [
        "ecs-tasks.amazonaws.com",
        "ec2.amazonaws.com"
      ]
    }
  }
}

resource "aws_iam_role" "gateway_role" {
  name               = "${var.project_name}-gateway-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.gateway_assume_role.json

  tags = {
    Name = "${var.project_name}-gateway-role-${var.environment}"
  }
}

# Narrowly scoped IAM policy for VaultGate Gateway service
data "aws_iam_policy_document" "gateway_policy_doc" {
  # Scoped S3 object operations
  statement {
    sid    = "ScopedS3ObjectAccess"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject"
    ]
    resources = [
      "${aws_s3_bucket.vaultgate_storage.arn}/*"
    ]
  }

  # Scoped S3 bucket listing
  statement {
    sid    = "ScopedS3BucketListing"
    effect = "Allow"
    actions = [
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.vaultgate_storage.arn
    ]
  }

  # Narrow KMS envelope encryption permissions
  statement {
    sid    = "KMSDataKeyAndDecryptionOnly"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = [
      aws_kms_key.vaultgate_key.arn
    ]
  }
}

resource "aws_iam_policy" "gateway_policy" {
  name        = "${var.project_name}-gateway-policy-${var.environment}"
  description = "Scoped policy for VaultGate client-side envelope encryption gateway"
  policy      = data.aws_iam_policy_document.gateway_policy_doc.json
}

resource "aws_iam_role_policy_attachment" "gateway_attach" {
  role       = aws_iam_role.gateway_role.name
  policy_arn = aws_iam_policy.gateway_policy.arn
}
