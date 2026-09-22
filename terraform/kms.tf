# Strict Key Policy with NO wildcard principals
data "aws_iam_policy_document" "kms_key_policy" {
  # 1. Key Administration: Account Root and Provisioning Admin ONLY
  statement {
    sid    = "KeyAdministratorAccess"
    effect = "Allow"
    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion"
    ]
    resources = ["*"]

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
        data.aws_caller_identity.current.arn
      ]
    }
  }

  # 2. Cryptographic Envelope Operations: Strictly the Gateway Role
  statement {
    sid    = "AllowGatewayEnvelopeOperations"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = ["*"]

    principals {
      type = "AWS"
      identifiers = [
        aws_iam_role.gateway_role.arn
      ]
    }
  }
}

resource "aws_kms_key" "vaultgate_key" {
  description             = "VaultGate Master Envelope Encryption Key (${var.environment})"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_key_policy.json

  tags = {
    Name = "${var.project_name}-kms-key-${var.environment}"
  }
}

resource "aws_kms_alias" "vaultgate_key_alias" {
  name          = "alias/${var.project_name}-master-key-${var.environment}"
  target_key_id = aws_kms_key.vaultgate_key.key_id
}
