output "s3_bucket_name" {
  description = "Name of the S3 storage bucket"
  value       = aws_s3_bucket.vaultgate_storage.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 storage bucket"
  value       = aws_s3_bucket.vaultgate_storage.arn
}

output "kms_key_id" {
  description = "Key ID of the KMS Customer-Managed Key"
  value       = aws_kms_key.vaultgate_key.key_id
}

output "kms_key_arn" {
  description = "ARN of the KMS Customer-Managed Key"
  value       = aws_kms_key.vaultgate_key.arn
}

output "kms_key_alias" {
  description = "Alias of the KMS Customer-Managed Key"
  value       = aws_kms_alias.vaultgate_key_alias.name
}

output "gateway_role_arn" {
  description = "ARN of the IAM role for the VaultGate service"
  value       = aws_iam_role.gateway_role.arn
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail trail"
  value       = var.enable_cloudtrail ? aws_cloudtrail.vaultgate_trail[0].name : "disabled"
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Log Group for KMS audit logs"
  value       = var.enable_cloudtrail ? aws_cloudwatch_log_group.kms_audit[0].name : "disabled"
}
