variable "aws_region" {
  description = "AWS region for provisioning resources"
  type        = string
  default     = "eu-central-1"
}

variable "environment" {
  description = "Deployment environment (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Project name identifier"
  type        = string
  default     = "vaultgate"
}

variable "enable_cloudtrail" {
  description = "Whether to provision CloudTrail for KMS audit logging"
  type        = bool
  default     = true
}

variable "localstack_endpoint" {
  description = "LocalStack endpoint URL for local emulation (empty for real AWS)"
  type        = string
  default     = ""
}
