terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # If targeting LocalStack, enable local endpoints and skip AWS-specific checks
  dynamic "endpoints" {
    for_each = var.localstack_endpoint != "" ? [1] : []
    content {
      s3         = var.localstack_endpoint
      kms        = var.localstack_endpoint
      iam        = var.localstack_endpoint
      cloudtrail = var.localstack_endpoint
      cloudwatch = var.localstack_endpoint
      logs       = var.localstack_endpoint
      sts        = var.localstack_endpoint
    }
  }

  s3_use_path_style           = var.localstack_endpoint != "" ? true : false
  skip_credentials_validation = var.localstack_endpoint != "" ? true : false
  skip_metadata_api_check     = var.localstack_endpoint != "" ? true : false
  skip_requesting_account_id  = var.localstack_endpoint != "" ? true : false

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "random_id" "suffix" {
  byte_length = 4
}
