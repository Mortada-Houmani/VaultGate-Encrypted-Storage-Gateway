resource "aws_s3_bucket" "vaultgate_storage" {
  bucket        = "${var.project_name}-storage-${var.environment}-${random_id.suffix.hex}"
  force_destroy = var.environment != "prod"

  tags = {
    Name = "${var.project_name}-storage-${var.environment}"
  }
}

# Enforce Object Versioning
resource "aws_s3_bucket_versioning" "vaultgate_storage" {
  bucket = aws_s3_bucket.vaultgate_storage.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Block all public access at bucket level
resource "aws_s3_bucket_public_access_block" "vaultgate_storage" {
  bucket = aws_s3_bucket.vaultgate_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Ownership controls to enforce BucketOwnerEnforced (disabling legacy S3 ACLs)
resource "aws_s3_bucket_ownership_controls" "vaultgate_storage" {
  bucket = aws_s3_bucket.vaultgate_storage.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
