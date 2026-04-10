variable "aws_region"       { type = string }
variable "elastic_host"     { type = string }
variable "elastic_password" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "trail" {
  bucket_prefix = "detection-lab-trail-"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

resource "aws_cloudtrail" "lab" {
  name                          = "detection-lab-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true
  depends_on                    = [aws_s3_bucket_policy.trail]
}

# lambda that reads cloudtrail from s3 and ships to elasticsearch
resource "aws_iam_role" "ingestor" {
  name = "detection-lab-ct-ingestor"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ingestor" {
  name = "ingestor"
  role = aws_iam_role.ingestor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

data "archive_file" "ingestor" {
  type        = "zip"
  output_path = "${path.module}/ingestor.zip"
  source {
    content = templatefile("${path.module}/ingestor.py.tpl", {
      elastic_host     = var.elastic_host
      elastic_password = var.elastic_password
    })
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "ingestor" {
  function_name    = "detection-lab-ct-ingestor"
  role             = aws_iam_role.ingestor.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 256
  filename         = data.archive_file.ingestor.output_path
  source_code_hash = data.archive_file.ingestor.output_base64sha256
}

resource "aws_lambda_permission" "s3" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ingestor.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.trail.arn
}

resource "aws_s3_bucket_notification" "trail" {
  bucket = aws_s3_bucket.trail.id
  lambda_function {
    lambda_function_arn = aws_lambda_function.ingestor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".json.gz"
  }
  depends_on = [aws_lambda_permission.s3]
}

output "trail_bucket" { value = aws_s3_bucket.trail.id }
