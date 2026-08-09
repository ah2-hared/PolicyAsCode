terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "eu-west-2"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}

resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data-example-bucket"

  tags = {
    Environment               = "production"
    gdpr_high_risk_processing = "true"
    gdpr_dpia_completed       = "true"
  }
}

resource "aws_s3_bucket_versioning" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id

  block_public_acls   = true
  block_public_policy = true

  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "customer_data" {
  bucket        = aws_s3_bucket.customer_data.id
  target_bucket = aws_s3_bucket.customer_data.id
  target_prefix = "access-logs/"
}

# ---------------------------------------------------------------------------
# Network — security group (ingress exposure) and an HTTPS-only load balancer
# listener (transport encryption). resource_type: "network"
# ---------------------------------------------------------------------------

resource "aws_security_group" "app" {
  name        = "customer-data-app-sg"
  description = "Application security group for the customer data service"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description = "HTTPS from the internal corporate network only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Unrestricted outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "app" {
  name               = "customer-data-app-lb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.app.id]
  subnets            = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
}

resource "aws_lb_target_group" "app" {
  name     = "customer-data-app-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = "vpc-0123456789abcdef0"
}

resource "aws_lb_listener" "app" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:eu-west-2:123456789012:certificate/11111111-1111-1111-1111-111111111111"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# ---------------------------------------------------------------------------
# Logging — CloudTrail audit trail + its CloudWatch log group.
# resource_type: "logging"
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "audit_trail" {
  name              = "/aws/cloudtrail/customer-data-system"
  retention_in_days = 400
}

resource "aws_cloudtrail" "audit_trail" {
  name                          = "customer-data-system-trail"
  s3_bucket_name                = aws_s3_bucket.customer_data.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
}

# ---------------------------------------------------------------------------
# Compute — an auto-scaling group behind the load balancer.
# resource_type: "compute"
# ---------------------------------------------------------------------------

resource "aws_launch_template" "app" {
  name_prefix   = "customer-data-app-"
  image_id      = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
}

resource "aws_autoscaling_group" "app" {
  name                      = "customer-data-app-asg"
  min_size                  = 2
  max_size                  = 4
  desired_capacity          = 2
  availability_zones        = ["eu-west-2a", "eu-west-2b"]
  health_check_type         = "ELB"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }
}

# ---------------------------------------------------------------------------
# Monitoring — a CloudWatch alarm watching the application.
# resource_type: "monitoring"
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "app_cpu_high" {
  alarm_name          = "customer-data-app-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Triggers when average CPU exceeds 80 percent"
}

# ---------------------------------------------------------------------------
# Encryption key — customer-managed KMS key with rotation enabled.
# resource_type: "encryption_key"
# ---------------------------------------------------------------------------

resource "aws_kms_key" "app_data" {
  description             = "Customer-managed key for customer data encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

# ---------------------------------------------------------------------------
# Identity — an application role with an MFA-conditioned trust policy and a
# least-privilege inline policy. resource_type: "identity"
# ---------------------------------------------------------------------------

resource "aws_iam_role" "app_role" {
  name = "customer-data-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "app_role" {
  name = "customer-data-app-policy"
  role = aws_iam_role.app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::customer-data-example-bucket/*"
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Secrets exposure example — deliberately insecure, so the pipeline has a
# real finding to report rather than an all-green run. A production system
# would source this from Secrets Manager / SSM Parameter Store instead.
# resource_type: swept for "secrets" evidence, not normalised as its own
# resource.
# ---------------------------------------------------------------------------

resource "aws_db_instance" "customer_metadata" {
  identifier              = "customer-metadata-db"
  engine                  = "postgres"
  engine_version          = "15"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "app_user"
  password                = "SuperSecret123!"
  skip_final_snapshot     = true
  publicly_accessible     = false
  storage_encrypted       = true
  backup_retention_period = 14
  multi_az                = true
}

# ---------------------------------------------------------------------------
# Backup — AWS Backup plan and selection covering the customer data bucket.
# Feeds backup_enabled / backup_encryption_enabled on the storage resource.
# ---------------------------------------------------------------------------

resource "aws_backup_vault" "customer_data" {
  name        = "customer-data-backup-vault"
  kms_key_arn = "arn:aws:kms:eu-west-2:123456789012:key/11111111-1111-1111-1111-111111111111"
}

resource "aws_backup_plan" "customer_data" {
  name = "customer-data-backup-plan"

  rule {
    rule_name         = "daily-backup"
    target_vault_name = aws_backup_vault.customer_data.name
    schedule          = "cron(0 5 * * ? *)"
  }
}

resource "aws_backup_selection" "customer_data" {
  name         = "customer-data-backup-selection"
  iam_role_arn = "arn:aws:iam::123456789012:role/aws-backup-service-role"
  plan_id      = aws_backup_plan.customer_data.id

  resources = [
    "arn:aws:s3:::customer-data-example-bucket"
  ]
}