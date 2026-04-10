variable "subnet_id"         { type = string }
variable "security_group_id" { type = string }
variable "key_name"          { type = string }
variable "elastic_host"      { type = string }
variable "elastic_password"  { type = string }

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# needs broad permissions so atomic tests generate real cloudtrail events
resource "aws_iam_role" "attack_host" {
  name = "detection-lab-attack-host"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "attack_host" {
  name = "lab-permissions"
  role = aws_iam_role.attack_host.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "iam:List*", "iam:Get*",
        "iam:CreateUser", "iam:AttachUserPolicy",
        "iam:DeleteUser", "iam:DetachUserPolicy",
        "sts:AssumeRole", "sts:GetCallerIdentity",
        "s3:List*", "s3:Get*", "s3:PutBucketPolicy",
        "secretsmanager:List*", "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
        "ec2:Describe*", "logs:Describe*", "logs:GetLogEvents"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "attack_host" {
  name = "detection-lab-attack-host"
  role = aws_iam_role.attack_host.name
}

resource "aws_instance" "attack_host" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.medium"
  key_name               = var.key_name
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]
  iam_instance_profile   = aws_iam_instance_profile.attack_host.name

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/setup.sh.tpl", {
    elastic_host     = var.elastic_host
    elastic_password = var.elastic_password
  })

  tags = { Name = "attack-host" }
}

output "public_ip" { value = aws_instance.attack_host.public_ip }
