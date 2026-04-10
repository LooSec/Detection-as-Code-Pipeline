variable "subnet_id"          { type = string }
variable "security_group_id"  { type = string }
variable "key_name"           { type = string }
variable "elastic_password"   { type = string }
variable "kibana_readonly_pw" { type = string }

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

resource "aws_instance" "elastic" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.xlarge"
  key_name               = var.key_name
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]

  root_block_device {
    volume_size = 80
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/setup.sh.tpl", {
    elastic_password   = var.elastic_password
    kibana_readonly_pw = var.kibana_readonly_pw
  })

  tags = { Name = "elastic-stack" }
}

output "public_ip"  { value = aws_instance.elastic.public_ip }
output "private_ip" { value = aws_instance.elastic.private_ip }
