variable "vpc_id"            { type = string }
variable "aws_region"        { type = string }
variable "igw_id"            { type = string }
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

# isolated subnet — no route to the elastic or attack host subnets
resource "aws_subnet" "honeypot" {
  vpc_id                  = var.vpc_id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"
  tags = { Name = "honeypot-isolated" }
}

resource "aws_route_table" "honeypot" {
  vpc_id = var.vpc_id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = var.igw_id
  }
}

resource "aws_route_table_association" "honeypot" {
  subnet_id      = aws_subnet.honeypot.id
  route_table_id = aws_route_table.honeypot.id
}

# wide open inbound on honeypot ports, locked down otherwise
resource "aws_security_group" "honeypot" {
  name_prefix = "honeypot-"
  vpc_id      = var.vpc_id

  # SSH honeypot — open to the world (this is the point)
  ingress {
    from_port   = 2222
    to_port     = 2222
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Telnet honeypot
  ingress {
    from_port   = 2223
    to_port     = 2223
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # real SSH for you to manage it — restrict to VPC only
  # you'd SSH through the elastic host as a jump box
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# NACLs to block honeypot subnet from reaching the lab subnet
resource "aws_network_acl" "honeypot" {
  vpc_id     = var.vpc_id
  subnet_ids = [aws_subnet.honeypot.id]

  # allow inbound from internet
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 65535
  }

  # allow outbound to internet (for apt, docker pulls, shipping logs to elastic)
  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 65535
  }

  # block outbound to lab subnet — honeypot can't reach elastic or attack host
  egress {
    rule_no    = 50
    protocol   = "-1"
    action     = "deny"
    cidr_block = "10.0.1.0/24"
    from_port  = 0
    to_port    = 0
  }
}

resource "aws_instance" "honeypot" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  key_name               = var.key_name
  subnet_id              = aws_subnet.honeypot.id
  vpc_security_group_ids = [aws_security_group.honeypot.id]

  root_block_device {
    volume_size = 15
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/setup.sh.tpl", {
    elastic_host     = var.elastic_host
    elastic_password = var.elastic_password
  })

  tags = { Name = "cowrie-honeypot" }
}

output "public_ip" { value = aws_instance.honeypot.public_ip }
