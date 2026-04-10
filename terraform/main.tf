terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = "detection-lab"
      ManagedBy = "terraform"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "my_ip" {
  description = "Your public IP for SSH/Kibana access (e.g. 1.2.3.4/32)"
  type        = string
}

variable "employer_cidrs" {
  type    = list(string)
  default = []
}

variable "key_name" {
  type = string
}

variable "elastic_password" {
  type      = string
  sensitive = true
}

variable "kibana_readonly_password" {
  type      = string
  sensitive = true
}

module "network" {
  source         = "./modules/network"
  aws_region     = var.aws_region
  my_ip          = var.my_ip
  employer_cidrs = var.employer_cidrs
}

module "elastic" {
  source             = "./modules/elastic"
  subnet_id          = module.network.public_subnet_id
  security_group_id  = module.network.elastic_sg_id
  key_name           = var.key_name
  elastic_password   = var.elastic_password
  kibana_readonly_pw = var.kibana_readonly_password
}

module "attack_host" {
  source            = "./modules/attack_host"
  subnet_id         = module.network.public_subnet_id
  security_group_id = module.network.attack_sg_id
  key_name          = var.key_name
  elastic_host      = module.elastic.private_ip
  elastic_password  = var.elastic_password
}

module "cloudtrail_pipeline" {
  source           = "./modules/cloudtrail_pipeline"
  aws_region       = var.aws_region
  elastic_host     = module.elastic.public_ip
  elastic_password = var.elastic_password
}

module "honeypot" {
  source           = "./modules/honeypot"
  vpc_id           = module.network.vpc_id
  aws_region       = var.aws_region
  igw_id           = module.network.igw_id
  key_name         = var.key_name
  elastic_host     = module.elastic.private_ip
  elastic_password = var.elastic_password
}

output "kibana_url" {
  value = "https://${module.elastic.public_ip}:5601"
}

output "kibana_readonly_user" {
  value = "employer_viewer"
}

output "elastic_ip" {
  value = module.elastic.public_ip
}

output "attack_host_ip" {
  value = module.attack_host.public_ip
}

output "cloudtrail_bucket" {
  value = module.cloudtrail_pipeline.trail_bucket
}

output "honeypot_ip" {
  value = module.honeypot.public_ip
}
