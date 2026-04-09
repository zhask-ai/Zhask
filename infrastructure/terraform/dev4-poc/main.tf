terraform {
  required_version = ">= 1.6.0"
}

variable "project_name" {
  type    = string
  default = "integrishield-poc"
}

variable "environment" {
  type    = string
  default = "dev"
}

locals {
  common_tags = {
    project     = var.project_name
    environment = var.environment
    owner       = "dev4"
  }
}

output "dev4_poc_tags" {
  value = local.common_tags
}
