
# PolicyAsCode local-test patch: the real data source below requires a
# live AWS STS call, which this offline evaluation deliberately does
# not have (see terraform_examples/terragoat/POLICYASCODE_PATCH.md).
# Swapped for a literal placeholder account id; every other resource
# in this repo is untouched.
# data "aws_caller_identity" "current" {}

variable "company_name" {
  default = "acme"
}

variable "environment" {
  default = "dev"
}

locals {
  resource_prefix = {
    value = "123456789012-${var.company_name}-${var.environment}"
  }
}



variable "profile" {
  default = "default"
}

variable "region" {
  default = "us-west-2"
}

variable ami {
  type    = string
  default = "ami-09a5b0b7edf08843d"
}

variable "dbname" {
  type        = string
  description = "Name of the Database"
  default     = "db1"
}

variable "password" {
  type        = string
  description = "Database password"
  default     = "Aa1234321Bb"
}

variable "neptune-dbname" {
  type        = string
  description = "Name of the Neptune graph database"
  default     = "neptunedb1"
}