
provider "aws" {
  profile = var.profile
  region  = var.region
}

provider "aws" {
  alias      = "plain_text_access_keys_provider"
  region     = "us-west-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

terraform {
  # PolicyAsCode local-test patch: pinned to the aws provider major
  # version contemporaneous with this vintage of TerraGoat (the repo's
  # own embedded yor git-trace metadata dates it to 2020-2022). No
  # version was pinned upstream, so `terraform init` was resolving the
  # latest aws provider (6.x), whose schema has diverged enough since
  # 2022 to hard-error on arguments this config relies on. This is a
  # compatibility pin only; see POLICYASCODE_PATCH.md.
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }

  backend "s3" {
    encrypt = true
  }
}
