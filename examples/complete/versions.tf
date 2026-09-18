terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Provider configuration belongs to the root module, never to the module being
# consumed. This is the credential that must point at the organization's
# management account; the module's aws_organizations_organization data source
# fails anywhere else.
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}
