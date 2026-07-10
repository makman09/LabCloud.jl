terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket  = "caucellcloud-terraform-state"
    key     = "research/terraform.tfstate"
    region  = "us-east-1"
    profile = "tf-admin"
  }
}
