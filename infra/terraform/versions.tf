# 버전을 고정한다. 프로바이더가 올라가면서 기본값이 바뀌면
# 손대지 않은 자원에 계획 차이가 생기고, 그 차이가 실수로 적용될 수 있다.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # 상태 파일은 우선 로컬에 둔다. 1인 프로젝트라 잠금 경쟁이 없다.
  # S3 백엔드로의 이전은 백업용 버킷을 만드는 시점에 함께 처리한다.
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "OpsLoop"
      ManagedBy = "Terraform"
    }
  }
}
