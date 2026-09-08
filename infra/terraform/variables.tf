variable "region" {
  description = "배포 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "vpc_id" {
  description = "기존 기본 VPC 식별자"
  type        = string
}

variable "subnet_id" {
  description = "인스턴스가 위치한 서브넷"
  type        = string
}

variable "key_name" {
  description = "수집 노드에 지정된 키 페어 이름. 실제 접속은 SSM 으로 하며 사용하지 않는다"
  type        = string
  default     = "opsloop"
}

variable "admin_cidr" {
  description = "개발용 API 접근을 허용할 주소. 회선이 바뀌면 갱신한다"
  type        = string
}

variable "honeypot_ami" {
  description = "수집 노드의 현재 AMI. import 후 terraform state show 로 확인해 채운다"
  type        = string
}

variable "app_ami" {
  description = "앱 노드의 현재 AMI"
  type        = string
}

# ── import 대상 식별자 ────────────────────────────────────────
# 콘솔에서 손으로 만든 자원을 코드로 가져오기 위한 값이다.
# 가져오기가 끝나면 이 변수들은 더 이상 쓰이지 않으므로 제거한다.

