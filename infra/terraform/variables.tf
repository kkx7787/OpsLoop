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

# ── DMZ 구간 (이슈 #15) ───────────────────────────────────────

variable "dmz_az" {
  description = "새 VPC 의 서브넷을 둘 가용 영역. 기존 노드와 같은 곳에 둔다"
  type        = string
  default     = "ap-northeast-2c"
}

variable "gateway_instance_type" {
  description = "관문 방화벽 인스턴스 유형"
  type        = string
  default     = "t3.micro"
}

variable "honeypot_dmz_ami" {
  description = "DMZ 허니팟의 AMI. 기존 허니팟에서 만든 이미지 ID 를 넣으면 생기고, 비우면 만들지 않는다 (README 'DMZ 재구성' 3단계)"
  type        = string
  default     = ""
}

# ── import 대상 식별자 ────────────────────────────────────────
# 콘솔에서 손으로 만든 자원을 코드로 가져오기 위한 값이다.
# 가져오기가 끝나면 이 변수들은 더 이상 쓰이지 않으므로 제거한다.

