output "gateway_public_ip" {
  description = "관문 방화벽 공인 주소(EIP). 허니팟 이전 뒤의 공격 유입구"
  value       = aws_eip.gateway.public_ip
}

output "honeypot_dmz_private_ip" {
  description = "DMZ 허니팟 사설 주소. honeypot_dmz_ami 가 비어 있으면 null"
  value       = one(aws_instance.honeypot_dmz[*].private_ip)
}
