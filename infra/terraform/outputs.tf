output "honeypot_public_ip" {
  description = "수집 노드 공인 주소. 공격 유입구"
  value       = aws_instance.honeypot.public_ip
}

output "honeypot_private_ip" {
  value = aws_instance.honeypot.private_ip
}

output "app_public_ip" {
  description = "앱 노드 공인 주소. 개발용 API 접근에 사용"
  value       = aws_instance.app.public_ip
}

output "app_private_ip" {
  description = "수집 노드가 데이터베이스에 접속할 때 쓰는 주소"
  value       = aws_instance.app.private_ip
}

output "api_url" {
  value = "http://${aws_instance.app.public_ip}:8000/docs"
}
