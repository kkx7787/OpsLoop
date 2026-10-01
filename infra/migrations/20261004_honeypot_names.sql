-- 허니팟 명칭 (이슈 #78 · #84). 차단 금지 대역(block_exempt) 관문 EIP 줄의 메모를 'AWS 관문 EIP' 에서 '허니팟 관문 EIP' 로 바꾼다.
--   메모는 그 주소를 차단하려 할 때 거부 사유 · 사건 상세에 보인다(app/absorbed.py · detector/triage.py). 대역 · 표 · 권한은 그대로다.
--   새 DB 는 schema.sql 초기값이 이미 같은 글자다. 옛 글자인 줄만 바꾸므로 여러 번 적용해도 같다(infra/test_honeypot_names_db.py 가 본다).
--   20260927_block_enforce.sql 을 다시 적용해도 있는 줄은 그대로다(ON CONFLICT DO NOTHING). 그 줄을 지운 뒤 다시 적용했다면 이 파일도
--   다시 적용한다. 앱 · triage 와 순서는 상관없다(메모 글자만 바뀐다).
-- 적용 (Mac, 저장소 루트):
--   ssh -F ~/.ssh/config.opsloop data01 'sudo -n docker exec -i opsloop-db psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q' \
--     < infra/migrations/20261004_honeypot_names.sql
-- 확인: SELECT cidr, note FROM block_exempt WHERE cidr = '15.164.37.49/32' → 허니팟 관문 EIP
BEGIN;
UPDATE block_exempt SET note = '허니팟 관문 EIP' WHERE note = 'AWS 관문 EIP';
COMMIT;
