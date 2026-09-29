#!/bin/bash
# 사용: run-s3.sh <인스턴스> <사례 JSON 파일> <시각표> <결과 파일>
set -eu
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CREDENTIAL_EXPIRATION
I=$1; CF=$2; T=$3; OUT=$4; R=ap-northeast-2
python3 - "$CF" "$T" "$I" > params.json <<'EOF'
import json,sys,shlex
cf,t,i=sys.argv[1:]
c=open(cf).read().strip(); src=open("s3probe.py").read()
cmd=f"B=opsloop-archive-739272173045 T={t} H={i} C={shlex.quote(c)} timeout 300 python3 - <<'PYEOF'\n{src}\nPYEOF"
print(json.dumps({"commands":[cmd],"executionTimeout":["360"]}))
EOF
CID=$(aws ssm send-command --region $R --instance-ids $I --document-name AWS-RunShellScript --parameters file://params.json --query Command.CommandId --output text)
for n in $(seq 1 60); do
  S=$(aws ssm get-command-invocation --region $R --command-id $CID --instance-id $I --query Status --output text 2>/dev/null || echo Pending)
  case $S in Pending|InProgress|Delayed) sleep 5;; *) break;; esac
done
aws ssm get-command-invocation --region $R --command-id $CID --instance-id $I --query '[Status,StandardOutputContent,StandardErrorContent]' --output json > "$OUT"
python3 - "$OUT" <<'EOF'
import json,sys
s,o,e=json.load(open(sys.argv[1])); print(s)
if e.strip(): print("stderr:", e[-800:])
if o.strip():
    for l,op,k,c,err in json.loads(o)["results"]: print(f"{c}\t{err}\t{l}")
EOF
