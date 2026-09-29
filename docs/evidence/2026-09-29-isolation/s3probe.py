"""S3 권한 탐침 (이슈 #70 격리 시험). 상태 코드와 오류 코드만 출력한다. 객체 내용은 출력하지 않는다.

CASES 는 [이름, 동작, 키] 목록. 동작: put_inm(If-None-Match: *), put_plain(조건 없음), put_glacier(If-None-Match + GLACIER),
delete, get, head, list(키를 접두사로).
"""
import json, os, sys
import boto3
from botocore.exceptions import ClientError

BUCKET = os.environ["B"]
CASES = json.loads(os.environ["C"])
BODY = json.dumps({"probe": "isolation-" + os.environ["T"], "issue": 70}).encode()

from botocore.config import Config

s3 = boto3.client("s3", region_name="ap-northeast-2",
                  config=Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 1}))
mode = {"inm": False, "sc": None}


def hdr(request, **_):
    if mode["inm"]:
        request.headers["If-None-Match"] = "*"
    if mode["sc"]:
        request.headers["x-amz-storage-class"] = mode["sc"]


s3.meta.events.register("before-sign.s3.PutObject", hdr)
out = {"host": os.environ.get("H", "?"), "results": []}
for label, op, key in CASES:
    mode["inm"] = op in ("put_inm", "put_glacier")
    mode["sc"] = "GLACIER" if op == "put_glacier" else None
    try:
        if op.startswith("put"):
            r = s3.put_object(Bucket=BUCKET, Key=key, Body=BODY, ContentType="application/json")
        elif op == "delete":
            r = s3.delete_object(Bucket=BUCKET, Key=key)
        elif op == "get":
            r = s3.get_object(Bucket=BUCKET, Key=key)
            r["Body"].close()
        elif op == "head":
            r = s3.head_object(Bucket=BUCKET, Key=key)
        elif op == "list":
            r = s3.list_objects_v2(Bucket=BUCKET, Prefix=key, MaxKeys=1)
        code, err = r["ResponseMetadata"]["HTTPStatusCode"], ""
    except ClientError as e:
        code = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        err = e.response.get("Error", {}).get("Code", "")
    except Exception as e:  # 요청 전 실패는 정책 결과로 세지 않는다
        code, err = None, type(e).__name__
    out["results"].append([label, op, key, code, err])
print(json.dumps(out, ensure_ascii=False))
