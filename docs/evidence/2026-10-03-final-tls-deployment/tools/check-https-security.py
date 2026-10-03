#!/usr/bin/env python3
"""Read-only HTTPS checks + one deliberately invalid login; no account changes.
Never saves a session value, password, webhook address, or response body.
"""
import http.client
import json
from pathlib import Path
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlencode

ROOT = Path('/Users/hanseongmin/opsloop-repo')
sys.path.insert(0, str(ROOT/'infra/vmware/failover'))
import common

HOST, PORT = '192.168.70.254', 8443
ORIGIN = f'https://{HOST}:{PORT}'
COOKIE = common.load_cookie()
rows = []

def request(label, method, path, expected, *, origin=ORIGIN, cookie=False, body=None):
    headers = {'Origin':origin, 'User-Agent':'opsloop-final-security-check/113'}
    if cookie:
        headers['Cookie'] = common.COOKIE_NAME + '=' + COOKIE
    if body is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    con = http.client.HTTPSConnection(HOST,PORT,context=common.tls_context(),timeout=10)
    try:
        con.request(method,path,body=body,headers=headers)
        res=con.getresponse()
        data=res.read()
        result={'label':label,'status':res.status,'expected':expected,'passed':res.status==expected}
        if label=='viewer-session':
            me=json.loads(data)
            result['role']=me.get('role')
            result['console']=me.get('console')
        if label=='logout-cookie-flags':
            # Drop cookie value, retain only security attributes for evidence.
            flags=(res.getheader('Set-Cookie') or '').split(';')[1:]
            result['cookie_attributes']=[f.strip() for f in flags]
            result['passed'] &= all(any(f.strip().lower()==wanted for f in flags) for wanted in ['secure','httponly','samesite=lax'])
        rows.append(result)
    finally:
        con.close()

request('viewer-session','GET','/api/me',200,cookie=True)
request('viewer-admin-read-denied','GET','/api/accounts',403,cookie=True)
request('http-origin-denied','POST','/login',403,origin=f'http://{HOST}:{PORT}',body='username=unused&password=unused')
request('one-invalid-login','POST','/login',401,body=urlencode({'username':'qa-final-113-nonexistent','password':'intentionally-invalid-test-value'}))
request('logout-cookie-flags','POST','/logout',302,cookie=True)
try:
    with socket.create_connection((HOST,PORT),timeout=10) as raw:
        with common.tls_context().wrap_socket(raw,server_hostname='wrong.opsloop.invalid'):
            rows.append({'label':'wrong-hostname','passed':False})
except ssl.SSLCertVerificationError:
    rows.append({'label':'wrong-hostname','passed':True,'error':'SSLCertVerificationError'})

out={'at':datetime.now(timezone.utc).isoformat(),'scope':'production HTTPS; viewer cookie minted by existing probe procedure, not a password login; one nonexistent-account failure; no external webhook','checks':rows}
path=ROOT/'output/final-development-20261003/deployment/https-security.json'
path.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(out,ensure_ascii=False,indent=2))
sys.exit(0 if all(x['passed'] for x in rows) else 1)
