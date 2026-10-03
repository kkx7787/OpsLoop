#!/usr/bin/env python3
"""#103 프로젝트 CA/콘솔 인증서 발급. 신뢰 등록·원격 배포는 하지 않는다.

init --ca-dir <Mac의 비공개 경로>
issue --ca-dir <같은 경로> --out <새 발급 폴더>
check --out <발급 폴더> [--minimum-days 21]

CA 개인키는 Mac에만 보관한다. issue는 기존 출력 폴더를 덮지 않으므로 갱신도 새 폴더에 발급한다.
"""
import argparse
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROLES = {
    'console': ('OpsLoop Console', 'IP:192.168.70.254'),
    'console-a': ('console-a.opsloop.internal', 'DNS:console-a.opsloop.internal,IP:192.168.50.11,IP:127.0.0.1'),
    'console-b': ('console-b.opsloop.internal', 'DNS:console-b.opsloop.internal,IP:192.168.50.12,IP:127.0.0.1'),
}


def openssl(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True, text=True)
    if result.returncode:
        # 개인키/인자 경로를 오류에 싣지 않는다.
        raise RuntimeError('OpenSSL 작업 실패: ' + args[0])
    return result.stdout.strip()


def new_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=False)


def init(ca):
    new_directory(ca)
    config = ca/'ca.cnf'
    config.write_text('''[req]
distinguished_name=dn
x509_extensions=ca
prompt=no
[dn]
CN=OpsLoop Project Root CA
[ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
''')
    openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '1825',
            '-config', config, '-keyout', ca/'ca.key', '-out', ca/'ca.crt')
    (ca/'ca.key').chmod(0o600)
    print(openssl('x509', '-in', ca/'ca.crt', '-noout', '-fingerprint', '-sha256'))
    print('CA 발급 완료. 아직 이 CA를 신뢰하거나 어디에도 배포하지 않았습니다.')


def issue(ca, out):
    if not (ca/'ca.key').is_file() or not (ca/'ca.crt').is_file():
        raise ValueError('CA 파일이 없습니다')
    if (ca/'ca.key').stat().st_mode & 0o077:
        raise ValueError('CA 개인키는 소유자만 읽을 수 있어야 합니다 (0600)')
    openssl('x509', '-in', ca/'ca.crt', '-noout', '-checkend', str(91*86400))
    new_directory(out)
    (out/'ca.crt').write_bytes((ca/'ca.crt').read_bytes())
    for role, (name, san) in ROLES.items():
        folder = out/role
        new_directory(folder)
        config = folder/'request.cnf'
        config.write_text(f'''[req]
distinguished_name=dn
prompt=no
[dn]
CN={name}
''')
        ext = folder/'server.ext'
        ext.write_text(f'''basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName={san}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
''')
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-config', config,
                '-keyout', folder/'server.key', '-out', folder/'server.csr')
        openssl('x509', '-req', '-in', folder/'server.csr', '-CA', ca/'ca.crt', '-CAkey', ca/'ca.key',
                '-set_serial', '0x'+secrets.token_hex(16), '-days', '90', '-sha256', '-extfile', ext,
                '-out', folder/'server.crt')
        (folder/'server.key').chmod(0o600)
        if role == 'console':
            (folder/'console.pem').write_bytes((folder/'server.crt').read_bytes()+(folder/'server.key').read_bytes())
            (folder/'console.pem').chmod(0o600)
    check(out, 21)
    print('90일 인증서 발급 완료. CA 개인키는 발급 폴더에 포함하지 않았습니다.')


def check(out, minimum_days):
    for role in ROLES:
        cert = out/role/'server.crt'
        identity = ('-verify_ip', '192.168.70.254') if role == 'console' else ('-verify_hostname', role+'.opsloop.internal')
        openssl('verify', '-CAfile', out/'ca.crt', '-purpose', 'sslserver', *identity, cert)
        openssl('x509', '-in', cert, '-noout', '-checkend', str(minimum_days*86400))
        public = openssl('x509', '-in', cert, '-pubkey', '-noout')
        if public != openssl('pkey', '-in', out/role/'server.key', '-pubout'):
            raise ValueError('인증서와 개인키가 일치하지 않습니다: '+role)
        print(role+': '+openssl('x509', '-in', cert, '-noout', '-enddate', '-fingerprint', '-sha256'))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['init', 'issue', 'check'])
    parser.add_argument('--ca-dir', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--minimum-days', type=int, default=21)
    args = parser.parse_args()
    if args.command in ('init', 'issue') and args.ca_dir is None:
        parser.error('--ca-dir 필요')
    if args.command in ('issue', 'check') and args.out is None:
        parser.error('--out 필요')
    if not 0 <= args.minimum_days <= 90:
        parser.error('--minimum-days는 0~90')
    os.umask(0o077)
    try:
        if args.command == 'init':
            init(args.ca_dir)
        elif args.command == 'issue':
            issue(args.ca_dir, args.out)
        else:
            check(args.out, args.minimum_days)
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
