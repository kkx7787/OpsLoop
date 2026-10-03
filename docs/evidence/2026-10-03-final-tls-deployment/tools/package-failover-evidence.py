#!/usr/bin/env python3
"""Package completed raw measurements without changing their timing definitions."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'output/final-development-20261003/deployment/failover'
DEST = ROOT / 'docs/evidence/2026-10-03-final-tls-deployment/failover'
sys.path.insert(0, str(ROOT / 'infra/vmware/restore-drill'))
import drill

result = json.loads((SOURCE / 'summary/results.json').read_text())
runs = result['runs']
assert len(runs) == 6, 'Six complete runs are required'
assert all(len(r['episodes']) == 1 and r['episodes'][0]['pass'] is True for r in runs)
known = []
cookie = Path.home() / '.config/opsloop/probe-cookie'
if cookie.exists():
    known.append(cookie.read_text().strip())
for path in (SOURCE / 'raw').rglob('*'):
    if path.is_file():
        found = drill.find_secrets(path.read_text(), known)
        assert not found, f'Secret-shaped data: {path.name} {found}'

DEST.mkdir(parents=True, exist_ok=True)
for name in ['results.json', 'sha256.json']:
    shutil.copy2(SOURCE / 'summary' / name, DEST / name)
rows = []
for run in runs:
    ep = run['episodes'][0]
    confirmations = [v['confirmed_s'] for v in ep['failover'].values() if v['basis'] != '콘솔 이름 없음 · 실패 없음']
    assert confirmations and all(v is not None for v in confirmations)
    rows.append({
        'run': run['run'], 'scenario': ep['scenario'], 'target': ep['target'],
        'pass': ep['pass'], 'detect_s': ep['detect_s'], 'switchover_s': ep['switchover_s'],
        'other_console_streak_first_request_s': ep['failover_s'],
        'twentieth_success_response_s': max(confirmations),
        'http_failed': ep['fail']['count'], 'http_samples': run['counts']['http'],
        'http_unauthorized': ep['unauthorized']['http_401'], 'ws_unauthorized': ep['unauthorized']['ws_1008'],
        'ws_close_max_s': ep['ws']['zombie_max_s'], 'ws_reconnect_max_s': ep['ws']['reconnect_max_s'],
        'http_p99_ms': ep['latency']['p99_ms'],
    })
out = {'scope': '2026-10-03 production HTTPS; 300 seconds per round; container stop/kill only',
       'source': 'results.json: runs[].episodes[0]; confirmed_s = max of applicable stream values',
       'rows': rows}
(DEST / 'metrics.json').write_text(json.dumps(out, ensure_ascii=False, indent=2) + '\n')
with tarfile.open(DEST / 'raw.tar.xz', 'w:xz') as tar:
    tar.add(SOURCE / 'raw', arcname='raw')
hashes = {str(p.relative_to(SOURCE)): hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted((SOURCE / 'raw').rglob('*')) if p.is_file()}
(DEST / 'raw-sha256.json').write_text(json.dumps(hashes, ensure_ascii=False, indent=2) + '\n')
shutil.copy2(SOURCE.parent / 'failover-run.log', DEST / 'runner.log')
print(json.dumps(out, ensure_ascii=False, indent=2))
