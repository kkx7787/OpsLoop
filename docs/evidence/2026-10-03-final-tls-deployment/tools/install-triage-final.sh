#!/usr/bin/env bash
# Run on data01 after copying the verified source to the named /tmp file.
set -euo pipefail
src=/tmp/opsloop-triage-38720bd.py
dst=/opt/opsloop/app/detector/triage.py
backup=/var/backups/opsloop/final-38720bd-cli
expected=a335d78ac01aba636f636efda332359480cdb4753f5df77a1ca84602969ac71e
test "$(sha256sum "$src" | cut -d ' ' -f1)" = "$expected"
python3 - "$src" <<'PY'
import ast, sys
ast.parse(open(sys.argv[1]).read())
print('Source syntax: OK')
PY
test ! -e "$backup/triage.py.before"
sudo -n install -d -m 700 -o root -g root "$backup"
sudo -n cp -p "$dst" "$backup/triage.py.before"
sudo -n sha256sum "$backup/triage.py.before"
sudo -n install -m 644 -o root -g root "$src" "$dst.new"
sudo -n mv "$dst.new" "$dst"
test "$(sha256sum "$dst" | cut -d ' ' -f1)" = "$expected"
sha256sum "$dst"
rm "$src"
set -a
. /etc/opsloop/triage.env
set +a
python3 - <<'PY'
import importlib.util, inspect, os, psycopg2
spec=importlib.util.spec_from_file_location('installed_triage', '/opt/opsloop/app/detector/triage.py')
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
conn=psycopg2.connect(os.environ['DATABASE_URL'], connect_timeout=10)
conn.set_session(readonly=True)
with conn.cursor() as cur:
    cur.execute('SELECT current_user')
    assert cur.fetchone()[0]=='opsloop_console'
    cur.execute('SELECT incident_key FROM incidents ORDER BY created_at DESC LIMIT 1')
    key=cur.fetchone()[0]
    token=mod.workflow_version(cur,key)
    assert token and ':' in token
    print('Installed CLI: console role, read-only workflow version query OK')
assert 'expected_version' in inspect.signature(mod.record).parameters
try:
    mod.record(conn, key, None, 'undetermined', 'not submitted', None, 'qa-not-submitted', None, False)
except ValueError as exc:
    assert 'expected_version' in str(exc)
    print('Missing version rejected before write: OK')
else:
    raise AssertionError('Missing version was accepted')
conn.rollback()
conn.close()
print('No production verdict/action submitted')
PY
