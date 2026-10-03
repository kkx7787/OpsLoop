#!/usr/bin/env python3
"""Read final runtime state; this script never changes services or accounts."""
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import ssl
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SSH = ['ssh','-F',str(Path.home()/'.ssh/config.opsloop'),'-o','BatchMode=yes','-o','ConnectTimeout=10']
def command(argv):
    proc = subprocess.run(argv,text=True,capture_output=True,timeout=30)
    return {'returncode':proc.returncode,'stdout':proc.stdout.strip(),'stderr':proc.stderr.strip()}
watch = Path.home()/'Library/Application Support/OpsLoop/bin/console-watch.sh'
source = ROOT/'infra/vmware/scripts/console-watch.sh'
context = ssl.create_default_context(cafile=str(Path.home()/'.config/opsloop/tls/ca.crt'))
con=http.client.HTTPSConnection('192.168.70.254',8443,context=context,timeout=10)
con.request('GET','/health')
response=con.getresponse()
status=response.status
response.read()
con.close()
result={
    'at':datetime.now(timezone.utc).isoformat(), 'https_health':status,
    'console_a':command(SSH+['console-a',"docker inspect -f '{{.Image}} {{.State.Running}} {{.HostConfig.RestartPolicy.Name}}' opsloop-api"]),
    'haproxy':command(SSH+['fw',"echo '@1 show servers state consoles' | sudo -n nc -N -U /run/haproxy-master.sock"]),
    'data_node':command(SSH+['data01',"systemctl is-active opsloop-data-health.timer; systemctl is-enabled opsloop-data-health.timer; systemctl show -p Id -p Result -p ExecMainStatus -p ExecMainExitTimestamp opsloop-data-health.service opsloop-ingest.service opsloop-agents.service; docker inspect -f '{{.State.Running}}' opsloop-db; sha256sum /opt/opsloop/app/detector/triage.py"]),
    'watch_status':command(['bash',str(watch),'--status']),
    'watch_source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
    'watch_installed_sha256':hashlib.sha256(watch.read_bytes()).hexdigest(),
    'probe_cookie_exists':(Path.home()/'.config/opsloop/probe-cookie').exists(),
    'restore_secret_dir_exists':(Path.home()/'.config/opsloop/drill').exists(),
    'running_vms':command(['/Applications/VMware Fusion.app/Contents/Library/vmrun','list']),
}
result['watch_matches_source']=result['watch_installed_sha256']==result['watch_source_sha256']
path=ROOT/'output/final-development-20261003/deployment/final-runtime.json'
path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(result,ensure_ascii=False,indent=2))
assert status==200 and result['watch_matches_source']
