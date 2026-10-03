#!/usr/bin/env python3
"""Authorized HTTPS regression: 3 container stops + 3 kills, existing 300s protocol.

No VM power-off, DB mutation, or external notification. Existing viewer cookie only.
Every round restores the target before advancing; a failed gate stops the suite.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from datetime import datetime

ROOT = Path('/Users/hanseongmin/opsloop-repo')
OUT = ROOT / 'output/final-development-20261003/deployment/failover'
TOOLS = ROOT / 'infra/vmware/failover'
SSH = ['ssh', '-F', str(Path.home()/'.ssh/config.opsloop'), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10']
STATE_CMD = 'echo "@1 show servers state consoles" | sudo -n nc -N -U /run/haproxy-master.sock'
ACTIVE = None
PROCS = []

def log(message):
    print(datetime.now().astimezone().isoformat(timespec='seconds'), message, flush=True)

def run(args, **kw):
    return subprocess.run([str(x) for x in args], check=True, text=True, **kw)

def state():
    result = run(SSH + ['fw', STATE_CMD], capture_output=True).stdout
    rows = [r.split() for r in result.splitlines() if len(r.split()) >= 7 and not r.startswith('#')]
    ok = len(rows) == 2 and all(r[5:7] == ['2', '0'] for r in rows)
    return ok, result

def wait_ready():
    for _ in range(45):
        ok, result = state()
        if ok:
            return result
        time.sleep(2)
    raise RuntimeError('Both consoles did not return UP/ready within 90s')

def mark(folder, kind, scenario, target):
    run([sys.executable, TOOLS/'mark.py', folder, kind, '--scenario', scenario, '--target', target])

def cleanup():
    global ACTIVE
    if ACTIVE:
        folder, scenario, target = ACTIVE
        log('Cleanup: restarting ' + target)
        try:
            mark(folder, 'recover', scenario, target)
            run(SSH + [target, 'docker start opsloop-api'], timeout=45)
            ACTIVE = None
        except Exception as e:
            log('RECOVERY NEEDS ATTENTION: ' + str(e))
    for proc in PROCS:
        if proc.poll() is None:
            proc.terminate()

def interrupted(signum, frame):
    raise KeyboardInterrupt

def round_run(name, target, scenario):
    global ACTIVE
    folder = OUT/'raw'/name
    folder.mkdir(parents=True, exist_ok=False)
    now = datetime.now()
    minute = now.hour * 60 + now.minute
    if any(start <= minute < end for start, end in [(258,285),(738,765),(1218,1245)]):
        raise RuntimeError('Regular backup window; no injection')
    log('START ' + name)
    (folder/'before.txt').write_text(wait_ready())
    commands = [
        ['bash', TOOLS/'collect_fw.sh', folder, '--duration', '300'],
        [sys.executable, TOOLS/'probe_http.py', '--run-dir', folder, '--duration', '300'],
        [sys.executable, TOOLS/'probe_ws.py', '--run-dir', folder, '--mode', 'browser', '--conns', '4', '--duration', '300'],
        [sys.executable, TOOLS/'probe_ws.py', '--run-dir', folder, '--mode', 'net', '--conns', '4', '--duration', '300'],
    ]
    handles = []
    PROCS.clear()
    try:
        for label, command in zip(['fw','http','ws-browser','ws-net'], commands):
            handle = (folder/(label+'.out')).open('w')
            handles.append(handle)
            PROCS.append(subprocess.Popen([str(x) for x in command], cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT))
        time.sleep(30)
        if not state()[0] or any(p.poll() is not None for p in PROCS):
            raise RuntimeError('Pre-injection state/probe gate failed')
        http = [json.loads(x) for x in (folder/'http.jsonl').read_text().splitlines()]
        if len(http) < 100 or any(x['error'] for x in http):
            raise RuntimeError('Baseline HTTP not healthy; no injection')
        ws = [json.loads(x) for x in (folder/'ws.jsonl').read_text().splitlines()]
        (folder/'baseline-check.json').write_text(json.dumps({'http_samples':len(http),'http_errors':0,'ws_events':len(ws)}, indent=2)+'\n')
        mark(folder, 'inject', scenario, target)
        ACTIVE = (folder, scenario, target)
        run(SSH + [target, 'docker ' + scenario + ' opsloop-api'], timeout=45)
        log('INJECTED ' + name)
        time.sleep(150)
        mark(folder, 'recover', scenario, target)
        run(SSH + [target, 'docker start opsloop-api'], timeout=45)
        ACTIVE = None
        log('RECOVERED ' + name)
        for proc in PROCS:
            if proc.wait(timeout=400) != 0:
                raise RuntimeError('Probe/collector failed')
        (folder/'after.txt').write_text(wait_ready())
        run([sys.executable, TOOLS/'summarize.py', folder, '--out', OUT/'check'/name])
        log('PASS ' + name)
    finally:
        cleanup()
        for handle in handles:
            handle.close()

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    keep_awake = subprocess.Popen(['caffeinate','-dims','-w',str(os.getpid())])
    try:
        for spec in [('t01-stop-a','console-a','stop'),('t02-stop-b','console-b','stop'),('t03-stop-a','console-a','stop'),('t04-kill-a','console-a','kill'),('t05-kill-b','console-b','kill'),('t06-kill-a','console-a','kill')]:
            round_run(*spec)
        run([sys.executable, TOOLS/'summarize.py', OUT/'raw', '--out', OUT/'summary'])
        log('ALL SIX ROUNDS COMPLETE')
    finally:
        cleanup()
        keep_awake.terminate()

if __name__ == '__main__':
    main()
