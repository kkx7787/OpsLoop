#!/usr/bin/env python3
"""raw/ 의 재현 결과를 조건별로 모아 results.tsv · micro-results.tsv 를 쓴다.
사용: summarize.py (repro/ 에서)"""
import glob
import json
import os
import re
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, 'raw')
sys.path.insert(0, HERE)
from analyze import one  # noqa: E402


def rng(v, nd=0):
    if not v:
        return '-'
    f = (lambda x: f'{x:.{nd}f}')
    return f'{f(st.median(v))} ({f(min(v))}~{f(max(v))})'


def secs(t):
    h, m, s = t.split(':')
    return int(h) * 3600 + int(m) * 60 + float(s)


def samples():
    rows = []
    for ln in open(os.path.join(RAW, 'load-samples.tsv')):
        p = ln.rstrip('\n').split('\t')
        m = re.search(r'([\d.]+)% idle', p[2])
        rows.append((secs(p[0]), float(p[1].split('=')[1]), float(m.group(1)) if m else None))
    return rows


def runs():
    out = {}
    for ln in list(open(os.path.join(RAW, 'runs.tsv')))[1:]:
        p = ln.rstrip('\n').split('\t')
        out[p[0]] = {'start': secs(p[3]), 'end': secs(p[4]), 'rc': int(p[5])}
    return out


GROUPS = [
    ('검토 첫 실행(17:09, 기본 작업자 7 · tsc -b 동시)', ['../../vitest.json']),
    ('검토 전체 재실행(17:17, --maxWorkers=4)', ['../../vitest-retry.json']),
    ('(a) router.test.tsx 단독', 'a-file-*.json'),
    ('(a) -t 로 404 시험만', 'a-only-*.json'),
    ('(b) 전체 · 기본 작업자(7)', 'b-full-*.json'),
    ('(c) 전체 · --maxWorkers=4', 'c-w4-*.json'),
    ('(d) 전체 · 기본 작업자 + npm run build 동시', 'd-build-*.json'),
    ('(추가 e) router.test.tsx 단독 + yes 64개', 'e-file-burn64-*.json'),
    ('(추가 f) 전체 · 기본 작업자 + npm run build + yes 12개', 'f-build-burn12-*.json'),
]


def main():
    smp, rr = samples(), runs()
    lines = ['조건\t횟수\t404 시험 실패\t다른 시험 실패\t404 시험 ms 중앙값(최소~최대)\t같은 파일 다른 시험 ms 중앙값(최소~최대)\t파일 소요 합 s\t전체 소요 s\t빌드 s\tCPU 유휴 % 평균\t1분 부하 평균\t실패 때 <main> 의 h1']
    for title, pat in GROUPS:
        paths = [os.path.join(RAW, p) for p in pat] if isinstance(pat, list) else sorted(glob.glob(os.path.join(RAW, pat)))
        rs = [one(p) for p in paths]
        f404 = sum(1 for r in rs if r.get('t404_status') == 'failed')
        other = [t for r in rs for t in r['failed_tests'] if '404 화면' not in t]
        builds, idle, load = [], [], []
        for p in paths:
            tag = os.path.basename(p)[:-5]
            bt = os.path.join(RAW, tag + '.build.time')
            if os.path.exists(bt):
                s, e, _ = open(bt).read().split('\t')
                builds.append(secs(e) - secs(s))
            if tag in rr:
                w = [x for x in smp if rr[tag]['start'] <= x[0] <= rr[tag]['end']]
                idle += [x[2] for x in w if x[2] is not None]
                load += [x[1] for x in w]
        mains = sorted({r.get('t404_main_text') or '(잘림)' for r in rs if r.get('t404_status') == 'failed'})
        lines.append('\t'.join([
            title, str(len(rs)), str(f404), f'{len(other)} ' + ('· '.join(sorted(set(other))) if other else ''),
            rng([r['t404_ms'] for r in rs]), rng([x for r in rs for x in r['router_other_ms']]),
            rng([r['file_sum_s'] for r in rs], 1), rng([r['wall_s'] for r in rs], 1), rng(builds, 1),
            f'{st.mean(idle):.0f}' if idle else '-', f'{st.mean(load):.1f}' if load else '-', ' / '.join(mains) or '-',
        ]))
    open(os.path.join(HERE, 'results.tsv'), 'w').write('\n'.join(lines) + '\n')

    mlines = ['조건\t시험\t횟수\t실패\t그리기 ms\t그린 직후 본문 h1\t404 제목이 DOM 에 생긴 시각 ms\t대기(waitFor) ms\t첫 확인 1회 ms\t확인 횟수\t다 그린 뒤 getByRole 1회 ms\t요소 수']
    for f in sorted(glob.glob(os.path.join(RAW, 'micro-*.jsonl'))):
        name = os.path.basename(f)[6:-6]
        rows = [json.loads(x) for x in open(f)]
        for lab in ('cold', 'warm1', 'warm2'):
            r = [x for x in rows if x['label'] == lab]
            if not r:
                continue
            mlines.append('\t'.join([
                name, {'cold': '첫 시험(냉시동)', 'warm1': '두 번째', 'warm2': '세 번째'}[lab], str(len(r)), str(sum(x['failed'] for x in r)),
                rng([x['render_ms'] for x in r]), ' / '.join(sorted({x['h1_at_render'] or '-' for x in r})),
                rng([x['heading_in_dom_ms'] for x in r if x['heading_in_dom_ms'] >= 0]) + (f' · 미출현 {sum(1 for x in r if x["heading_in_dom_ms"] < 0)}' if any(x['heading_in_dom_ms'] < 0 for x in r) else ''),
                rng([x['wait_ms'] for x in r]), rng([x['check_log'][0]['cost'] for x in r], 1), rng([x['checks'] for x in r]),
                rng([x['getByRole_after_ms'] for x in r if not x['failed']], 1), str(r[0]['elements']),
            ]))
    open(os.path.join(HERE, 'micro-results.tsv'), 'w').write('\n'.join(mlines) + '\n')


if __name__ == '__main__':
    main()
