#!/usr/bin/env python3
"""vitest JSON 결과에서 404 시험(router.test.tsx 첫 시험)의 소요 · 실패와 실행 조건을 뽑는다.
사용: analyze.py <결과.json>... (표준 출력은 JSON 줄, 한 줄에 실행 하나)"""
import json
import re
import sys

ROUTER = 'src/app/router.test.tsx'
TEST = '없는 주소는 틀 안에서 404 화면: 주소 표시 · 대시보드 링크'
ANSI = re.compile(r'\x1b\[[0-9;]*m')


def main_text(msg):
    """실패 메시지의 DOM 에서 <main> 부분을 뽑아 보이는 글자만 남긴다."""
    plain = ANSI.sub('', msg)
    i = plain.find('<main')
    if i < 0:
        return None, plain
    j = plain.find('</main>', i)
    seg = plain[i:j if j > 0 else len(plain)]
    lines = [ln.strip() for ln in seg.splitlines()]
    text = [ln for ln in lines if ln and not ln.startswith('<') and not ln.startswith('/>') and not ln.startswith('>') and '=' not in ln]
    return ' | '.join(text), plain


def one(path):
    d = json.load(open(path))
    t0 = d['startTime']
    files = d['testResults']
    ends = [f['endTime'] for f in files]
    order = sorted(files, key=lambda f: f['startTime'])
    out = {
        'file': path.rsplit('/', 1)[-1],
        'tests': d['numTotalTests'],
        'failed': d['numFailedTests'],
        'wall_s': round((max(ends) - t0) / 1000, 2),
        'file_sum_s': round(sum(f['endTime'] - f['startTime'] for f in files) / 1000, 1),
        'failed_tests': [a['fullName'] for f in files for a in f['assertionResults'] if a['status'] == 'failed'],
    }
    for idx, f in enumerate(order):
        if not f['name'].endswith(ROUTER):
            continue
        s, e = f['startTime'], f['endTime']
        # 이 파일이 시작할 때 함께 돌던 파일 수(이 파일 제외)
        overlap = sum(1 for g in files if g is not f and g['startTime'] <= s < g['endTime'])
        overlap_any = sum(1 for g in files if g is not f and g['startTime'] < e and s < g['endTime'])
        out.update({
            'router_order': idx + 1,
            'files': len(files),
            'router_start_s': round((s - t0) / 1000, 2),
            'router_file_ms': round(e - s),
            'router_concurrent_at_start': overlap,
            'router_overlapping_files': overlap_any,
        })
        others = []
        for a in f['assertionResults']:
            if a['title'] == TEST or a['fullName'].endswith(TEST):
                out['t404_status'] = a['status']
                out['t404_ms'] = round(a.get('duration') or 0, 1)
                if a['status'] == 'failed':
                    msg = '\n'.join(a['failureMessages'])
                    main, plain = main_text(msg)
                    out['t404_error'] = plain.splitlines()[0][:200]
                    out['t404_main_text'] = main
                    out['t404_login_loading'] = '로그인 정보를 확인하는 중입니다' in plain
                    out['t404_has_notfound'] = '페이지를 찾을 수 없습니다' in plain
            elif a['status'] in ('passed', 'failed'):
                others.append(round(a.get('duration') or 0, 1))
        out['router_other_ms'] = others
    return out


if __name__ == '__main__':
    for p in sys.argv[1:]:
        print(json.dumps(one(p), ensure_ascii=False))
