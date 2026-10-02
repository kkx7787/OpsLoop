#!/usr/bin/env python3
"""첫 실행(vitest.json)의 파일 시작 순서를 그대로 따르는 vitest 결과 캐시를 만든다.
vitest 는 캐시의 실패 여부 · 소요가 큰 파일부터 돌리므로, 시작 순서대로 소요를 줄여 적으면 같은 순서가 된다.
사용: make-order-cache.py <첫 실행 vitest.json> <console 경로> > results.json"""
import json
import os
import sys

src, root = sys.argv[1], sys.argv[2]
d = json.load(open(src))
order = sorted(d['testResults'], key=lambda f: f['startTime'])
n = len(order)
results = []
for i, f in enumerate(order):
    rel = os.path.relpath(f['name'], root)
    results.append([':' + rel, {'duration': float((n - i) * 1000), 'failed': False}])
print(json.dumps({'version': '5.0.1', 'results': results}, ensure_ascii=False, separators=(',', ':')))
