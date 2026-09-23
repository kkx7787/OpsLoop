"""화면용 판정 제안. 탐지 임계치나 심각도를 정답으로 사용하지 않는다.

9/8 판정 기준과 9/18 화면 설계를 따른다. R001·R005는 별도 행위 근거로
제안하고, 순환 규칙은 이미 위협으로 판정된 사건과의 중복만 제안한다.
웹·감사·인프라 규칙에 SSH 판정 기준을 임의로 옮기지 않는다.
"""


def propose(rule_id, counts, covered_by=None):
    def result(verdict, *reasons):
        return {"verdict": verdict, "reasons": list(reasons)}

    if rule_id not in {"R001", "R002", "R003", "R004", "R005"}:
        return result(None, "이 규칙 유형에는 자동 제안 기준이 없습니다. 증거를 보고 직접 판정하세요.")
    if covered_by:
        return result("non_actionable", f"같은 출발지·겹치는 구간에 이미 실제 위협으로 판정된 사건이 있습니다: {covered_by}",
                      "대표 사건의 조치 범위를 확인한 뒤 중복 여부를 판정하세요.")
    if rule_id in {"R002", "R003", "R004"}:
        return result(None, "규칙 조건과 위협 판정 근거가 겹칩니다. 같은 증거를 정답으로 재사용하지 않고 직접 판정하세요.")

    fails = counts.get("cowrie.login.failed", 0)
    oks = counts.get("cowrie.login.success", 0)
    cmds = counts.get("cowrie.command.input", 0)
    files = sum(n for event, n in counts.items() if event.startswith("cowrie.session.file_"))
    proxy = counts.get("cowrie.direct-tcpip.request", 0)
    facts = f"관측 구간: 로그인 실패 {fails} · 성공 {oks} · 명령 {cmds} · 파일 {files} · 경유 시도 {proxy}"
    if cmds or files or proxy:
        return result("threat", facts, "빈도 조건과 별도로 명령 실행·파일 이동·경유 시도 중 하나가 관측됐습니다.")
    if oks or fails:
        return result("non_actionable", facts, "관측 구간에는 인증 시도만 있고 후속 명령·파일 이동·경유 시도는 없습니다. 지속성과 조치 필요성을 확인하세요.")
    return result(None, "근거가 될 행위 기록이 없습니다. 수집 누락을 정상으로 판단하지 않고 직접 확인하세요.")
