"""비신뢰 글자를 밖으로 내보낼 때의 표시 규칙 (이슈 #41). 콘솔 화면의 revealHidden(console/src/lib)과 같은 규칙이다.

숨은 문자는 유니코드 Cf(형식 문자: 방향 제어 · 제로폭 · BOM · 태그 문자)와 Cc(제어 문자) 가운데 탭 · 줄바꿈을 뺀 것이다.
보이는 표식 ⟨U+XXXX⟩ 로 바꾼다. 줄바꿈은 한 줄 안에서 가짜 줄을 만들지 못하게 표식(↵)이나 공백으로 바꾸고, 탭은 공백이다.
짝 없는 서로게이트(Cs)도 표식으로 바꾼다. UTF-8 로 쓸 수 없어 로그 출력 · 알림 전송이 통째로 실패하기 때문이다.
줄 · 문단 구분자(U+2028 · U+2029, Zl · Zp)도 표식으로 바꾼다. 화면 · 알림 카드에서 줄을 끊기 때문이다(콘솔과 같다).
기본 무시 문자(Default_Ignorable) 가운데 Cf 가 아닌 것(한글 채움 U+3164 · 결합 자소 연결 U+034F · 이형 선택자 등)도
아무것도 그리지 않으므로 숨은 문자로 본다. 'adm\u3164in' 이 'admin' 과 같아 보이지 않게 한다.

원문은 DB 에 그대로 둔다(증거). 바꾸는 것은 로그 한 줄 · 알림처럼 밖으로 나가는 모습뿐이다.
"""
import re
import unicodedata

HIDDEN = ("Cf", "Cc", "Cs", "Zl", "Zp")
# 기본 무시 문자 가운데 Cf 가 아닌 것(유니코드 DerivedCoreProperties 의 Default_Ignorable_Code_Point)과 점자 빈칸 U+2800
IGNORABLE = re.compile("[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u2800\u3164\ufe00-\ufe0f\uffa0\ufff0-\ufff8"
                       "\U000e0000-\U000e0fff]")
MORE = "…"


def is_hidden(ch: str) -> bool:
    return unicodedata.category(ch) in HIDDEN or IGNORABLE.match(ch) is not None


def marker(ch: str) -> str:
    return f"⟨U+{ord(ch):04X}⟩"


def reveal(value, *, newline: str = "↵", limit: int | None = None) -> str:
    """숨은 문자를 표식으로, 줄바꿈을 newline 으로, 탭을 공백으로 바꾼다.

    limit 이 있으면 바꾼 결과를 그 글자 수 안에 맞춘다. 넘치면 표식 중간에서 자르지 않고 끝에 '…' 를 붙인다.
    """
    pieces = []
    for ch in str(value):
        if ch == "\n":
            pieces.append(newline)
        elif ch == "\t":
            pieces.append(" ")
        elif is_hidden(ch):
            pieces.append(marker(ch))
        else:
            pieces.append(ch)
    if limit is None or sum(map(len, pieces)) <= limit:
        return "".join(pieces)
    out, size = [], 0
    for piece in pieces:
        if size + len(piece) > limit - len(MORE):
            break
        out.append(piece)
        size += len(piece)
    return "".join(out) + MORE
