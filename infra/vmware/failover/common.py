"""장애 주입 시험 도구의 공통 부분 (이슈 #43). 표준 라이브러리만 쓴다.

  쿠키   프로브용 세션 쿠키를 0600 파일(~/.config/opsloop/probe-cookie)에서 읽는다.
         --mint-cookie <콘솔> 은 ssh 로 콘솔 컨테이너 안에서 auth.issue("failover-probe", "viewer") 를 불러 받아 그 파일에만 둔다.
         비밀번호 없이 서버 비밀(SESSION_SECRET)로 발급한 viewer 12시간 쿠키다. 두 콘솔이 같은 비밀을 쓰므로 어느 쪽에서 받아도 된다.
         화면 · 로그 · 기록 파일에 찍지 않는다. 시험이 끝나면 지운다(--drop-cookie 또는 rm).
  기록   JSONL 한 줄씩 쓴다. 스레드 여럿이 함께 써도 줄이 섞이지 않는다.
  시각   기록의 시각은 모두 Mac 벽시계(epoch ns)다. 지연은 단조 시계로 잰다.
"""

import base64
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

DEFAULT_URL = "http://192.168.70.254:8443"       # 콘솔 진입점(HAProxy frontend console)
COOKIE_NAME = "opsloop_session"                  # app/auth.py COOKIE
COOKIE_FILE = os.path.join("~", ".config", "opsloop", "probe-cookie")
PROBE_USER, PROBE_ROLE = "failover-probe", "viewer"
# app/auth.issue 의 꼴: base64url(본문) + "." + 서명 앞 32자(hex)
COOKIE_RE = re.compile(r"^[A-Za-z0-9_-]{8,1024}\.[0-9a-f]{32}$")
# 쿠키처럼 생긴 글자. 원격 오류 문구를 찍기 전에 가린다
COOKIE_LIKE = re.compile(r"[A-Za-z0-9_-]{8,}\.[0-9a-f]{32}")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
RUN_RE = re.compile(r"[^A-Za-z0-9_.-]")
# 서버 · 원격이 정하는 글자를 기록 · 화면에 넣기 전에 '?' 로 바꾼다 (C0 · DEL · C1)
CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# 콘솔 컨테이너 안에서 쿠키를 만든다. 결과는 표준 출력 한 줄뿐이고 여기서 받아 파일에만 쓴다
MINT_REMOTE = ("docker exec opsloop-api python3 -c "
               "'import auth; print(auth.issue(\"%s\", \"%s\"))'" % (PROBE_USER, PROBE_ROLE))


class ToolError(Exception):
    """사용자에게 한 줄로 보이고 종료 코드 2 로 끝나는 오류."""


def now_ns() -> int:
    return time.time_ns()


def iso(ns) -> str:
    """epoch ns → UTC ISO 문자열."""
    if ns is None:
        return None
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).isoformat()


def clean(value, n=64):
    """서버 · 원격이 준 글자를 한 줄로 정리한다. 문자열이 아니면 None."""
    if not isinstance(value, str):
        return None
    return CTRL.sub("?", value)[:n]


def run_name(run_dir: str, given=None) -> str:
    """회차 이름. 주지 않으면 폴더 이름. 쿼리 · 기록에 넣으므로 [A-Za-z0-9_.-] 만 남긴다."""
    name = given or os.path.basename(os.path.normpath(run_dir)) or "run"
    return RUN_RE.sub("_", name)[:64]


def ssh_base():
    return ["ssh", "-F", os.path.expanduser(os.path.join("~", ".ssh", "config.opsloop")),
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]


def split_url(url: str):
    """'http://호스트:포트' → (scheme, host, port, origin). 경로는 쓰지 않는다."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ToolError("주소는 http(s)://호스트:포트 꼴이어야 한다: %s" % clean(url, 120))
    port = parts.port or (443 if parts.scheme == "https" else 80)
    host = parts.hostname
    shown = "[%s]" % host if ":" in host else host
    return parts.scheme, host, port, "%s://%s:%d" % (parts.scheme, shown, port)


# ──────────────────────────────────────────────────────────────
#  쿠키
# ──────────────────────────────────────────────────────────────
def cookie_path(path=None) -> str:
    return os.path.expanduser(path or COOKIE_FILE)


def cookie_expiry(token: str):
    """쿠키 본문의 만료(epoch 초). 풀 수 없으면 None. 본문은 서명 없이도 읽힌다(아이디 · 역할 · 만료뿐)."""
    try:
        payload = token.rpartition(".")[0]
        body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return int(body["e"])
    except (ValueError, KeyError, TypeError):
        return None


def load_cookie(path=None) -> str:
    """0600 파일에서 쿠키를 읽는다. 권한 · 꼴 · 만료가 맞지 않으면 ToolError (쿠키 값은 문구에 넣지 않는다)."""
    path = cookie_path(path)
    try:
        st = os.stat(path)
    except FileNotFoundError:
        raise ToolError("쿠키 파일이 없다: %s (--mint-cookie console-a 로 받는다)" % path)
    if not os.path.isfile(path):
        raise ToolError("쿠키 파일이 일반 파일이 아니다: %s" % path)
    if st.st_mode & 0o077:
        raise ToolError("쿠키 파일 권한이 0600 이 아니다: %s (%o). chmod 600 뒤 다시" % (path, st.st_mode & 0o777))
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise ToolError("쿠키 파일 소유자가 내가 아니다: %s" % path)
    with open(path, encoding="ascii", errors="replace") as f:
        token = f.read(4096).strip()
    if not COOKIE_RE.match(token):
        raise ToolError("쿠키 파일 내용이 세션 쿠키 꼴이 아니다: %s" % path)
    exp = cookie_expiry(token)
    if exp is not None and exp <= time.time():
        raise ToolError("쿠키가 만료됐다 (%s). --mint-cookie 로 다시 받는다" % iso(exp * 10 ** 9))
    return token


def write_secret(path: str, text: str) -> None:
    """0600 으로 새로 만들어 바꿔 넣는다. 폴더는 0700."""
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    tmp = "%s.tmp%d" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, text.encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def mask(text: str, *secrets_) -> str:
    """원격 문구에서 쿠키 · 쿠키처럼 생긴 글자를 가린다."""
    for s in secrets_:
        if s:
            text = text.replace(s, "***")
    return COOKIE_LIKE.sub("***", text)


def mint_cookie(host: str, path=None, timeout=60) -> str:
    """ssh <host> 로 콘솔 컨테이너 안에서 쿠키를 받아 0600 파일에 둔다. 돌려주는 값은 화면에 쓰지 않을 요약이다."""
    if not HOST_RE.match(host or ""):
        raise ToolError("ssh 별칭이 이상하다: %s" % clean(host, 64))
    path = cookie_path(path)
    try:
        p = subprocess.run(ssh_base() + [host, MINT_REMOTE], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except FileNotFoundError:
        raise ToolError("ssh 가 없다")
    except subprocess.TimeoutExpired:
        raise ToolError("%s 에서 %d초 안에 쿠키를 받지 못했다" % (host, timeout))
    out = p.stdout.decode("ascii", "replace").strip().splitlines()
    token = out[-1].strip() if out else ""
    if p.returncode != 0 or not COOKIE_RE.match(token):
        err = mask(p.stderr.decode("utf-8", "replace"), token)
        last = [x for x in err.strip().splitlines() if x.strip()][-1:] or ["(오류 문구 없음)"]
        raise ToolError("%s 에서 쿠키를 받지 못했다 (종료 %d): %s" % (host, p.returncode, clean(last[0], 200)))
    write_secret(path, token + "\n")
    exp = cookie_expiry(token)
    return "쿠키를 받았다: %s · %s · 만료 %s → %s (0600). 시험 뒤 지운다: --drop-cookie" % (
        PROBE_USER, PROBE_ROLE, iso(exp * 10 ** 9) if exp else "?", path)


def drop_cookie(path=None) -> str:
    path = cookie_path(path)
    try:
        os.remove(path)
    except FileNotFoundError:
        return "쿠키 파일이 없다: %s" % path
    return "쿠키 파일을 지웠다: %s" % path


def add_cookie_args(parser) -> None:
    parser.add_argument("--cookie-file", default=None,
                        help="프로브 쿠키 파일 (기본 ~/.config/opsloop/probe-cookie, 0600 이어야 한다)")
    parser.add_argument("--mint-cookie", metavar="콘솔", default=None,
                        help="ssh 로 이 콘솔(console-a · console-b) 컨테이너 안에서 viewer 12시간 쿠키를 받아 파일에만 두고 끝낸다")
    parser.add_argument("--drop-cookie", action="store_true", help="쿠키 파일을 지우고 끝낸다")


def cookie_command(args) -> bool:
    """--mint-cookie · --drop-cookie 를 처리했으면 True."""
    if args.mint_cookie:
        print(mint_cookie(args.mint_cookie, args.cookie_file), file=sys.stderr)
        return True
    if args.drop_cookie:
        print(drop_cookie(args.cookie_file), file=sys.stderr)
        return True
    return False


# ──────────────────────────────────────────────────────────────
#  기록
# ──────────────────────────────────────────────────────────────
class JsonlWriter:
    """덧붙여 쓰는 JSONL. 한 줄씩 잠그고 쓰고 비운다."""

    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._f = open(path, "a", encoding="utf-8")

    def write(self, record: dict) -> None:
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._lock:
            if self._f.closed:       # 끝낸 뒤 늦게 끝난 요청은 버린다
                return
            self._f.write(line)
            self._f.flush()

    def close(self) -> None:
        with self._lock:
            self._f.close()


def read_jsonl(path: str) -> list:
    """깨진 줄(중간에 끊긴 마지막 줄 등)은 건너뛴다."""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    out.append(rec)
    except FileNotFoundError:
        pass
    return out


def _interrupt(_signum, _frame):
    raise KeyboardInterrupt


def stop_signals():
    """Ctrl-C 와 kill(SIGTERM) 둘 다 정리하고 끝나게 한다.
    백그라운드(&)로 띄운 프로세스는 SIGINT 가 무시된 채 시작하므로 되살린다."""
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, _interrupt)


def main_guard(fn):
    """ToolError 는 한 줄로, Ctrl-C 는 130 으로 끝낸다."""
    try:
        return fn()
    except ToolError as e:
        print("오류: %s" % e, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
