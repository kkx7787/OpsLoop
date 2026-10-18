"""같은 원장 폴더의 적재·풀러 수동 실행을 직렬화한다. 잠금 파일은 지우지 않는다."""
import contextlib
import fcntl
import os


class Busy(RuntimeError):
    pass


@contextlib.contextmanager
def run_lock(home, inherited=None):
    os.makedirs(home, exist_ok=True)
    path = os.path.join(home, '.ingest.lock')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if inherited is not None:
            old = int(inherited)
            a, b = os.fstat(old), os.fstat(fd)
            if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                raise ValueError('다른 원장의 잠금 파일입니다')
            # 같은 open file description으로 전달한 잠금만 재사용한다.
            fcntl.flock(old, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield old
        else:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Busy('다른 수집·적재 회차가 실행 중입니다') from exc
            yield fd
    finally:
        os.close(fd)
