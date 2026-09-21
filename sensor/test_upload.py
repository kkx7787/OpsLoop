"""업로더 단위 테스트. 실제 S3 대신 올린 객체를 모아 두는 가짜 클라이언트를 쓴다.
가짜 클라이언트는 조건부 쓰기(If-None-Match: *)를 흉내 낸다: 같은 키가 있으면 412.

실행: python3 sensor/test_upload.py
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import upload  # noqa: E402


class PreconditionFailed(Exception):
    response = {"Error": {"Code": "PreconditionFailed"}}


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.puts = 0

    def put_object(self, Bucket, Key, Body, **kw):
        self.puts += 1
        if Key.startswith("raw/") and Key in self.objects:
            raise PreconditionFailed()
        self.objects[Key] = Body


def rebuilt(s3, sensor="cowrie"):
    """올린 조각을 파일(inode+세대) 별로 이어 붙여 원문을 다시 만든다."""
    by_file = {}
    for key, body in s3.objects.items():
        if not key.startswith(f"raw/v1/sensor={sensor}/"):
            continue
        fid = key.split("/ino=")[1].split("/")[0]
        start = int(key.rsplit("/", 1)[1].split("-")[0])
        by_file.setdefault(fid, []).append((start, body))
    out = {}
    for fid, parts in by_file.items():
        # 겹치는 조각이 있으면 앞에서 이미 덮은 부분은 건너뛴다 (내부 적재도 line_hash 로 한 번만 넣는다)
        data, end = b"", 0
        for start, body in sorted(parts):
            if start + len(body) > end:
                data += body[max(0, end - start):]
                end = start + len(body)
        out[fid] = data
    return out


class UploaderTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.state = {}
        self.s3 = FakeS3()
        self._chunk, self._cap = upload.CHUNK, upload.RUN_CAP

    def tearDown(self):
        upload.CHUNK, upload.RUN_CAP = self._chunk, self._cap

    def run_once(self, path, sensor="cowrie"):
        return upload.upload_file(self.s3, "b", "i-test", sensor, path, self.state, dry_run=False)

    def write(self, name, data, mode="ab"):
        p = os.path.join(self.dir, name)
        with open(p, mode) as f:
            f.write(data)
        return p

    def test_반쪽_줄은_다음_회차로(self):
        p = self.write("cowrie.json", b'{"a":1}\n{"a":2', "wb")
        self.run_once(p)
        self.assertEqual(list(rebuilt(self.s3).values()), [b'{"a":1}\n'])
        self.write("cowrie.json", b'}\n')
        self.run_once(p)
        self.assertEqual(list(rebuilt(self.s3).values()), [b'{"a":1}\n{"a":2}\n'])

    def test_회전해도_이어서_올린다(self):
        p = self.write("cowrie.json", b'L1\nL2\n', "wb")
        self.run_once(p)
        rotated = os.path.join(self.dir, "cowrie.json.2026-09-21")
        os.rename(p, rotated)                            # 이름만 바뀌고 inode 는 같다
        self.write("cowrie.json.2026-09-21", b'L3\n')
        self.run_once(rotated)
        new = self.write("cowrie.json", b'N1\n', "wb")   # 새 파일은 새 inode
        self.run_once(new)
        self.assertEqual(sorted(rebuilt(self.s3).values()), [b'L1\nL2\nL3\n', b'N1\n'])

    def test_두번_돌려도_중복으로_올리지_않는다(self):
        p = self.write("cowrie.json", b'L1\n', "wb")
        self.run_once(p)
        puts = self.s3.puts
        self.assertEqual(self.run_once(p), 0)
        self.assertEqual(self.s3.puts, puts)

    def test_줄_내용을_바꾸지_않는다(self):
        # 한글, 줄 끝 공백, CRLF, 깨진 바이트까지 그대로 올라가야 한다
        raw = b'{"k":"\xed\x95\x9c\xea\xb8\x80"}  \r\n\xff\xfe broken\n'
        p = self.write("cowrie.json", raw, "wb")
        self.run_once(p)
        self.assertEqual(list(rebuilt(self.s3).values()), [raw])

    def test_파일이_줄면_새_세대로_다시(self):
        p = self.write("cowrie.json", b'L1\nL2\n', "wb")
        self.run_once(p)
        self.write("cowrie.json", b'X1\n', "wb")          # 같은 inode 에 덮어써 줄어듦
        self.run_once(p)
        gens = {k.split("/ino=")[1].split("/")[0].split(".")[1] for k in self.s3.objects}
        self.assertEqual(gens, {"g0", "g1"})               # 앞 세대 원장을 덮어쓰지 않는다

    def test_큰_파일은_줄_경계에서_나눈다(self):
        upload.CHUNK = 10
        p = self.write("cowrie.json", b'aaaa\nbbbb\ncccc\n', "wb")
        self.run_once(p)
        self.assertGreater(len(self.s3.objects), 1)
        self.assertEqual(list(rebuilt(self.s3).values()), [b'aaaa\nbbbb\ncccc\n'])

    def test_CHUNK_보다_긴_한_줄은_통째로(self):
        # 검토에서 나온 결함: 긴 줄 하나 때문에 그 뒤가 영구히 멈추면 안 된다
        upload.CHUNK = 8
        data = b'short\n' + b'X' * 40 + b'\nafter1\nafter2\n'
        p = self.write("cowrie.json", data, "wb")
        self.run_once(p)
        self.assertEqual(list(rebuilt(self.s3).values()), [data])
        self.assertTrue(any(body == b'X' * 40 + b'\n' for body in self.s3.objects.values()))

    def test_아직_쓰이는_긴_줄은_기다린다(self):
        upload.CHUNK = 8
        p = self.write("cowrie.json", b'ok\n' + b'Y' * 30, "wb")   # 줄바꿈 없이 끝남
        self.run_once(p)
        self.assertEqual(list(rebuilt(self.s3).values()), [b'ok\n'])
        self.write("cowrie.json", b'\nend\n')
        self.run_once(p)
        self.assertEqual(list(rebuilt(self.s3).values()), [b'ok\n' + b'Y' * 30 + b'\nend\n'])

    def test_올린_뒤_상태_저장_전에_죽어도_이어진다(self):
        p = self.write("cowrie.json", b'L1\n', "wb")
        self.run_once(p)
        self.state.clear()                                  # PUT 은 됐는데 상태 저장 전에 죽었다
        self.run_once(p)                                    # 같은 조각 → 412 → 이미 있음으로 넘어감
        self.assertEqual(self.state[next(iter(self.state))]["offset"], 3)
        self.write("cowrie.json", b'L2\n')
        self.run_once(p)
        self.assertEqual(list(rebuilt(self.s3).values()), [b'L1\nL2\n'])
        self.assertEqual(len(self.s3.objects), 2)

    def test_회차_상한을_지킨다(self):
        upload.CHUNK, upload.RUN_CAP = 4, 8
        p = self.write("cowrie.json", b'aaa\nbbb\nccc\nddd\n', "wb")
        self.assertEqual(self.run_once(p), 8)
        self.assertEqual(self.run_once(p), 8)
        self.assertEqual(list(rebuilt(self.s3).values()), [b'aaa\nbbb\nccc\nddd\n'])

    def test_심볼릭_링크는_거부한다(self):
        target = self.write("secret.txt", b'top secret\n', "wb")
        link = os.path.join(self.dir, "cowrie.json.2099-01-01")
        os.symlink(target, link)
        with self.assertRaises(OSError):
            self.run_once(link)
        self.assertEqual(self.s3.objects, {})

    def test_이름_규칙에_맞는_파일만_고른다(self):
        for n in ["cowrie.json", "cowrie.json.2026-09-21", "cowrie.json.x", "cowrie.log", "decoy.json.2026-09-21"]:
            self.write(n, b'x\n', "wb")
        got = sorted(os.path.basename(p) for _, p in
                     upload.sources(f"cowrie:{self.dir}/cowrie.json*,decoy:{self.dir}/decoy.json.*"))
        self.assertEqual(got, ["cowrie.json", "cowrie.json.2026-09-21", "decoy.json.2026-09-21"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
