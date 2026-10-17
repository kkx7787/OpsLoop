"""디코이의 첫 요청과 후속 행위가 같은 세션으로 기록되는지 확인한다."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

spec = importlib.util.spec_from_file_location("decoy_app_under_test", Path(__file__).with_name("app.py"))
decoy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoy)


class SessionLoggingTests(unittest.TestCase):
    def test_first_login_and_followup_share_session(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(decoy, "LOG_DIR", Path(directory)):
            with TestClient(decoy.app) as client:
                response = client.post("/admin/login", data={"username": "admin", "password": "admin"})
                self.assertEqual(response.status_code, 200)
                sid = client.cookies["sid"]
                client.get("/admin/users")
            records = [json.loads(line) for path in Path(directory).glob("decoy.json.*")
                       for line in path.read_text().splitlines()]
            self.assertEqual(sum(r["eventid"] == "decoy.session.connect" for r in records), 1)
            self.assertTrue(any(r["eventid"] == "decoy.login.success" for r in records))
            self.assertTrue(any(r["eventid"] == "decoy.action.view" for r in records))
            self.assertEqual({r["session"] for r in records}, {sid})

    def test_first_failed_login_has_session(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(decoy, "LOG_DIR", Path(directory)):
            with TestClient(decoy.app) as client:
                response = client.post("/admin/login", data={"username": "invalid", "password": "invalid"})
                self.assertEqual(response.status_code, 401)
                sid = client.cookies["sid"]
            records = [json.loads(line) for path in Path(directory).glob("decoy.json.*")
                       for line in path.read_text().splitlines()]
            self.assertEqual({r["session"] for r in records}, {sid})

    def test_health_does_not_create_observation(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(decoy, "LOG_DIR", Path(directory)):
            with TestClient(decoy.app) as client:
                self.assertEqual(client.get("/health").status_code, 200)
                self.assertNotIn("sid", client.cookies)
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
