"""운영 API 입력·권한 시험. 실제 계정이나 등록 토큰을 만들지 않는다."""
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from fastapi import HTTPException
from pydantic import ValidationError
from operations import EnrollmentIn, interval, issue_enrollment, cancel_enrollment, audit_log

class OperationsInputTests(unittest.TestCase):
    def test_enrollment_accepts_exact_address_and_deduplicates_logs(self):
        body = EnrollmentIn(node_id='web-01', hostname='opsloop-web', addr='2001:db8::1', logs=['auth','nginx','auth'])
        self.assertEqual(body.logs, ['auth','nginx'])
        self.assertEqual(body.addr, '2001:db8::1')

    def test_invalid_identity_address_logs_and_unknown_fields(self):
        base = dict(node_id='web-01',hostname='web-01',addr='192.0.2.1',logs=['auth'])
        for values in [dict(node_id='console'),dict(node_id='../bad'),dict(addr='127.0.0.1'),
                       dict(addr='192.0.2.1/24'),dict(addr='0.0.0.0'),dict(logs=[]),
                       dict(logs=['shell']),dict(token_hash='arbitrary')]:
            with self.subTest(values=values), self.assertRaises(ValidationError):
                EnrollmentIn(**(base | values))

    def test_interval_requires_ordered_timezone_pair(self):
        aware = datetime(2026,9,23,tzinfo=timezone.utc)
        interval(None,None)
        for pair in [(aware,None),(None,aware),(aware,aware),(datetime(2026,9,23),aware)]:
            with self.subTest(pair=pair), self.assertRaises(HTTPException) as error:
                interval(*pair)
            self.assertEqual(error.exception.status_code,422)

class OperationsPermissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_admin_operations_reject_before_database_access(self):
        body = EnrollmentIn(node_id='web-01',hostname='web',addr='192.0.2.1',logs=['auth'])
        for role in ['viewer','operator',None]:
            request=SimpleNamespace(state=SimpleNamespace(user={'u':'tester','r':role} if role else None))
            for call,args in [(issue_enrollment,(body,request,None)),(cancel_enrollment,('web-01',1,request)),(audit_log,(request,))]:
                with self.subTest(role=role,call=call), self.assertRaises(HTTPException) as error:
                    await call(*args)
                self.assertEqual(error.exception.status_code,403 if role else 401)
