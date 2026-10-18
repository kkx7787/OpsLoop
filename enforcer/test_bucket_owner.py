"""#130: 실제 botocore 요청에 소유자 조건을 붙이는지, 외부 연결 없이 확인."""
import io
import unittest
from unittest.mock import patch
import block_enforcer as be


class BucketOwnerTest(unittest.TestCase):
    def test_owner_is_required_before_credentials_or_network(self):
        for owner in (None, '', '123', '123456789012;'):
            with self.assertRaises(be.ConfigError), patch.object(be,'read_env',side_effect=AssertionError('must not read keys')):
                be.s3_client({'bucket':'unit-test','bucket_owner':owner},'s3-block.env')

    def test_get_put_enforce_owner_and_reject_wrong_owner(self):
        from botocore.stub import Stubber
        from botocore.exceptions import ClientError
        cfg={'bucket':'unit-test','bucket_owner':'123456789012','region':'ap-northeast-2'}
        with patch.object(be,'read_env',return_value={'AWS_ACCESS_KEY_ID':'synthetic','AWS_SECRET_ACCESS_KEY':'synthetic'}):
            client=be.s3_client(cfg,'s3-block.env')
        params={'Bucket':'unit-test','Key':'test','ExpectedBucketOwner':cfg['bucket_owner']}
        with Stubber(client) as stub:
            stub.add_response('get_object',{'Body':io.BytesIO(b'{}')},params)
            stub.add_response('put_object',{},dict(params,Body=b'{}'))
            stub.add_client_error('get_object',service_error_code='AccessDenied',http_status_code=403,expected_params=params)
            self.assertEqual(client.get_object(Bucket='unit-test',Key='test')['Body'].read(),b'{}')
            client.put_object(Bucket='unit-test',Key='test',Body=b'{}')
            with self.assertRaises(ClientError): client.get_object(Bucket='unit-test',Key='test')
            stub.assert_no_pending_responses()
        client.close()


if __name__=='__main__':unittest.main()
