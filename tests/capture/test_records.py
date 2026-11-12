import unittest
from sealvault.codec import sha256, canonical, VaultError
from sealvault.capture import records


def make_record(extra=None, secret_header=None, secret_value=None):
    png = b'\x89PNG\r\n\x1a\n' + b'screenshot-bytes'
    dom = '<!doctype html><html>稳定页面</html>'.encode()
    data = {
        'capture_id': 'cap-1',
        'target_url': 'http://127.0.0.1:8787/',
        'final_url': 'http://127.0.0.1:8787/',
        'ready_selector': '#record[data-ready=true]',
        'page_time': '2026-11-12T01:00:00.123456Z',
        'captured_at': '2026-11-12T01:00:01.123456Z',
        'revision': '3',
        'attempts': [{'attempt': 1, 'outcome': 'retried', 'reason': 'revision_drift', 'at': '2026-11-12T00:59:59Z'},
                     {'attempt': 2, 'outcome': 'succeeded', 'reason': None, 'at': '2026-11-12T01:00:01Z'}],
        'navigation': [{'sequence': 1, 'url': 'http://127.0.0.1:8787/', 'status': 200, 'at': '2026-11-12T01:00:00Z'}],
        'resources': [
            {'ordinal': 0, 'requested_url': 'http://127.0.0.1:8787/', 'final_url': 'http://127.0.0.1:8787/',
             'method': 'GET', 'status': 200, 'media_type': 'text/html', 'bytes': 120, 'sha256': sha256(b'doc'),
             'state': 'ok', 'failure_reason': None, 'deny_reason': None},
            {'ordinal': 1, 'requested_url': 'http://127.0.0.1:8787/missing-image',
             'final_url': 'http://127.0.0.1:8787/missing-image', 'method': 'GET', 'status': 404,
             'media_type': 'image/png', 'bytes': None, 'sha256': None, 'state': 'failed',
             'failure_reason': 'http_status_404', 'deny_reason': None},
            {'ordinal': 2, 'requested_url': 'http://evil.example/tracker.js',
             'final_url': 'http://evil.example/tracker.js', 'method': 'GET', 'status': None,
             'media_type': '', 'bytes': None, 'sha256': None, 'state': 'blocked',
             'failure_reason': None, 'deny_reason': 'origin_forbidden'},
        ],
        'screenshot': {'media_type': 'image/png', 'bytes': len(png), 'sha256': sha256(png)},
        'dom': {'media_type': 'text/html; charset=utf-8', 'bytes': len(dom), 'sha256': sha256(dom)},
        'policy_fingerprint': 'a' * 64,
    }
    if secret_header:
        data['resources'][0][secret_header] = secret_value or 'Bearer secret-token'
    if extra:
        data.update(extra)
    return data, png, dom


class RecordTests(unittest.TestCase):
    def test_valid_record_envelope_roundtrip(self):
        data, png, dom = make_record()
        envelope = records.build_envelope('cap-1', data)
        parsed = records.parse_envelope(envelope, 'cap-1')
        self.assertEqual(parsed['revision'], '3')
        self.assertEqual(parsed['resources'][1]['failure_reason'], 'http_status_404')

    def test_envelope_binds_capture_identifier(self):
        data, _, _ = make_record()
        envelope = records.build_envelope('cap-1', data)
        with self.assertRaises(VaultError) as error:
            records.parse_envelope(envelope, 'cap-other')
        self.assertEqual(error.exception.code, 'capture_binding')

    def test_cookie_and_authorization_are_rejected(self):
        for header in ('cookie', 'set-cookie', 'authorization', 'proxy-authorization'):
            data, _, _ = make_record(secret_header=header)
            with self.assertRaises(VaultError) as error:
                records.assert_no_secrets(data)
            self.assertEqual(error.exception.code, 'capture_secret')
        data, _, _ = make_record()
        data['resources'][0]['failure_reason'] = 'Bearer abc.def.ghi token'
        with self.assertRaises(VaultError) as error:
            records.assert_no_secrets(data)
        self.assertEqual(error.exception.code, 'capture_secret')

    def test_navigation_must_end_at_final_url(self):
        data, _, _ = make_record({'final_url': 'http://127.0.0.1:8787/?visit=9'})
        with self.assertRaises(VaultError) as error:
            records.validate(data)
        self.assertEqual(error.exception.code, 'capture_record')

    def test_failed_resource_needs_reason_and_no_body_summary(self):
        data, _, _ = make_record()
        data['resources'][1]['failure_reason'] = None
        with self.assertRaises(VaultError):
            records.validate(data)

    def test_ordinal_contiguity_enforced(self):
        data, _, _ = make_record()
        data['resources'][2]['ordinal'] = 5
        with self.assertRaises(VaultError):
            records.validate(data)

    def test_artifact_summary(self):
        summary = records.artifact_summary(b'abc', 'image/png')
        self.assertEqual(summary, {'media_type': 'image/png', 'bytes': 3, 'sha256': sha256(b'abc')})


if __name__ == '__main__':
    unittest.main()
