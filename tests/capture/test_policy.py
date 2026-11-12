import unittest
from sealvault.codec import fail, digest
from sealvault.capture.policy import CapturePolicy


class CapturePolicyTests(unittest.TestCase):
    def policy(self, paths=('/','/content','/page.js','/missing-image')):
        return CapturePolicy([{'origin': 'http://127.0.0.1:8787', 'paths': list(paths)}])

    def test_origin_and_path_decisions(self):
        policy = self.policy()
        for allowed_url in ('http://127.0.0.1:8787/', 'http://127.0.0.1:8787/page.js',
                            'http://127.0.0.1:8787/missing-image'):
            self.assertEqual(policy.check(allowed_url), (True, None))
        # Approval covers the path; a query cannot reach an unapproved path.
        self.assertEqual(policy.check('http://127.0.0.1:8787/content?x=1'), (True, None))
        self.assertEqual(policy.check('http://127.0.0.1:8787/content/../secret'), (False, 'path_forbidden'))
        allowed, reason = policy.check('http://127.0.0.1:8787/secret')
        self.assertFalse(allowed)
        self.assertEqual(reason, 'path_forbidden')
        allowed, reason = policy.check('http://evil.example/')
        self.assertFalse(allowed)
        self.assertEqual(reason, 'origin_forbidden')

    def test_non_http_schemes_are_blocked_even_with_hostname_match(self):
        policy = self.policy()
        for bad in ('javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd',
                    'ftp://127.0.0.1:8787/', 'about:blank', 'chrome://settings'):
            allowed, reason = policy.check(bad)
            self.assertFalse(allowed, bad)
            self.assertEqual(reason, 'scheme_forbidden', bad)

    def test_prefix_paths_and_credentials_rejected(self):
        policy = CapturePolicy([{'origin': 'https://vault.local', 'paths': ['/public/']}])
        self.assertTrue(policy.check('https://vault.local/public/a/b.png')[0])
        self.assertFalse(policy.check('https://vault.local/publicx')[0])
        self.assertFalse(policy.check('https://user:pwd@vault.local/public/')[0])

    def test_policy_construction_validation(self):
        for bad in ([], [{}], [{'origin': 'not-a-url', 'paths': ['/']}],
                    [{'origin': 'http://a.test/path', 'paths': ['/']}],
                    [{'origin': 'http://a.test', 'paths': []}],
                    [{'origin': 'http://a.test', 'paths': ['no-slash']}]):
            with self.assertRaises(Exception):
                CapturePolicy(bad)

    def test_policy_fingerprint_is_stable_and_order_independent(self):
        left = CapturePolicy([{'origin': 'http://a.test', 'paths': ['/x', '/']}])
        right = CapturePolicy([{'origin': 'http://a.test', 'paths': ['/', '/x']}])
        self.assertEqual(left.fingerprint, right.fingerprint)
        self.assertEqual(len(left.fingerprint), 64)
        different = CapturePolicy([{'origin': 'http://a.test', 'paths': ['/y']}])
        self.assertNotEqual(left.fingerprint, different.fingerprint)


if __name__ == '__main__':
    unittest.main()
