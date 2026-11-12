from sealvault.codec import sha256, canonical, VaultError, digest
from sealvault.capture.engine import CaptureError
from tests.support import Case

POLICY = [{'origin': 'http://127.0.0.1:8787', 'paths': ['/', '/content', '/page.js', '/missing-image']}]
TARGET = 'http://127.0.0.1:8787/'


def fake_engine(policy, selector, max_attempts, clock):
    return FakeEngine(policy, max_attempts)


class FakeEngine:
    behavior = 'succeed'

    def __init__(self, policy, max_attempts):
        self.policy = policy
        self.max_attempts = max_attempts
        self.calls = 0

    def capture(self, url):
        self.calls += 1
        allowed, reason = self.policy.check(url)
        if not allowed:
            raise CaptureError('document_blocked:' + reason, [])
        behavior = FakeEngine.behavior
        if behavior == 'browser_fail':
            raise RuntimeError('chromium crashed')
        if behavior == 'exhausted':
            raise CaptureError('attempts_exhausted',
                               [{'attempt': n, 'outcome': 'retried', 'reason': 'revision_drift',
                                 'at': '2026-11-11T00:00:00Z'} for n in range(1, self.max_attempts + 1)])
        attempts = []
        if behavior == 'retry_then_succeed':
            attempts.append({'attempt': 1, 'outcome': 'retried', 'reason': 'navigation_drift',
                             'at': '2026-11-11T00:00:00Z'})
        attempts.append({'attempt': len(attempts) + 1, 'outcome': 'succeeded', 'reason': None,
                         'at': '2026-11-11T00:00:02Z'})
        png = b'\x89PNG\r\n\x1a\n' + b'capture-png'
        dom = '<!doctype html><html>稳定 DOM revision 2</html>'.encode()
        body = b'{"revision":2}'
        record = {
            'target_url': url,
            'final_url': url,
            'ready_selector': '#record[data-ready=true]',
            'page_time': '2026-11-11T00:00:01Z',
            'captured_at': '2026-11-11T00:00:02Z',
            'revision': '2',
            'attempts': attempts,
            'navigation': [{'sequence': 1, 'url': url, 'status': 200, 'at': '2026-11-11T00:00:00Z'}],
            'resources': [
                {'ordinal': 0, 'requested_url': url, 'final_url': url, 'method': 'GET', 'status': 200,
                 'media_type': 'text/html', 'bytes': len(body), 'sha256': sha256(body),
                 'state': 'ok', 'failure_reason': None, 'deny_reason': None},
                {'ordinal': 1, 'requested_url': url + 'missing-image', 'final_url': url + 'missing-image',
                 'method': 'GET', 'status': 404, 'media_type': 'image/png', 'bytes': None, 'sha256': None,
                 'state': 'failed', 'failure_reason': 'http_status_404', 'deny_reason': None},
            ],
            'screenshot': {'media_type': 'image/png', 'bytes': len(png), 'sha256': sha256(png)},
            'dom': {'media_type': 'text/html; charset=utf-8', 'bytes': len(dom), 'sha256': sha256(dom)},
            'policy_fingerprint': self.policy.fingerprint,
            'screenshot_bytes': png,
            'dom_bytes': dom,
        }
        return record


class CaptureDeskTests(Case):
    def setUp(self):
        super().setUp()
        FakeEngine.behavior = 'succeed'
        self.vault.captures.engine_factory = fake_engine
        self.vault.cases.create('case-web', '网页证据案件', 'collector')

    def start(self, capture_id='cap-1', expected_revision=1):
        return self.vault.captures.start(capture_id, 'case-web', 'collector', TARGET, POLICY, expected_revision)

    def test_successful_group_is_attached_atomically(self):
        self.start()
        result = self.vault.captures.run('cap-1', 'collector')
        self.assertEqual(result['state'], 'attached')
        case = self.vault.cases.get('case-web')
        paths = [entry['path'] for entry in case['entries']]
        self.assertEqual(paths, ['captures/cap-1/capture.json', 'captures/cap-1/dom.html',
                                 'captures/cap-1/screenshot.png'])
        # Screenshot and DOM share the same stable revision metadata.
        for entry in case['entries']:
            if entry['path'].endswith(('.png', '.html')):
                self.assertTrue(entry['metadata']['stable'])
                self.assertEqual(entry['metadata']['revision'], '2')
        record = result['record']['payload']['data']['capture']
        self.assertEqual(record['screenshot']['sha256'],
                         next(entry for entry in case['entries'] if entry['path'].endswith('screenshot.png'))['digest'])
        self.assertEqual(record['dom']['sha256'],
                         next(entry for entry in case['entries'] if entry['path'].endswith('dom.html'))['digest'])

    def test_repeated_confirmation_does_not_add_a_second_group(self):
        self.start()
        first = self.vault.captures.run('cap-1', 'collector')
        second = self.vault.captures.run('cap-1', 'collector')
        self.assertEqual(first['record_digest'], second['record_digest'])
        self.assertEqual(len(self.vault.cases.get('case-web')['entries']), 3)
        # Restarting the same identifier is idempotent as well.
        self.assertEqual(self.start()['state'], 'attached')

    def test_retry_history_is_recorded_then_succeeds(self):
        FakeEngine.behavior = 'retry_then_succeed'
        self.start()
        result = self.vault.captures.run('cap-1', 'collector')
        self.assertEqual(result['state'], 'attached')
        record = result['record']['payload']['data']['capture']
        self.assertEqual([item['outcome'] for item in record['attempts']], ['retried', 'succeeded'])

    def test_browser_failure_records_reason_and_attaches_nothing(self):
        FakeEngine.behavior = 'browser_fail'
        self.start()
        result = self.vault.captures.run('cap-1', 'collector')
        self.assertEqual(result['state'], 'failed')
        self.assertTrue(result['failure_reason'].startswith('browser_failure'))
        self.assertIsNone(result['record'])
        self.assertEqual(self.vault.cases.get('case-web')['entries'], [])
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 0)

    def test_exhausted_attempts_leave_failure_with_attempt_chain(self):
        FakeEngine.behavior = 'exhausted'
        self.start()
        result = self.vault.captures.run('cap-1', 'collector')
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['failure_reason'], 'attempts_exhausted')
        self.assertEqual(len(result['attempts']), 3)
        self.assertEqual(self.vault.cases.get('case-web')['entries'], [])

    def test_case_sealed_between_collection_and_attachment_records_failure(self):
        self.start()

        class SealAfterCapture(FakeEngine):
            def capture(self, url):
                record = super().capture(url)
                case = self_vault.cases.get('case-web')
                self_vault.seals.prepare('seal-web', 'case-web', case['revision'], 'collector')
                self_vault.seals.seal('seal-web', 'custodian', '2099-01-01T00:00:00Z')
                return record

        self_vault = self.vault
        # An unrelated prior entry lets the case reach a legal sealed state.
        stored = self.vault.objects.put(b'prior intake note')
        self.vault.cases.attach('case-web', 1, 'collector',
                                {'path': 'intake/note.txt', 'digest': stored['digest'],
                                 'size': len(b'prior intake note'), 'media_type': 'text/plain',
                                 'metadata': {'synthetic': True}})
        case = self.vault.cases.get('case-web')
        self.assertEqual(case['revision'], 2)

        def factory(policy, selector, attempts, clock):
            return SealAfterCapture(policy, attempts)

        self.vault.captures.engine_factory = factory
        result = self.vault.captures.run('cap-1', 'collector')
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['failure_reason'], 'case_not_draft')
        self.assertIsNone(result['record'])
        # The capture group never entered the case; the pre-existing entry alone remains.
        case = self.vault.cases.get('case-web')
        self.assertEqual(case['state'], 'sealed')
        self.assertEqual([entry['path'] for entry in case['entries']], [])
        self.assertEqual(self.db.scalar("SELECT COUNT(*) FROM objects WHERE state='available'"), 1)

    def test_start_requires_draft_case_and_approved_target(self):
        self.error('case_revision', self.vault.captures.start, 'cap-x', 'case-web', 'collector',
                   TARGET, POLICY, 99)
        case = self.vault.cases.get('case-web')
        stored = self.vault.objects.put(b'pre-seal note')
        self.vault.cases.attach('case-web', case['revision'], 'collector',
                                {'path': 'intake/note.txt', 'digest': stored['digest'],
                                 'size': len(b'pre-seal note'), 'media_type': 'text/plain',
                                 'metadata': {'synthetic': True}})
        case = self.vault.cases.get('case-web')
        self.vault.seals.prepare('seal-x', 'case-web', case['revision'], 'collector')
        self.vault.seals.seal('seal-x', 'custodian', '2099-01-01T00:00:00Z')
        self.error('case_state', self.vault.captures.start, 'cap-y', 'case-web', 'collector',
                   TARGET, POLICY, case['revision'] + 1)
        self.error('capture_denied', self.vault.captures.start, 'cap-z', 'case-web', 'collector',
                   'http://evil.example/', POLICY, 1)
        fresh = self.vault
        fresh.cases.create('case-open', '另一案件', 'collector')
        self.error('capture_denied', self.vault.captures.start, 'cap-w', 'case-open', 'collector',
                   'javascript:alert(1)', POLICY, 1)

    def test_identifier_conflict_detects_changed_input(self):
        self.start()
        other = [{'origin': 'http://127.0.0.1:9999', 'paths': ['/']}]
        self.error('capture_conflict', self.vault.captures.start, 'cap-1', 'case-web', 'collector',
                   'http://127.0.0.1:9999/', other, 1)

    def test_route_available_through_vault_execute(self):
        self.start()
        result = self.vault.execute({'operation': 'capture.run', 'arguments':
                                     {'capture_id': 'cap-1', 'owner': 'collector'}})
        self.assertEqual(result['state'], 'attached')
        listed = self.vault.execute({'operation': 'capture.list', 'arguments': {'case_id': 'case-web'}})
        self.assertEqual([item['capture_id'] for item in listed], ['cap-1'])
