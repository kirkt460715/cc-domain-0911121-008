from sealvault.codec import key, text, integer, canonical, loads, digest, fail, VaultError
from sealvault.custody import actors, chain
from sealvault.custody.cases import Cases
from sealvault.objects import Objects
from sealvault.capture.policy import CapturePolicy
from sealvault.capture import records
from sealvault.capture.engine import BrowserCapture, CaptureError

DDL = '''
CREATE TABLE IF NOT EXISTS captures(capture_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,owner TEXT NOT NULL,target_url TEXT NOT NULL,input_fingerprint TEXT NOT NULL,policy_body TEXT NOT NULL,policy_fingerprint TEXT NOT NULL,ready_selector TEXT NOT NULL,max_attempts INTEGER NOT NULL,state TEXT NOT NULL,failure_reason TEXT,attempts TEXT NOT NULL,record_body TEXT,record_digest TEXT,attached_at TEXT);
'''


def _capture_key(value):
    key(value)
    if ':' in value or '/' in value:
        fail('key', 'Capture identifiers may not contain path or namespace separators')
    return value


class Captures:
    """Persistent web capture jobs.

    A capture either attaches its complete evidence group in one transaction or
    attaches nothing. Failed browser runs and cases that became sealed while the
    browser was working are recorded with their reason instead of partial data.
    Repeating a finished confirmation returns the same group and never adds a
    second set of attachments.
    """

    def __init__(self, database, engine_factory=None):
        self.db = database
        self.cases = Cases(database)
        self.objects = Objects(database)
        self.engine_factory = engine_factory or (
            lambda policy, selector, attempts, clock: BrowserCapture(policy, selector, 'data-revision', attempts, clock))
        if database.depth:
            fail('capture_transaction', 'Initialize capture desk outside transactions')
        database.connection.executescript(DDL)

    def start(self, capture_id, case_id, owner, target_url, policy, expected_revision,
              ready_selector='#record[data-ready=true]', max_attempts=3):
        _capture_key(capture_id)
        text(target_url, 4096)
        selector = text(ready_selector, 300)
        integer(max_attempts, 'max_attempts', 1, 10)
        allowed = CapturePolicy(policy)
        permitted, reason = allowed.check(target_url)
        if not permitted:
            fail('capture_denied', 'Target URL is outside the approved capture policy', url=target_url, reason=reason)
        fingerprint = digest([case_id, owner, target_url, allowed.targets, selector, max_attempts])
        with self.db.transaction():
            actors.require(self.db, owner, {'collector', 'custodian'})
            previous = self.db.one('SELECT * FROM captures WHERE capture_id=?', (capture_id,))
            if previous:
                if previous['input_fingerprint'] != fingerprint:
                    fail('capture_conflict', 'Capture identifier binds different capture input')
                return self.get(capture_id)
            self.cases.editable(case_id, expected_revision, owner)
            self.db.execute("INSERT INTO captures VALUES(?,?,?,?,?,?,?,?,?,'running',NULL,?,NULL,NULL,NULL)",
                            (capture_id, case_id, owner, target_url, fingerprint, canonical(allowed.as_data()),
                             allowed.fingerprint, selector, max_attempts, canonical([])))
            chain.append(self.db, case_id, 'capture_started', owner,
                         {'capture_id': capture_id, 'target_url': target_url,
                          'policy_fingerprint': allowed.fingerprint})
            return self.get(capture_id)

    def run(self, capture_id, owner):
        """Drive one capture job through browser collection and case attachment.

        The browser runs outside the database transaction; attachment of the
        whole group (screenshot, DOM, manifest) is a single all-or-nothing case
        edit. If the case was sealed in the meantime, the outcome is recorded as
        a failed capture and no object is mounted.
        """
        key(owner)
        with self.db.transaction():
            job = self.db.one('SELECT * FROM captures WHERE capture_id=?', (capture_id,))
            if job is None:
                fail('capture_missing', 'Capture job does not exist')
            if job['owner'] != owner:
                fail('capture_owner', 'Capture owner differs')
            if job['state'] == 'attached':
                return self.get(capture_id)
            if job['state'] != 'running':
                fail('capture_state', 'Capture job cannot run from its current state')
            actors.require(self.db, owner, {'collector', 'custodian'})
            policy = CapturePolicy(loads(job['policy_body']))
            engine = self.engine_factory(policy, job['ready_selector'], job['max_attempts'], self.db.clock)
            target_url = job['target_url']
            case_id = job['case_id']

        browser_error = None
        captured = None
        try:
            captured = engine.capture(target_url)
        except CaptureError as exc:
            browser_error = exc
        except VaultError:
            raise
        except Exception as exc:  # browser launch failures, driver crashes, timeouts
            browser_error = CaptureError('browser_failure:' + type(exc).__name__, [])

        with self.db.transaction():
            if browser_error is not None:
                attempts = browser_error.attempts if browser_error.attempts else []
                self.db.execute('UPDATE captures SET state=?,failure_reason=?,attempts=? WHERE capture_id=?',
                                ('failed', browser_error.reason, canonical(attempts), capture_id))
                chain.append(self.db, case_id, 'capture_failed', owner,
                             {'capture_id': capture_id, 'reason': browser_error.reason})
                return self.get(capture_id)

            screenshot_bytes = captured.pop('screenshot_bytes')
            dom_bytes = captured.pop('dom_bytes')
            record = dict(captured)
            record['capture_id'] = capture_id
            record['policy_fingerprint'] = policy.fingerprint
            records.validate(record)
            envelope = records.build_envelope(capture_id, record)
            manifest_bytes = canonical(envelope).encode('utf-8')

            case = self.db.one('SELECT * FROM cases WHERE case_id=?', (case_id,))
            if case is None or case['state'] != 'draft':
                self.db.execute('UPDATE captures SET state=?,failure_reason=?,attempts=? WHERE capture_id=?',
                                ('failed', 'case_not_draft', canonical(record['attempts']), capture_id))
                chain.append(self.db, case_id, 'capture_failed', owner,
                             {'capture_id': capture_id, 'reason': 'case_not_draft'})
                return self.get(capture_id)

            self._check_artifact(screenshot_bytes, record['screenshot'])
            self._check_artifact(dom_bytes, record['dom'])

            prefix = 'captures/' + capture_id
            entries = [
                self._entry(prefix + '/screenshot.png', screenshot_bytes, 'image/png',
                            {'capture_id': capture_id, 'role': 'screenshot',
                             'revision': record['revision'], 'stable': True}),
                self._entry(prefix + '/dom.html', dom_bytes, 'text/html',
                            {'capture_id': capture_id, 'role': 'dom',
                             'revision': record['revision'], 'stable': True}),
                self._entry(prefix + '/capture.json', manifest_bytes, 'application/json',
                            {'capture_id': capture_id, 'role': 'manifest',
                             'resource_count': len(record['resources']),
                             'nav_count': len(record['navigation'])}),
            ]
            revision = case['revision']
            for entry in entries:
                revision = self.cases.attach(case_id, revision, owner, entry)['revision']
            self.db.execute(
                'UPDATE captures SET state=?,failure_reason=NULL,attempts=?,record_body=?,record_digest=?,attached_at=? WHERE capture_id=?',
                ('attached', canonical(record['attempts']), canonical(envelope), digest(envelope),
                 self.db.clock(), capture_id))
            chain.append(self.db, case_id, 'capture_attached', owner,
                         {'capture_id': capture_id, 'paths': [entry['path'] for entry in entries],
                          'record_digest': digest(envelope), 'revision': record['revision']})
            return self.get(capture_id)

    @staticmethod
    def _check_artifact(content, summary):
        from sealvault.codec import sha256
        if not isinstance(content, bytes) or len(content) != summary['bytes'] or sha256(content) != summary['sha256']:
            fail('capture_artifact', 'Artifact bytes do not match the same-state capture summary')

    def _entry(self, path_value, content, media_type, metadata):
        stored = self.objects.put(content)
        return {'path': path_value, 'digest': stored['digest'], 'size': len(content),
                'media_type': media_type, 'metadata': metadata}

    def get(self, capture_id):
        row = self.db.one('SELECT * FROM captures WHERE capture_id=?', (capture_id,))
        if row is None:
            fail('capture_missing', 'Capture job does not exist')
        result = {name: row[name] for name in row.keys()}
        result['attempts'] = loads(result['attempts'])
        result['policy'] = loads(result.pop('policy_body'))
        result['record'] = loads(result['record_body']) if result['record_body'] else None
        return result

    def list(self, case_id=None, state=None):
        if state is not None and state not in {'running', 'attached', 'failed'}:
            fail('capture_state', 'Unknown capture state')
        conditions = []
        arguments = []
        if case_id is not None:
            conditions.append('case_id=?')
            arguments.append(case_id)
        if state is not None:
            conditions.append('state=?')
            arguments.append(state)
        sql = 'SELECT capture_id FROM captures'
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)
        return [self.get(row['capture_id']) for row in self.db.all(sql + ' ORDER BY capture_id', arguments)]
