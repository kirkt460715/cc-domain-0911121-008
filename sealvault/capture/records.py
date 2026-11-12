from sealvault.codec import fields, canonical, envelope, unwrap, fail, sha256, timestamp

FORBIDDEN_HEADERS = {'cookie', 'set-cookie', 'authorization', 'proxy-authorization'}
RECORD_FORMAT = 'sealvault-capture'

RESOURCE_FIELDS = {'ordinal', 'requested_url', 'final_url', 'method', 'status',
                   'media_type', 'bytes', 'sha256', 'state', 'failure_reason', 'deny_reason'}
NAV_FIELDS = {'sequence', 'url', 'status', 'at'}
ATTEMPT_FIELDS = {'attempt', 'outcome', 'reason', 'at'}
CAPTURE_FIELDS = {'capture_id', 'target_url', 'final_url', 'ready_selector', 'page_time',
                  'captured_at', 'revision', 'attempts', 'navigation', 'resources',
                  'screenshot', 'dom', 'policy_fingerprint'}
ARTIFACT_FIELDS = {'media_type', 'bytes', 'sha256'}


def _bounded_url(value, name):
    if not isinstance(value, str) or not value or len(value) > 4096:
        fail('capture_record', f'{name} must be bounded text')
    return value


def _resource(value):
    fields(value, RESOURCE_FIELDS)
    _bounded_url(value['requested_url'], 'requested_url')
    _bounded_url(value['final_url'], 'final_url')
    if value['method'] not in {'GET', 'POST', 'HEAD', 'PUT', 'PATCH', 'DELETE'}:
        fail('capture_record', 'Unsupported resource method')
    if value['state'] not in {'ok', 'failed', 'blocked'}:
        fail('capture_record', 'Unknown resource state')
    if value['state'] == 'ok':
        if not isinstance(value['status'], int) or not 100 <= value['status'] <= 599:
            fail('capture_record', 'Resource status outside HTTP range')
        if value['failure_reason'] is not None or value['deny_reason'] is not None:
            fail('capture_record', 'Successful resource carries no failure reason')
    else:
        if value['status'] is not None and (not isinstance(value['status'], int) or not 100 <= value['status'] <= 599):
            fail('capture_record', 'Resource status outside HTTP range')
        if value['sha256'] is not None or value['bytes'] is not None:
            fail('capture_record', 'Unsuccessful resource carries no body summary')
        if value['state'] == 'failed' and not value['failure_reason']:
            fail('capture_record', 'Failed resource requires a reason')
        if value['state'] == 'blocked' and not value['deny_reason']:
            fail('capture_record', 'Blocked resource requires a policy reason')
    if not isinstance(value['media_type'], str) or not value or len(value['media_type']) > 200:
        fail('capture_record', 'Resource media type must be bounded text')
    if value['bytes'] is not None and (not isinstance(value['bytes'], int) or not 0 <= value['bytes'] <= 16777216):
        fail('capture_record', 'Resource byte summary out of range')
    if value['sha256'] is not None:
        if not isinstance(value['sha256'], str) or len(value['sha256']) != 64:
            fail('capture_record', 'Resource digest must be a SHA-256 hex string')
    return value


def validate(data):
    """Validate and normalize an engine result before it can be stored as evidence."""
    fields(data, CAPTURE_FIELDS)
    _bounded_url(data['target_url'], 'target_url')
    _bounded_url(data['final_url'], 'final_url')
    timestamp(data['captured_at'])
    timestamp(data['page_time'])
    if not isinstance(data['ready_selector'], str) or not 1 <= len(data['ready_selector']) <= 300:
        fail('capture_record', 'Ready selector must be bounded text')
    if not isinstance(data['revision'], str) or len(data['revision']) > 200:
        fail('capture_record', 'Stable page revision must be bounded text')
    if not isinstance(data['policy_fingerprint'], str) or len(data['policy_fingerprint']) != 64:
        fail('capture_record', 'Policy fingerprint must be a SHA-256 hex string')
    if not isinstance(data['attempts'], list) or not 1 <= len(data['attempts']) <= 10:
        fail('capture_record', 'Capture requires one to ten attempts')
    for attempt in data['attempts']:
        fields(attempt, ATTEMPT_FIELDS)
        if attempt['outcome'] not in {'retried', 'succeeded'}:
            fail('capture_record', 'Unknown attempt outcome')
        if attempt['outcome'] == 'succeeded' and attempt['reason'] is not None:
            fail('capture_record', 'Successful attempt carries no failure reason')
        timestamp(attempt['at'])
    if data['attempts'][-1]['outcome'] != 'succeeded':
        fail('capture_record', 'Only a successful capture can produce a record')
    navigation = data['navigation']
    if not isinstance(navigation, list) or not navigation:
        fail('capture_record', 'Navigation chain requires at least one entry')
    for item in navigation:
        fields(item, NAV_FIELDS)
        _bounded_url(item['url'], 'navigation url')
        if item['status'] is not None and (not isinstance(item['status'], int) or not 100 <= item['status'] <= 599):
            fail('capture_record', 'Navigation status out of range')
        timestamp(item['at'])
    if navigation[-1]['url'] != data['final_url']:
        fail('capture_record', 'Navigation chain does not end at the final URL')
    resources = data['resources']
    if not isinstance(resources, list) or not resources:
        fail('capture_record', 'Resource manifest requires at least the document request')
    ordinals = []
    for item in resources:
        _resource(item)
        ordinals.append(item['ordinal'])
    if ordinals != list(range(len(resources))):
        fail('capture_record', 'Resource ordinals must be contiguous from zero')
    for artifact in (data['screenshot'], data['dom']):
        fields(artifact, ARTIFACT_FIELDS)
        if not isinstance(artifact['bytes'], int) or not 0 < artifact['bytes'] <= 16777216:
            fail('capture_record', 'Artifact byte summary out of range')
        if not isinstance(artifact['sha256'], str) or len(artifact['sha256']) != 64:
            fail('capture_record', 'Artifact digest must be a SHA-256 hex string')
    assert_no_secrets(data)
    return data


def assert_no_secrets(data):
    """The manifest stores metadata only; cookies and credentials must never appear."""
    def scan(value, location):
        if isinstance(value, dict):
            for name, item in value.items():
                if name.lower() in FORBIDDEN_HEADERS:
                    fail('capture_secret', 'Forbidden credential header appears in capture record', header=name.lower())
                scan(item, location + '.' + name)
        elif isinstance(value, list):
            for item in value:
                scan(item, location)
        elif isinstance(value, str) and value.lower().startswith(('bearer ', 'basic ')):
            fail('capture_secret', 'Credential value appears in capture record', location=location)
    scan(data, 'record')
    for item in data['resources']:
        if item['state'] == 'ok' and (not item['sha256'] or not item['bytes']):
            fail('capture_record', 'Stored resource requires a body summary without the body itself')


def build_envelope(capture_id, data):
    validate(data)
    return envelope(RECORD_FORMAT, {'capture_id': capture_id, 'capture': data})


def parse_envelope(value, capture_id):
    data = unwrap(value, RECORD_FORMAT)
    fields(data, {'capture_id', 'capture'})
    if data['capture_id'] != capture_id:
        fail('capture_binding', 'Record envelope belongs to another capture job')
    validate(data['capture'])
    return data['capture']


def artifact_summary(content, media_type):
    if not isinstance(content, bytes) or not content or len(content) > 16777216:
        fail('capture_artifact', 'Artifact must be nonempty bytes no larger than 16 MiB')
    if not isinstance(media_type, str) or not media_type:
        fail('capture_artifact', 'Artifact media type missing')
    return {'media_type': media_type.lower(), 'bytes': len(content), 'sha256': sha256(content)}
