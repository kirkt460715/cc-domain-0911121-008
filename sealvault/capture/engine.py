"""Browser capture engine.

One engine run produces one capture record from one stable page state.
Each attempt uses a brand-new browser context with no persistent profile;
screenshot and DOM are taken back-to-back and revalidated against the same
ready flag, revision and URL. Any navigation or revision change between the
stable point and capture invalidates the whole attempt, never just part of it.
"""
from sealvault.codec import now, sha256, fail
from sealvault.capture.records import artifact_summary

QUIET_WINDOW_MS = 700
POLL_MS = 100
GOTO_TIMEOUT_MS = 15000
READY_TIMEOUT_MS = 15000
STABILITY_DEADLINE_MS = 20000
MAX_RESOURCES = 500
VIEWPORT = {'width': 1280, 'height': 720}


class CaptureError(Exception):
    def __init__(self, reason, attempts):
        super().__init__(reason)
        self.reason = reason
        self.attempts = attempts


class _Resource:
    def __init__(self, ordinal, requested_url, method, document):
        self.ordinal = ordinal
        self.requested_url = requested_url
        self.final_url = requested_url
        self.method = method
        self.document = document
        self.status = None
        self.media_type = ''
        self.bytes = None
        self.digest = None
        self.state = 'pending'
        self.failure_reason = None
        self.deny_reason = None

    def as_data(self):
        return {'ordinal': self.ordinal, 'requested_url': self.requested_url,
                'final_url': self.final_url, 'method': self.method, 'status': self.status,
                'media_type': self.media_type, 'bytes': self.bytes, 'sha256': self.digest,
                'state': self.state, 'failure_reason': self.failure_reason,
                'deny_reason': self.deny_reason}


class BrowserCapture:
    def __init__(self, policy, ready_selector='#record[data-ready=true]', revision_attribute='data-revision',
                 max_attempts=3, clock=now):
        self.policy = policy
        self.ready_selector = ready_selector
        self.revision_attribute = revision_attribute
        self.max_attempts = max_attempts
        self.clock = clock

    def capture(self, target_url):
        allowed, reason = self.policy.check(target_url)
        if not allowed:
            fail('capture_denied', 'Target URL is outside the approved capture policy', url=target_url, reason=reason)
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise CaptureError('browser_unavailable', []) from exc
        attempts = []
        with sync_playwright() as library:
            browser = library.chromium.launch(headless=True, args=['--no-sandbox'])
            try:
                for number in range(1, self.max_attempts + 1):
                    outcome = self._attempt(browser, target_url, number)
                    if outcome['ok']:
                        attempts.append({'attempt': number, 'outcome': 'succeeded', 'reason': None, 'at': self.clock()})
                        record = outcome['record']
                        record['attempts'] = attempts
                        return record
                    attempts.append({'attempt': number, 'outcome': 'retried', 'reason': outcome['reason'], 'at': self.clock()})
                raise CaptureError('attempts_exhausted', attempts)
            finally:
                browser.close()

    def _attempt(self, browser, target_url, number):
        # Fresh ephemeral context: no cookies, storage state or persistent profile.
        context = browser.new_context(viewport=dict(VIEWPORT))
        page = context.new_page()
        resources = {}
        ordinals = {'next': 0}
        pending = set()
        navigation = []
        drift = {'reason': None}

        def note_drift(reason):
            if drift['reason'] is None:
                drift['reason'] = reason

        def handle_route(route):
            request = route.request
            url = request.url
            allowed, reason = self.policy.check(url)
            ordinal = ordinals['next']
            ordinals['next'] += 1
            resource = _Resource(ordinal, url, request.method, request.resource_type == 'document')
            resources[id(request)] = resource
            if len(resources) > MAX_RESOURCES:
                note_drift('resource_limit')
            if not allowed:
                resource.state = 'blocked'
                resource.deny_reason = reason
                if resource.document:
                    navigation.append({'sequence': len(navigation) + 1, 'url': url, 'status': None, 'at': self.clock()})
                    note_drift('document_blocked:' + reason)
                route.abort('accessdenied')
                return
            if resource.document:
                navigation.append({'sequence': len(navigation) + 1, 'url': url, 'status': None, 'at': self.clock()})
            # Background XHR/fetch polling is recorded in the manifest but must not
            # keep resetting the document/subresource stability window.
            if request.resource_type not in ('xhr', 'fetch'):
                pending.add(id(request))
            route.continue_()

        def handle_response(response):
            resource = resources.get(id(response.request))
            if resource is None or resource.state != 'pending':
                return
            resource.status = response.status
            resource.final_url = response.url
            header_value = response.headers.get('content-type', '')
            resource.media_type = header_value[:200]

        def finish_request(request, failed):
            marker = id(request)
            resource = resources.get(marker)
            pending.discard(marker)
            if resource is None or resource.state != 'pending':
                return
            if failed:
                resource.state = 'failed'
                resource.failure_reason = 'network_failed'
                if resource.document:
                    note_drift('document_network_failed')
                return
            response = request.response()
            if response is None:
                resource.state = 'failed'
                resource.failure_reason = 'response_missing'
                return
            resource.final_url = response.url
            if resource.document:
                for entry in navigation:
                    if entry['url'] == resource.requested_url and entry['status'] is None:
                        entry['status'] = response.status
                        break
            if response.status >= 400:
                resource.state = 'failed'
                resource.failure_reason = 'http_status_%d' % response.status
                return
            try:
                body = response.body()
            except Exception:
                # Redirect and no-body responses legitimately carry no bytes.
                body = b''
            if len(body) > 16777216:
                resource.state = 'failed'
                resource.failure_reason = 'body_too_large'
                return
            resource.bytes = len(body)
            resource.digest = sha256(body)
            resource.state = 'ok'

        def handle_navigated(frame):
            if frame != page.main_frame:
                return
            url = frame.url
            allowed, reason = self.policy.check(url)
            if not allowed:
                note_drift('navigation_forbidden:' + reason)

        context.route('**/*', handle_route)
        page.on('response', handle_response)
        page.on('requestfinished', lambda request: finish_request(request, False))
        page.on('requestfailed', lambda request: finish_request(request, True))
        page.on('framenavigated', handle_navigated)

        try:
            try:
                page.goto(target_url, wait_until='commit', timeout=GOTO_TIMEOUT_MS)
            except Exception as exc:
                if drift['reason']:
                    return {'ok': False, 'reason': drift['reason']}
                return {'ok': False, 'reason': 'navigation_failed:' + type(exc).__name__}
            try:
                page.locator(self.ready_selector).first.wait_for(state='attached', timeout=READY_TIMEOUT_MS)
            except Exception:
                return {'ok': False, 'reason': 'ready_timeout'}
            try:
                revision = page.locator(self.ready_selector).first.get_attribute(self.revision_attribute)
                stable_url = page.url
                ticks = 0
                quiet_ticks = 0
                required_quiet = QUIET_WINDOW_MS // POLL_MS
                settled = False
                while ticks * POLL_MS <= STABILITY_DEADLINE_MS:
                    if drift['reason']:
                        return {'ok': False, 'reason': drift['reason']}
                    ready = page.locator(self.ready_selector).first
                    if ready.count() == 0 or ready.get_attribute('data-ready') != 'true':
                        return {'ok': False, 'reason': 'ready_flag_lost'}
                    if ready.get_attribute(self.revision_attribute) != revision:
                        return {'ok': False, 'reason': 'revision_drift'}
                    if page.url != stable_url:
                        return {'ok': False, 'reason': 'navigation_drift'}
                    if pending:
                        quiet_ticks = 0
                    else:
                        quiet_ticks += 1
                        if quiet_ticks >= required_quiet:
                            settled = True
                            break
                    page.wait_for_timeout(POLL_MS)
                    ticks += 1
                if not settled:
                    return {'ok': False, 'reason': 'stability_timeout'}
                # Screenshot and DOM come from the same validated stable state.
                screenshot_bytes = page.screenshot(full_page=False)
                dom_bytes = page.content().encode('utf-8')
                page_time = page.evaluate('() => new Date().toISOString()')
                ready = page.locator(self.ready_selector).first
                if page.url != stable_url or ready.count() == 0 or ready.get_attribute('data-ready') != 'true':
                    return {'ok': False, 'reason': 'navigation_drift'}
                if ready.get_attribute(self.revision_attribute) != revision:
                    return {'ok': False, 'reason': 'revision_drift'}
                if drift['reason']:
                    return {'ok': False, 'reason': drift['reason']}
            except CaptureError:
                raise
            except Exception as exc:
                return {'ok': False, 'reason': 'capture_failed:' + type(exc).__name__}
            if any(item.state == 'pending' for item in resources.values()):
                return {'ok': False, 'reason': 'requests_unsettled'}
            record = {
                'target_url': target_url,
                'final_url': page.url,
                'ready_selector': self.ready_selector,
                'page_time': page_time,
                'captured_at': self.clock(),
                'revision': str(revision),
                'attempts': [],
                'navigation': navigation,
                'resources': [resources[key].as_data() for key in sorted(resources, key=lambda marker: resources[marker].ordinal)],
                'screenshot': artifact_summary(screenshot_bytes, 'image/png'),
                'dom': artifact_summary(dom_bytes, 'text/html'),
                'policy_fingerprint': self.policy.fingerprint,
                'screenshot_bytes': screenshot_bytes,
                'dom_bytes': dom_bytes,
            }
            return {'ok': True, 'record': record}
        finally:
            context.close()
