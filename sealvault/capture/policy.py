from urllib.parse import urlsplit, unquote
from sealvault.codec import fail, text, canonical, digest

SAFE_SCHEMES = ('http', 'https')


class CapturePolicy:
    """Operator-approved origin/path allow-list for a web capture job.

    Every navigation and every resource request is re-checked against the same
    policy instance; nothing is trusted from a prior decision.
    """

    def __init__(self, targets):
        normalized = self.build(targets)
        self.targets = normalized
        self.fingerprint = digest(normalized)

    @staticmethod
    def build(value):
        if not isinstance(value, list) or not 1 <= len(value) <= 50:
            fail('capture_policy', 'Policy requires one to fifty origin targets')
        normalized = []
        seen = set()
        for target in value:
            if not isinstance(target, dict) or set(target) not in (set(), {'origin', 'paths'}):
                fail('capture_policy', 'Each target needs an origin and bounded paths')
            origin = text(target.get('origin'), 300)
            parts = urlsplit(origin)
            if parts.scheme not in SAFE_SCHEMES or not parts.hostname or parts.path or parts.query or parts.fragment:
                fail('capture_policy', 'Origin must be an http(s) origin without path or query')
            if parts.username is not None or parts.password is not None:
                fail('capture_policy', 'Credentials are not allowed in capture origins')
            paths = target.get('paths')
            if not isinstance(paths, list) or not 1 <= len(paths) <= 200:
                fail('capture_policy', 'Each origin requires one to two hundred allowed paths')
            clean_paths = []
            for item in paths:
                candidate = text(item, 500)
                if not candidate.startswith('/') or any(ch in candidate for ch in '?#'):
                    fail('capture_policy', 'Allowed paths start with / and carry no query or fragment')
                clean_paths.append(candidate)
            entry = {'origin': f'{parts.scheme}://{parts.netloc}', 'paths': sorted(set(clean_paths))}
            marker = canonical(entry)
            if marker in seen:
                fail('capture_policy', 'Duplicate policy target')
            seen.add(marker)
            normalized.append(entry)
        return sorted(normalized, key=lambda item: item['origin'])

    def check(self, url):
        """Return (allowed, reason). Never raises, safe inside event handlers."""
        if not isinstance(url, str) or len(url) > 4096:
            return False, 'malformed_url'
        try:
            parts = urlsplit(url)
        except ValueError:
            return False, 'malformed_url'
        if parts.scheme not in SAFE_SCHEMES:
            return False, 'scheme_forbidden'
        if parts.username is not None or parts.password is not None:
            return False, 'credentials_forbidden'
        origin = f'{parts.scheme}://{parts.netloc}'
        # Collapse percent-encoding and dot segments before matching so traversal
        # cannot disguise an unapproved path.
        path = unquote(parts.path or '/')
        segments = []
        for segment in path.split('/'):
            if not segment or segment == '.':
                continue
            if segment == '..':
                if segments:
                    segments.pop()
            else:
                segments.append(segment)
        path = '/' + '/'.join(segments)
        for target in self.targets:
            if target['origin'] != origin:
                continue
            for allowed in target['paths']:
                if allowed == '/':
                    if path == '/':
                        return True, None
                elif allowed.endswith('/'):
                    if path == allowed.rstrip('/') or path.startswith(allowed):
                        return True, None
                elif path == allowed:
                    return True, None
            return False, 'path_forbidden'
        return False, 'origin_forbidden'

    def allow(self, url):
        allowed, reason = self.check(url)
        if not allowed:
            fail('capture_denied', 'Request is outside the approved capture policy', url=url, reason=reason)
        return url

    def as_data(self):
        return [dict(target) for target in self.targets]
