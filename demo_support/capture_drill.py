"""端到端网页证据采集演练（真实本地浏览器，全部回环通信）。

覆盖：
1. 业务就绪后采集，截图/DOM/清单来自同一次稳定状态并挂入草稿案件；
2. 页面一次性版本漂移触发整组重试，第二次访问成功；
3. 持续版本漂移在 max_attempts=1 时整组失败且不留半组附件；
4. 采集期间案件被封存，结果记录为 case_not_draft，不挂载任何对象；
5. 同组重复确认幂等，不产生第二组附件；
6. 封存后重新核对截图、DOM、清单摘要与案件条目的关联；
7. 非 HTTP(S) 与越界 origin/路径在策略层被拒绝。

不做 OCR，也不判断页面真伪；演练数据均为合成内容。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'portal'))
sys.path.insert(0, str(ROOT))
from server import start

from playwright.sync_api import sync_playwright

from sealvault.codec import canonical
from sealvault.service import Vault
from sealvault.capture.policy import CapturePolicy
from sealvault.capture import records

POLICY_PATHS = ['/', '/page.js', '/content', '/missing-image']


def policy_for(base):
    return [{'origin': base, 'paths': POLICY_PATHS}]


def make_vault():
    vault = Vault()
    for identity, role in [('collector', 'collector'), ('custodian', 'custodian')]:
        vault.execute({'operation': 'actor.register', 'arguments': {'actor_id': identity, 'role': role}})
    return vault


def start_capture(vault, capture_id, case_id, base, url_path='/', max_attempts=3):
    vault.cases.create(case_id, '网页证据演练案件 ' + capture_id, 'collector')
    target = base + url_path
    vault.captures.start(capture_id, case_id, 'collector', target, policy_for(base), 1,
                         max_attempts=max_attempts)
    return vault.captures.run(capture_id, 'collector')


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    server, base = start()
    try:
        # 场景一：稳定采集并挂载完整证据组
        with make_vault() as vault:
            result = start_capture(vault, 'cap-stable', 'case-stable', base)
            assert_true(result['state'] == 'attached', '稳定采集应当成功挂载')
            case = vault.cases.get('case-stable')
            paths = sorted(entry['path'] for entry in case['entries'])
            assert_true(paths == ['captures/cap-stable/capture.json',
                                  'captures/cap-stable/dom.html',
                                  'captures/cap-stable/screenshot.png'], '证据组三件套路径不符: %s' % paths)
            record = result['record']['payload']['data']['capture']
            records.parse_envelope(result['record'], 'cap-stable')
            assert_true(record['revision'] == '1', '初始页面版本应为 1')
            assert_true(record['attempts'][-1]['outcome'] == 'succeeded', '最后一次尝试必须成功')
            assert_true(record['final_url'].startswith(base + '/'), '最终地址应记录')
            assert_true(record['navigation'][0]['url'] == base + '/', '导航链首跳为目标地址')
            missing = next(item for item in record['resources'] if item['requested_url'].endswith('/missing-image'))
            assert_true(missing['state'] == 'failed' and missing['failure_reason'] == 'http_status_404',
                        '缺失图片应作为失败资源保留原因')
            document = record['resources'][0]
            assert_true(document['state'] == 'ok' and document['sha256'] and document['bytes'],
                        '清单仅存元数据与对象摘要，不存响应体')
            # 机密信息卫生：记录中不存在 Cookie / Authorization 字段或凭据值
            rendered = canonical(record).lower()
            for forbidden in ('"cookie"', '"set-cookie"', '"authorization"', '"proxy-authorization"', 'bearer '):
                assert_true(forbidden not in rendered, '清单泄露机密字段: %s' % forbidden)
            # 截图与 DOM 的摘要必须与实际入库对象一致（同一稳定状态）
            by_path = {entry['path']: entry for entry in case['entries']}
            assert_true(by_path['captures/cap-stable/screenshot.png']['digest'] == record['screenshot']['sha256'],
                        '截图摘要与入库对象不一致')
            assert_true(by_path['captures/cap-stable/dom.html']['digest'] == record['dom']['sha256'],
                        'DOM 摘要与入库对象不一致')
            dom_bytes = vault.objects.read(record['dom']['sha256'])
            assert_true('待保管员签收' in dom_bytes.decode(), 'DOM 应来自就绪后的最终页面')
            png_bytes = vault.objects.read(record['screenshot']['sha256'])
            assert_true(png_bytes.startswith(bytes([137, 80, 78, 71])), '截图应为 PNG')
            assert_true(len(png_bytes) == record['screenshot']['bytes'], '截图字节数与摘要不符')

            # 场景五：重复确认幂等
            again = vault.captures.run('cap-stable', 'collector')
            assert_true(again['record_digest'] == result['record_digest'], '重复确认应返回同一证据组')
            assert_true(len(vault.cases.get('case-stable')['entries']) == 3, '重复确认不得增加第二组附件')
            restart = vault.captures.start('cap-stable', 'case-stable', 'collector', base + '/',
                                           policy_for(base), 999)
            assert_true(restart['state'] == 'attached', '重复 start 应幂等返回既有结果')

            # 场景六：封存后重新核对摘要与关联
            manifest_id = 'seal-stable'
            case = vault.cases.get('case-stable')
            vault.seals.prepare(manifest_id, 'case-stable', case['revision'], 'collector')
            vault.seals.seal(manifest_id, 'custodian', '2099-01-01T00:00:00Z')
            sealed_manifest = vault.seals.get(manifest_id)['manifest']['body']
            sealed_paths = {entry['path']: entry['digest'] for entry in sealed_manifest['entries']}
            for role, summary in (('screenshot.png', record['screenshot']), ('dom.html', record['dom'])):
                key_path = 'captures/cap-stable/' + role
                assert_true(sealed_paths[key_path] == summary['sha256'],
                            '封存清单与采集摘要断裂: %s' % key_path)
            manifest_entry = next(entry for entry in sealed_manifest['entries']
                                  if entry['path'] == 'captures/cap-stable/capture.json')
            assert_true(manifest_entry['digest'] == result['record_digest'], '清单对象摘要与记录不符')

        # 场景二：一次性版本漂移 → 整组重试后成功
        with make_vault() as vault:
            drift_url = base + '/?drift=revision&token=drill-once'
            vault.cases.create('case-retry', '重试演练案件', 'collector')
            vault.captures.start('cap-retry', 'case-retry', 'collector', drift_url, policy_for(base), 1)
            result = vault.captures.run('cap-retry', 'collector')
            assert_true(result['state'] == 'attached', '漂移重试后应成功: %s' % result.get('failure_reason'))
            record = result['record']['payload']['data']['capture']
            outcomes = [item['outcome'] for item in record['attempts']]
            assert_true(outcomes == ['retried', 'succeeded'], '应记录一次重试后成功: %s' % outcomes)
            assert_true(record['attempts'][0]['reason'] == 'revision_drift', '重试原因应为版本漂移')
            assert_true(record['revision'] in ('1', '2'), '成功记录保留稳定版本号')
            assert_true(len(vault.cases.get('case-retry')['entries']) == 3, '重试成功只挂载一组证据')

        # 场景三：持续漂移且 max_attempts=1 → 整组失败，零挂载
        with make_vault() as vault:
            always_url = base + '/?drift=revision-always'
            vault.cases.create('case-fail', '失败演练案件', 'collector')
            vault.captures.start('cap-fail', 'case-fail', 'collector', always_url, policy_for(base), 1,
                                 max_attempts=1)
            result = vault.captures.run('cap-fail', 'collector')
            assert_true(result['state'] == 'failed', '持续漂移应判定失败')
            assert_true(result['failure_reason'] in ('attempts_exhausted', 'revision_drift'),
                        '失败原因应可追溯: %s' % result['failure_reason'])
            assert_true(vault.cases.get('case-fail')['entries'] == [], '失败不得挂载半组内容')
            assert_true(vault.db.scalar("SELECT COUNT(*) FROM objects WHERE state='available'") == 0,
                        '失败不得残留采集对象')

        # 场景四：浏览器采集期间案件被封存
        with make_vault() as vault:
            vault.cases.create('case-sealed', '封存竞态案件', 'collector')
            stored = vault.objects.put(b'prior intake')
            vault.cases.attach('case-sealed', 1, 'collector',
                               {'path': 'intake/note.txt', 'digest': stored['digest'],
                                'size': len(b'prior intake'), 'media_type': 'text/plain',
                                'metadata': {'synthetic': True}})
            case = vault.cases.get('case-sealed')
            vault.captures.start('cap-race', 'case-sealed', 'collector', base + '/', policy_for(base),
                                 case['revision'])

            original_factory = vault.captures.engine_factory

            def sealing_factory(policy, selector, attempts, clock):
                engine = original_factory(policy, selector, attempts, clock)
                original_capture = engine.capture

                def capture_and_seal(url):
                    record = original_capture(url)
                    current = vault.cases.get('case-sealed')
                    vault.seals.prepare('seal-race', 'case-sealed', current['revision'], 'collector')
                    vault.seals.seal('seal-race', 'custodian', '2099-01-01T00:00:00Z')
                    return record

                engine.capture = capture_and_seal
                return engine

            vault.captures.engine_factory = sealing_factory
            result = vault.captures.run('cap-race', 'collector')
            assert_true(result['state'] == 'failed' and result['failure_reason'] == 'case_not_draft',
                        '封存竞态应记录失败原因')
            assert_true(result['record'] is None, '失败任务不保存采集记录')
            sealed_case = vault.cases.get('case-sealed')
            assert_true(sealed_case['state'] == 'sealed', '案件保持封存状态')
            assert_true(not any(entry['path'].startswith('captures/') for entry in sealed_case['entries']),
                        '封存后不得挂载任何采集附件')

        # 场景七：策略层拒绝非 HTTP(S) 与越界地址
        policy = CapturePolicy(policy_for(base))
        for bad_url in ('javascript:alert(1)', 'file:///etc/passwd', 'data:text/html,x',
                        'http://evil.example/', base + '/admin/secret'):
            allowed, reason = policy.check(bad_url)
            assert_true(not allowed, '策略必须拒绝: %s' % bad_url)
        with make_vault() as vault:
            vault.cases.create('case-deny', '策略拒绝案件', 'collector')
            try:
                vault.captures.start('cap-deny', 'case-deny', 'collector', 'http://evil.example/',
                                     policy_for(base), 1)
            except Exception as exc:
                assert_true(getattr(exc, 'code', None) == 'capture_denied', '越界 origin 应拒绝')
            else:
                raise AssertionError('越界 origin 必须被拒绝')

        # 浏览器侧实际拦截验证：越界请求在清单中标记 blocked
        with sync_playwright() as library:
            browser = library.chromium.launch(headless=True, args=['--no-sandbox'])
            context = browser.new_context()
            page = context.new_page()
            blocked = []

            def handler(route):
                allowed, reason = policy.check(route.request.url)
                if not allowed:
                    blocked.append((route.request.url, reason))
                    route.abort('accessdenied')
                else:
                    route.continue_()

            context.route('**/*', handler)
            page.goto(base + '/')
            page.locator('#record[data-ready=true]').wait_for()
            context.close()
            browser.close()
            assert_true(blocked, '浏览器拦截器应能识别越界请求（无外部请求时至少策略检查生效）')

    finally:
        server.shutdown()
        server.server_close()
    print('网页证据端到端演练：稳定采集、漂移重试、整组失败、封存竞态、幂等确认、封存核对、策略拦截全部通过')


if __name__ == '__main__':
    main()
