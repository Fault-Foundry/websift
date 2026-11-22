import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from scan_safety import Limits, SafetyStop, TrafficGuard, http_hooks, scan_session
from scan_pipeline import run_pipeline, run_single
from shared_recon import Session, Inventory
from SQLi.sqlmap_client import SqlmapClient, SqlmapTarget
from SQLi.sqli_scanner import ReconTarget


class SafetyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    async def test_concurrent_requests_share_pacing_and_budget(self):
        guard = TrafficGuard(Limits.load())
        now = [100.0]
        starts = []

        async def sleep(seconds):
            now[0] += seconds

        async def request():
            await guard.acquire()
            starts.append(now[0])

        with patch('scan_safety.time.monotonic', lambda: now[0]), \
             patch('scan_safety.asyncio.sleep', sleep):
            await asyncio.gather(*(request() for _ in range(4)))
        self.assertEqual(starts, [100, 101, 102, 103])
        self.assertEqual(guard.count, 4)

    async def test_budget_prevents_next_network_request(self):
        os.environ['SCAN_MAX_REQUESTS'] = '1'
        calls = []
        with self.assertRaises(SafetyStop):
            async with scan_session():
                async with httpx.AsyncClient(event_hooks=http_hooks(), transport=httpx.MockTransport(
                        lambda req: (calls.append(req), httpx.Response(200))[1])) as client:
                    await client.get('https://lab.test/')
                    await client.get('https://lab.test/')
        self.assertEqual(len(calls), 1)

    async def test_overload_response_stops_before_another_engine(self):
        for status in (429, 500, 503):
            calls = []
            with self.assertRaises(SafetyStop):
                async with scan_session():
                    async with httpx.AsyncClient(event_hooks=http_hooks(), transport=httpx.MockTransport(
                            lambda req: (calls.append(req), httpx.Response(status))[1])) as client:
                        await client.get('https://lab.test/')
                        self.fail('Response must trip the guard')
            self.assertEqual(len(calls), 1)

    async def test_separate_scans_cannot_overlap(self):
        entered = asyncio.Event()
        release = asyncio.Event()
        events = []

        async def first():
            async with scan_session():
                events.append('first')
                entered.set()
                await release.wait()
                events.append('finished')

        async def second():
            await entered.wait()
            async with scan_session():
                events.append('second')

        a, b = asyncio.create_task(first()), asyncio.create_task(second())
        await entered.wait()
        await asyncio.sleep(0)
        self.assertEqual(events, ['first'])
        release.set()
        await asyncio.gather(a, b)
        self.assertEqual(events, ['first', 'finished', 'second'])

    async def test_sqlmap_preserves_coverage_but_enforces_request_delay(self):
        captured = {}
        def handler(request):
            captured.update(json.loads(request.content))
            return httpx.Response(200, json={'success': True})
        client = SqlmapClient(sqlmap_dir='/unused')
        async with httpx.AsyncClient(base_url='https://api.test', transport=httpx.MockTransport(handler)) as http:
            client._http = http
            await client.start_scan('task', SqlmapTarget('https://lab.test/?q=x',
                                    level=5, risk=3, delay=0, tamper='randomcase'))
        for key, value in {'threads': 1, 'risk': 3, 'level': 5, 'delay': 1,
                           'technique': 'BEUSTQ', 'retries': 0, 'randomAgent': True}.items():
            self.assertEqual(captured[key], value)
        self.assertEqual(captured['tamper'], 'randomcase')

    async def test_cancel_stops_sqlmap_task(self):
        client = SqlmapClient(sqlmap_dir='/unused')
        entered = asyncio.Event()
        async def polling(task):
            entered.set()
            await asyncio.Event().wait()
        client.new_task = AsyncMock(return_value='task')
        client.start_scan = AsyncMock()
        client.get_status = polling
        client.stop_scan = AsyncMock()
        client.delete_task = AsyncMock()
        task = asyncio.create_task(client.scan(SqlmapTarget('https://lab.test/')))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        client.stop_scan.assert_awaited_once_with('task')
        client.delete_task.assert_awaited_once_with('task')

    async def test_target_cap_reports_incomplete(self):
        os.environ['SCAN_MAX_TARGETS'] = '1'
        inv = Inventory(Session('A'), targets=[ReconTarget('https://lab.test/?q=1'),
                                               ReconTarget('https://lab.test/?q=2')])
        with patch('scan_pipeline.authenticate', AsyncMock(return_value=inv.session)), \
             patch('scan_pipeline.ReconService.discover', AsyncMock(return_value=inv)), \
             patch('scan_pipeline.scan_target', AsyncMock(return_value=[])) as scan:
            report = await run_pipeline('https://lab.test/', 'sqli', [('', '')], object())
        self.assertEqual(scan.await_count, 1)
        self.assertEqual(report['sqli']['status'], 'incomplete')

    async def test_xss_can_disable_browser_forms_explicitly(self):
        os.environ['SCAN_BROWSER_FORMS'] = '0'
        run = AsyncMock()
        run.report.return_value = {}
        with tempfile.TemporaryDirectory() as tmp:
            run.project = Path(tmp)
            run.report = lambda: {}
            with patch('scan_pipeline.authenticate', AsyncMock(return_value=Session('A'))), \
                 patch('scan_pipeline.XSSRun', return_value=run), \
                 patch('browser_xss.check_forms', AsyncMock()) as forms:
                await run_pipeline('https://lab.test/', 'xss', [('', '')], None, single=True)
            forms.assert_not_awaited()

    async def test_xss_filters_scope_before_applying_target_cap(self):
        from xss_bridge import XSSRun
        os.environ['SCAN_MAX_TARGETS'] = '1'
        with tempfile.TemporaryDirectory() as tmp:
            run = XSSRun('https://lab.test/', Path(__file__).resolve().parents[1] / 'xss-orchestrator/run.sh', tmp)
            await run.import_inventory(Inventory(Session('A'), [
                'https://other.test/', 'https://lab.test/?q=1', 'https://lab.test/?q=2']))
            self.assertEqual(run.urls(), ['https://lab.test/?q=1'])
            coverage = json.loads((run.project / 'coverage.json').read_text())
            self.assertEqual(coverage['limited_urls'], 1)
            self.assertEqual(coverage['supplied_urls'], 1)

    async def test_browser_routes_share_budget_and_abort_after_limit(self):
        from browser_auth import scoped_context
        browser = AsyncMock()
        context = browser.new_context.return_value
        from unittest.mock import Mock
        context.set_default_timeout = Mock()
        context.on = Mock()
        os.environ['SCAN_MAX_REQUESTS'] = '1'
        with self.assertRaises(SafetyStop):
            async with scan_session():
                await scoped_context(browser, 'https://lab.test/')
                route_handler = context.route.call_args.args[1]
                first, second = AsyncMock(), AsyncMock()
                first.request.url = second.request.url = 'https://lab.test/'
                await route_handler(first)
                await route_handler(second)
                first.continue_.assert_awaited_once()
                second.abort.assert_awaited_once()
                second.continue_.assert_not_awaited()

    async def test_anonymous_browser_recon_uses_controlled_browser(self):
        from shared_recon import ReconService
        service = ReconService('https://lab.test/', mode='browser')
        crawler = AsyncMock()
        crawler.crawl.return_value.targets = []
        crawler._all_cookies = lambda: {}
        crawler._visited_responses = {'https://lab.test/': '<html></html>'}
        crawler.errors = []
        with patch('shared_recon.Crawler', return_value=crawler), \
             patch('browser_auth.browser_discover', AsyncMock(return_value=[])) as browser, \
             patch.object(service, '_katana', AsyncMock()) as katana:
            await service.discover(Session('A'))
        browser.assert_awaited_once()
        katana.assert_not_awaited()

    async def test_timeout_reports_incomplete(self):
        class ImmediateTimeout:
            async def __aenter__(self):
                raise TimeoutError
            async def __aexit__(self, *args):
                pass
        with patch('scan_safety.asyncio.timeout', return_value=ImmediateTimeout()):
            report = await run_single('https://lab.test/', '', ('', ''), None)
        self.assertEqual(report['status'], 'incomplete')
        self.assertIn('SCAN_TIMEOUT', report['errors'][0])

    def test_invalid_limits_fail_closed(self):
        for value in ('0', '-1', 'nan', 'inf', '0.5', '61', 'abc'):
            with patch.dict(os.environ, {'SCAN_REQUEST_INTERVAL': value}):
                with self.assertRaises(ValueError):
                    Limits.load()
        self.assertTrue(Limits.load().browser_forms)
