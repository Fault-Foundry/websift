import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from target_headers import parse_lines, parse_target, use_target_headers, headers_for
from durable_queue import QueueStore
from scan_safety import http_hooks
from shared_recon import Session


class TargetFormatTests(unittest.TestCase):
    def test_comments_bom_and_plain_urls(self):
        lines = parse_lines('\ufeff# source\nhttps://lab.test/\nhttps://other.test/\t{"X-Test":"name"}\n')
        self.assertEqual(parse_target(lines[0]), ('https://lab.test/', {}))
        self.assertEqual(parse_target(lines[1])[1], {'x-test': 'name'})

    def test_invalid_headers_do_not_echo_values(self):
        for raw in ['[]', '{"X-Test":2}', '{"X-Test":"secret\\r\\nInjected: yes"}',
                    '{"Host":"secret"}', '{"Authorization":"secret"}',
                    '{"Cookie":"secret"}', '{"X-Test":"a","x-test":"secret"}', '{bad-secret']:
            with self.subTest(raw=raw), self.assertRaises(ValueError) as caught:
                parse_lines('https://lab.test/\t' + raw)
            self.assertNotIn('secret', str(caught.exception))
            self.assertIn('1', str(caught.exception))

    def test_queue_restart_atomic_conflicts_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            store = QueueStore(directory)
            batch, count = store.enqueue(1, 1, ['https://lab.test/\t{"X-Test":"name"}'] * 2, 'all', ['', '', '', ''])
            self.assertEqual(count, 1)
            with self.assertRaises(ValueError):
                store.enqueue(1, 1, ['https://other.test/', 'https://other.test/\t{"X-Test":"other"}'], 'all', ['', '', '', ''])
            self.assertEqual(store.db.execute('SELECT count(*) FROM jobs').fetchone()[0], 1)
            store.close()
            store = QueueStore(directory)
            job = store.claim()
            self.assertEqual(job['url'], 'https://lab.test/')
            self.assertEqual(json.loads(job['headers']), {'x-test': 'name'})
            store.complete(job, {}, [])
            self.assertEqual(store.db.execute('SELECT headers FROM jobs').fetchone()[0], '{}')
            store.close()

    def test_cli_file_headers_and_body(self):
        import cli
        with tempfile.TemporaryDirectory() as directory:
            targets = Path(directory) / 'input.txt'
            targets.write_text('https://lab.test/\t{"User-Agent":"researcher"}')
            body = Path(directory) / 'body.txt'
            body.write_text('q=hello')
            with patch('cli.load_dotenv'):
                result = cli.main(['--queue-dir', directory, 'scan', '--file', str(targets), '--mode', 'sqli_check', '--data-file', str(body), '--enqueue'])
            self.assertEqual(result, 0)
            store = QueueStore(directory)
            job = store.claim()
            self.assertEqual(job['url'], 'https://lab.test/\0q=hello')
            self.assertEqual(json.loads(job['headers']), {'user-agent': 'researcher'})
            store.close()


class HeaderTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_http_redirect_never_sends_headers_off_origin(self):
        seen = []
        def handler(req):
            seen.append(req)
            return httpx.Response(302, headers={'Location': 'https://other.test/'})
        with use_target_headers('https://lab.test/', {'X-Test': 'researcher'}):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler), event_hooks=http_hooks(), follow_redirects=True) as client:
                with self.assertRaises(ValueError):
                    await client.get('https://lab.test/')
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].headers['X-Test'], 'researcher')
        self.assertEqual(headers_for('https://lab.test/'), {})

    async def test_parallel_jobs_do_not_share_headers(self):
        async def task(value):
            with use_target_headers('https://lab.test/', {'X-Test': value}):
                await asyncio.sleep(0)
                return Session('A').headers['x-test']
        self.assertEqual(await asyncio.gather(task('one'), task('two')), ['one', 'two'])

    async def test_runner_passes_context_and_resets(self):
        import scan_runner
        async def pipeline(*args, **kwargs):
            self.assertEqual(Session('A').headers['x-test'], 'worker')
            return {}
        job = {'url': 'https://lab.test/', 'mode': 'xss', 'credentials': '["","","",""]', 'headers': '{"X-Test":"worker"}'}
        with patch('scan_pipeline.run_pipeline', side_effect=pipeline):
            await scan_runner.scan_queued_job(job)
        self.assertEqual(Session('A').headers, {})

    async def test_sqlmap_preserves_user_agent(self):
        from SQLi.sqlmap_client import SqlmapClient, SqlmapTarget
        captured = {}
        def handler(req):
            captured.update(json.loads(req.content))
            return httpx.Response(200, json={'success': True})
        client = SqlmapClient(sqlmap_dir='/unused')
        async with httpx.AsyncClient(base_url='http://api.test', transport=httpx.MockTransport(handler)) as http:
            client._http = http
            await client.start_scan('id', SqlmapTarget('https://lab.test/', headers={'user-agent': 'researcher'}))
        self.assertFalse(captured['randomAgent'])
        self.assertEqual(captured['agent'], 'researcher')
        self.assertTrue(captured['ignoreRedirects'])

    async def test_browser_route_checks_scope_and_fetches_one_hop(self):
        from browser_auth import scoped_context
        context = MagicMock()
        context.route = AsyncMock()
        browser = MagicMock()
        browser.new_context = AsyncMock(return_value=context)
        with use_target_headers('https://lab.test/', {'X-Test': 'browser'}):
            await scoped_context(browser, 'https://lab.test/')
            handler = context.route.call_args.args[1]
            route = MagicMock()
            route.request.url = 'https://lab.test/start'
            route.request.all_headers = AsyncMock(return_value={})
            route.fetch = AsyncMock()
            route.fulfill = AsyncMock()
            route.abort = AsyncMock()
            await handler(route)
            route.fetch.assert_awaited_once_with(headers={'x-test': 'browser'}, max_redirects=0)
            route.fulfill.assert_awaited_once()
            route.request.url = 'https://other.test/'
            await handler(route)
            route.abort.assert_awaited_once()
            self.assertEqual(route.fetch.await_count, 1)

    async def test_xss_inventory_receives_target_headers(self):
        from shared_recon import Inventory
        from xss_bridge import XSSRun
        with tempfile.TemporaryDirectory() as directory, use_target_headers('https://lab.test/', {'X-Test': 'xss'}):
            run = XSSRun('https://lab.test/', Path(__file__).resolve().parents[1] / 'xss-orchestrator/run.sh', directory)
            await run.import_inventory(Inventory(Session('A'), ['https://lab.test/']))
            self.assertEqual(json.loads((run.project / 'session.config.json').read_text())['scan']['headers'], ['x-test: xss'])

    async def test_browser_redirect_keeps_headers_on_origin(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from threading import Thread
        from browser_auth import scoped_context, browser_options
        from playwright.async_api import async_playwright
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get('X-Test')))
                if self.path == '/start':
                    self.send_response(302)
                    self.send_header('Location', '/same')
                elif self.path == '/same':
                    self.send_response(302)
                    self.send_header('Location', f'http://localhost:{self.server.server_port}/outside')
                else:
                    self.send_response(200)
                self.end_headers()
            def log_message(self, *args):
                pass
        try:
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        except PermissionError:
            self.skipTest('Environment prohibits local listening sockets')
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f'http://127.0.0.1:{server.server_port}/start'
        try:
            with use_target_headers(url, {'X-Test': 'browser'}):
                async with async_playwright() as pw:
                    browser = await pw.chromium.launch(**browser_options())
                    try:
                        context = await scoped_context(browser, url)
                        page = await context.new_page()
                        try:
                            await page.goto(url)
                        except Exception:
                            pass
                        self.assertEqual(seen, [('/start', 'browser'), ('/same', 'browser')])
                    finally:
                        await browser.close()
        finally:
            await asyncio.to_thread(server.shutdown)
            server.server_close()
