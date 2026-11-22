import unittest
from unittest.mock import AsyncMock, patch
import httpx
from shared_recon import Session, Inventory
from SQLi.sqli_scanner import ReconTarget
from SQLi.sqlmap_client import SqlmapClient, SqlmapAPIError
from scan_pipeline import run_pipeline, run_single, format_results


class CoverageTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_input_is_not_clean_and_filter_counts_visible(self):
        inventory = Inventory(Session('A'), targets=[
            ReconTarget('https://lab.test/api/search?q=private-value'),
            ReconTarget('https://lab.test/'),
            ReconTarget('https://lab.test/login', 'POST', data={'password': 'secret'}),
            ReconTarget('https://lab.test/logout?id=1')], sources=['http'])
        with patch('scan_pipeline.authenticate', AsyncMock(return_value=inventory.session)), \
             patch('scan_pipeline.ReconService.discover', AsyncMock(return_value=inventory)), \
             patch('scan_pipeline.scan_target', AsyncMock(side_effect=SqlmapAPIError('engine failed'))):
            report = await run_pipeline('https://lab.test/', 'sqli', [('', '')], object())
        text = format_results('https://lab.test/', report)
        self.assertEqual(report['sqli']['status'], 'incomplete')
        self.assertIn('параметры: q | ошибка', text)
        self.assertIn('без параметров — 1', text)
        self.assertIn('формы с паролем — 1', text)
        self.assertIn('исключённые пути — 1', text)
        self.assertNotIn('private-value', text)
        self.assertNotIn('secret', text)

    async def test_quick_mode_reports_actual_input(self):
        with patch('scan_pipeline.authenticate', AsyncMock(return_value=Session('A'))), \
             patch('scan_pipeline.scan_target', AsyncMock(return_value=[])):
            report = await run_single('https://lab.test/api?q=x', '', ('', ''), object())
        self.assertEqual(report['coverage']['targets'][0]['fields'], ['q'])
        self.assertEqual(report['coverage']['targets'][0]['status'], 'завершена')

    async def test_api_errors_and_exit_codes_do_not_become_empty_findings(self):
        for endpoint, payload in [
            ('data', {'success': True, 'data': [], 'error': ['sensitive details']}),
            ('data', {'success': False}),
            ('status', {'success': True, 'status': 'terminated', 'returncode': 1}),
            ('status', {'success': True, 'status': 'not running', 'returncode': None})]:
            client = SqlmapClient(sqlmap_dir='/unused')
            async with httpx.AsyncClient(base_url='https://api.test', transport=httpx.MockTransport(
                    lambda request: httpx.Response(200, json=payload))) as http:
                client._http = http
                with self.assertRaises(SqlmapAPIError) as error:
                    await getattr(client, 'get_' + endpoint)('task')
                self.assertNotIn('sensitive details', str(error.exception))

    async def test_successful_empty_engine_result_remains_valid(self):
        client = SqlmapClient(sqlmap_dir='/unused')
        async with httpx.AsyncClient(base_url='https://api.test', transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={'success': True, 'data': [], 'error': []}))) as http:
            client._http = http
            self.assertEqual(await client.get_data('task'), [])

    async def test_full_scan_deduplicates_but_preserves_different_values(self):
        inventory = Inventory(Session('A'), targets=[
            ReconTarget('https://lab.test/me?fields=email'),
            ReconTarget('https://lab.test/me', params={'fields': 'email'}),
            ReconTarget('https://lab.test/me?fields=id'),
            ReconTarget('https://lab.test/socket.io/?EIO=4&t=abc')])
        with patch('scan_pipeline.authenticate', AsyncMock(return_value=inventory.session)), \
             patch('scan_pipeline.ReconService.discover', AsyncMock(return_value=inventory)), \
             patch('scan_pipeline.scan_target', AsyncMock(return_value=[])) as scan:
            report = (await run_pipeline('https://lab.test/', 'sqli', [('', '')], object()))['sqli']
        self.assertEqual(scan.await_count, 2)
        self.assertEqual(report['coverage']['duplicates'], 1)
        self.assertEqual(report['coverage']['service'], 1)

    async def test_timeout_emitted_once_with_no_query_values(self):
        from SQLi.sqli_scanner import scan_target
        from SQLi.waf_detect import WafDetectionResult
        client = AsyncMock()
        client.scan.return_value = ([], True)
        diagnostics = []
        with patch('SQLi.sqli_scanner.detect_waf', AsyncMock(return_value=WafDetectionResult(detected=False))):
            with self.assertRaises(TimeoutError) as error:
                await scan_target(ReconTarget('https://lab.test/redirect?to=private'), client,
                                  scan_timeout=10, diagnostics=diagnostics)
        self.assertEqual(diagnostics, [])
        self.assertIn('/redirect', str(error.exception))
        self.assertNotIn('private', str(error.exception))
