import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
import httpx
from shared_recon import Session
from scan_pipeline import run_pipeline
from IDOR.idor_detector import scan_single_url
from xss_bridge import XSSRun


class QuickModeTests(unittest.IsolatedAsyncioTestCase):
    async def test_xss_does_not_discover(self):
        run = AsyncMock()
        run.project = Path('/tmp/absent-quick-mode-test')
        run.restrict_to_page = lambda url: None
        run.report = lambda: {'strong_candidates': []}
        with patch('scan_pipeline.authenticate', new_callable=AsyncMock, return_value=Session('A')), \
             patch('pathlib.Path.write_text'), \
             patch('browser_xss.check_forms', AsyncMock(return_value={'status': 'skipped', 'tested': 0, 'findings': []})), \
             patch('scan_pipeline.ReconService') as recon, patch('scan_pipeline.XSSRun', return_value=run):
            report = await run_pipeline('https://example.test/page?q=1','xss',[('','')],None,single=True)
        recon.assert_not_called()
        self.assertEqual(run.import_inventory.call_args.args[0].urls,['https://example.test/page?q=1'])
        self.assertEqual(report['xss']['status'],'completed')

    async def test_idor_exact_url_only(self):
        url = 'https://example.test/object?id=2&tab=details'
        calls = []
        def handler(req):
            calls.append(str(req.url))
            return httpx.Response(200,json={'id':2}) if req.headers.get('cookie') else httpx.Response(403)
        sessions = [Session(label,{'sid':label},authenticated=True) for label in ('A','B')]
        result = await scan_single_url(url,sessions,transport=httpx.MockTransport(handler))
        self.assertEqual(set(calls),{url})
        self.assertEqual(len(result['findings']),1)
        self.assertIn('candidate',result['findings'][0]['vuln_type'])

    async def test_idor_requires_accounts(self):
        with self.assertRaises(ValueError):
            await scan_single_url('https://example.test/',[Session('A'),Session('B')])

    def test_xss_scope_allows_payload_not_other_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = XSSRun('https://example.test/page?q=1','/tmp/run.sh',tmp)
            run.restrict_to_page('https://example.test/page?q=1')
            scope = re.compile((run.project/'single-scope.regex').read_text())
            self.assertTrue(scope.search('https://example.test/page?q=payload'))
            for url in ('https://example.test/page2','https://example.test/page/child','https://other.test/page'):
                self.assertFalse(scope.search(url))

    async def test_help_and_commands(self):
        import bot
        message = AsyncMock()
        await bot.start(message)
        text = message.answer.call_args.args[0]
        self.assertNotIn('/sqli_check',text)
        self.assertIn('/modes',text)
        await bot.modes(message)
        for command in ('sqli_check','xss_check','idor_check'):
            self.assertIn('/'+command,message.answer.call_args.args[0])
        message.text = '/xss_check@scanner_bot https://example.test/page'
        with patch('bot.save_urls_and_ask_creds',new_callable=AsyncMock) as save:
            await bot.handle_quick_command(message,AsyncMock())
            self.assertEqual(save.call_args.args[2:4],('xss_check',['https://example.test/page']))
