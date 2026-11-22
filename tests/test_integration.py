import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
import httpx
from shared_recon import Session, Inventory, ReconService, authenticate
from IDOR.idor_detector import scan_inventories
from IDOR.idor_recon import observations
from xss_bridge import XSSRun
from scan_pipeline import run_pipeline
from SQLi.sqli_scanner import _serialize_data


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_discovery_cached_per_session(self):
        service = ReconService('https://test.invalid')
        with patch.object(service, '_discover', new_callable=AsyncMock) as discover:
            a = Session('A', {'sid': 'a'})
            await service.discover(a)
            await service.discover(a)
            await service.discover(Session('B', {'sid': 'b'}))
            self.assertEqual(discover.await_count, 2)

    async def test_all_consumes_same_inventory(self):
        inventory = Inventory(Session('A'), ['https://test.invalid/'])
        bridge = AsyncMock()
        bridge.project = Path('/tmp/nonexistent-test-project')
        bridge.report = lambda: {'strong_candidates': [], 'dom_candidates': [], 'reflections': []}
        with patch('exposure_bridge.run_exposure', AsyncMock(return_value={'status': 'completed', 'findings': []})), \
             patch('scan_pipeline.authenticate', new_callable=AsyncMock, return_value=Session('A')), \
             patch('scan_pipeline.ReconService.discover', new_callable=AsyncMock, return_value=inventory) as discover, \
             patch('scan_pipeline.scan_inventories', new_callable=AsyncMock, return_value={'status':'completed','findings':[]}), \
             patch('pathlib.Path.write_text'), \
             patch('browser_xss.check_forms', AsyncMock(return_value={'status': 'skipped', 'tested': 0, 'findings': []})), \
             patch('scan_pipeline.XSSRun', return_value=bridge):
            result = await run_pipeline('https://test.invalid', 'all', [('', ''), ('', '')], object())
        self.assertEqual(discover.await_count, 2)
        bridge.import_inventory.assert_awaited_once_with(inventory)
        self.assertEqual(result['sqli']['status'], 'skipped')

    async def test_auth_failure_does_not_fall_back(self):
        with patch('exposure_bridge.run_exposure', AsyncMock(return_value={'status': 'completed', 'findings': []})), \
             patch('scan_pipeline.authenticate', side_effect=RuntimeError('invalid login')), \
             patch('scan_pipeline.ReconService.discover', new_callable=AsyncMock) as discover:
            result = await run_pipeline('https://test.invalid', 'all', [('a','x'), ('b','y')], None)
        discover.assert_not_awaited()
        self.assertTrue(all(result[tool]['status'] == 'error' for tool in ('sqli', 'idor', 'xss')))

    async def test_form_page_action_and_csrf_same_session(self):
        seen = []
        def handler(request):
            seen.append(request)
            if request.url.path == '/login':
                return httpx.Response(200, text='<form action="/session" method="post"><input type="hidden" name="csrf" value="abc"><input name="username"><input type="password" name="password"></form>', headers={'set-cookie':'csrf=abc; Path=/'})
            if request.url.path == '/session':
                self.assertIn(b'csrf=abc', request.content)
                self.assertIn('csrf=abc', request.headers['cookie'])
                return httpx.Response(200, text='OK', headers={'set-cookie':'sid=a; Path=/'})
            return httpx.Response(200, text='Signed in as A')
        real_client = httpx.AsyncClient
        with patch.dict('os.environ', {'AUTH_SUCCESS_REGEX':'Signed in as A', 'AUTH_CHECK_URL':'https://test.invalid/me'}), \
             patch('shared_recon.httpx.AsyncClient', side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw)):
            session = await authenticate('https://test.invalid/login', 'A', 'a', 'password')
        self.assertTrue(session.authenticated)
        self.assertEqual(session.cookies['sid'], 'a')

    async def idor_case(self, vulnerable=False, public=False, shell=False):
        urls = ['https://test.invalid/item?id=1&tab=info', 'https://test.invalid/item?id=2&tab=info']
        inv = [Inventory(Session(label, {'sid': str(i)}, authenticated=True), [urls[i-1]]) for i,label in ((1,'A'),(2,'B'))]
        def handler(request):
            ident = request.headers.get('cookie', '').replace('sid=', '')
            obj = request.url.params.get('id')
            self.assertIn(obj, ('1','2'))
            self.assertEqual(request.url.params['tab'], 'info')
            if shell:
                return httpx.Response(200, text='<html>SPA shell</html>')
            if not public and (not ident or (not vulnerable and ident != obj)):
                return httpx.Response(403, json={'error':'denied'})
            return httpx.Response(200, json={'id':obj, 'secret':f'private {obj}'})
        return await scan_inventories(inv, 0, httpx.MockTransport(handler))

    async def test_idor_authorized_only(self):
        self.assertEqual((await self.idor_case())['findings'], [])

    async def test_idor_cross_access_candidate(self):
        result = await self.idor_case(vulnerable=True)
        self.assertEqual(len(result['findings']), 2)
        self.assertIn('candidate', result['findings'][0]['vuln_type'])

    async def test_idor_public_and_spa_shell_not_findings(self):
        self.assertEqual((await self.idor_case(public=True))['findings'], [])
        self.assertEqual((await self.idor_case(shell=True))['findings'], [])

    async def test_import_xss_inventory_without_crawl(self):
        script = Path(__file__).resolve().parents[1] / 'xss-orchestrator/run.sh'
        with tempfile.TemporaryDirectory() as tmp:
            run = XSSRun('https://test.invalid/', script, tmp)
            await run.import_inventory(Inventory(Session('A', {'sid':'secret'}),
                ['https://test.invalid/?a=1&a=2', 'https://external.invalid/?a=1']))
            self.assertEqual(run.urls(), ['https://test.invalid/?a=1&a=2'])
            self.assertTrue((run.run / 'recon.complete').exists())
            self.assertEqual((run.project/'session.http').stat().st_mode & 0o777, 0o600)

    async def test_serialization_and_id_positions(self):
        self.assertEqual(_serialize_data({'x':'a&b=c'}), 'x=a%26b%3Dc')
        result = observations(['https://test.invalid/users/1/items/2'])
        self.assertEqual(len(result), 2)


if __name__ == '__main__':
    unittest.main()


class ShellContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_wrapper_with_fake_dalfox(self):
        import os
        script = Path(__file__).resolve().parents[1] / 'xss-orchestrator/run.sh'
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'dalfox'
            fake.write_text('''#!/usr/bin/env python3
import sys,json
if '--version' in sys.argv:
 print('3.2.4');sys.exit(0)
assert sys.argv[1] == 'scan'
assert '--cookie-from-raw' in sys.argv
config=json.load(open(sys.argv[sys.argv.index('--config')+1]))
assert config['scan']['headers'] == ['Authorization: Bearer test']
path=sys.argv[sys.argv.index('-o')+1]
open(path,'w').write(json.dumps({'meta':{'incomplete':False,'target_summary':[]},'findings':[]}))
''')
            fake.chmod(0o700)
            import shutil
            wrapper = Path(tmp) / 'wrapper'
            wrapper.mkdir()
            shutil.copy(script, wrapper / 'run.sh')
            shutil.copy(script.parent / 'glue.py', wrapper / 'glue.py')
            run = XSSRun('https://test.invalid/', wrapper / 'run.sh', tmp)
            await run.import_inventory(Inventory(Session('A', {'sid':'secret'}, {'Authorization':'Bearer test'}), ['https://test.invalid/?a=1']))
            with patch.dict(os.environ, {'PATH':tmp + os.pathsep + os.environ['PATH']}):
                await run.execute('scan', 10)
            self.assertEqual(run.report()['strong_candidates'], [])
