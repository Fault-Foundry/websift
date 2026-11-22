import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
import httpx
from browser_auth import BrowserAuthError, verify_session, identity_value
from shared_recon import authenticate, Session, Inventory, ReconService
from SQLi.generic_login import LoginDiscoveryError
from xss_bridge import XSSRun


class BrowserSessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_auto_falls_back_only_when_html_login_missing(self):
        session = Session('A', headers={'Authorization':'Bearer test'}, authenticated=True)
        with patch.dict(os.environ, {}, clear=True), \
             patch('shared_recon._html_authenticate', side_effect=LoginDiscoveryError('SPA')), \
             patch('browser_auth.browser_login', new_callable=AsyncMock, return_value=session) as browser:
            self.assertIs(await authenticate('https://lab.invalid/', 'A', 'a', 'p'), session)
            browser.assert_awaited_once()
        with patch.dict(os.environ, {}, clear=True), \
             patch('shared_recon._html_authenticate', side_effect=RuntimeError('bad password')), \
             patch('browser_auth.browser_login', new_callable=AsyncMock) as browser:
            with self.assertRaises(RuntimeError):
                await authenticate('https://lab.invalid/', 'A', 'a', 'p')
            browser.assert_not_awaited()

    async def test_bearer_verified_against_guest(self):
        def handler(req):
            if req.headers.get('authorization') == 'Bearer valid':
                return httpx.Response(200, json={'user':{'email':'a@example.test'}})
            return httpx.Response(200, json={'user':{}})
        probe = await verify_session('https://lab.invalid/', 'a@example.test', {},
                                     {'Authorization':'Bearer valid'}, ['https://lab.invalid/api/me'], httpx.MockTransport(handler))
        self.assertEqual(probe, 'https://lab.invalid/api/me')

    async def test_invalid_and_public_token_responses_rejected(self):
        for data in ({}, {'user':{'email':'a@example.test'}}):
            with self.assertRaises(BrowserAuthError):
                await verify_session('https://lab.invalid/', 'a@example.test', {}, {'Authorization':'Bearer wrong'},
                                     ['https://lab.invalid/api/me'], httpx.MockTransport(lambda _: httpx.Response(200,json=data)))

    async def test_off_origin_probe_not_requested(self):
        def handler(req):
            self.fail('External probe must not be requested')
        with self.assertRaises(BrowserAuthError):
            await verify_session('https://lab.invalid/', 'a', {}, {}, ['https://evil.invalid/api/me'], httpx.MockTransport(handler))

    async def test_browser_state_used_instead_of_cookie_only_katana(self):
        session = Session('A', headers={'Authorization':'Bearer valid'}, authenticated=True,
                          browser_state={'cookies':[], 'origins':[]})
        service = ReconService('https://lab.invalid/')
        crawler = AsyncMock()
        crawler.crawl.return_value.targets = []
        crawler._all_cookies = lambda: {}
        crawler._visited_responses = {'https://lab.invalid/':'<html>shell</html>'}
        crawler.errors = []
        with patch('shared_recon.Crawler', return_value=crawler), \
             patch('browser_auth.browser_discover', new_callable=AsyncMock, return_value=['https://lab.invalid/api/search?q=x']), \
             patch.object(service, '_katana', new_callable=AsyncMock) as katana:
            inventory = await service.discover(session)
        katana.assert_not_awaited()
        self.assertEqual(inventory.targets[0].headers['Authorization'], 'Bearer valid')

    async def test_xss_bearer_config_private(self):
        script = Path(__file__).resolve().parents[1] / 'xss-orchestrator/run.sh'
        with tempfile.TemporaryDirectory() as tmp:
            run = XSSRun('https://lab.invalid/', script, tmp)
            await run.import_inventory(Inventory(Session('A',headers={'Authorization':'Bearer valid'}), ['https://lab.invalid/']))
            config = run.project / 'session.config.json'
            self.assertEqual(json.loads(config.read_text())['scan']['headers'], ['Authorization: Bearer valid'])
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)

    def test_identity_does_not_accept_arbitrary_reflection(self):
        self.assertFalse(identity_value({'query':'a@example.test'}, 'a@example.test'))
