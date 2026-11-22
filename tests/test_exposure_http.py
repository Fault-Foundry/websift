import unittest
from unittest.mock import patch
import httpx
from exposure_bridge import run_exposure
from scan_safety import TrafficGuard, Limits, _current

class ExposureHTTPTests(unittest.IsolatedAsyncioTestCase):
    async def scan(self, handler):
        factory = httpx.AsyncClient
        with patch('exposure_bridge.httpx.AsyncClient', side_effect=lambda **kw: factory(transport=httpx.MockTransport(handler), **kw)):
            return await run_exposure('https://example.test/app')

    async def test_confirmation_redaction_redirects_cookies(self):
        paths = []
        def handler(request):
            paths.append(request.url.path)
            self.assertNotIn('cookie', request.headers)
            if request.url.path == '/.env':
                return httpx.Response(200, text='APP_NAME=test\nDB_PASSWORD=secret-value\nDEBUG=true')
            return httpx.Response(302, headers={'Location': 'https://outside.test/', 'Set-Cookie': 'sid=private'})
        report = await self.scan(handler)
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(paths.count('/.env'), 2)
        self.assertNotIn('secret-value', str(report))

    async def test_soft404(self):
        report = await self.scan(lambda r: httpx.Response(200, text='APP_NAME=x\nDB_PASSWORD=secret\nDEBUG=true'))
        self.assertEqual(report['findings'], [])

    async def test_rate_limit(self):
        guard = TrafficGuard(Limits(0, 0, 0, 0, 0, False))
        token = _current.set(guard)
        try:
            report = await self.scan(lambda r: httpx.Response(429))
            self.assertEqual(report['status'], 'incomplete')
            self.assertTrue(report['retryable'])
            self.assertEqual(guard.count, 1)
        finally:
            _current.reset(token)
