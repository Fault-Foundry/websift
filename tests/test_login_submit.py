import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from browser_auth import carries_credentials, submit_and_wait, BrowserAuthError


class SubmitTests(unittest.IsolatedAsyncioTestCase):
    def test_identifies_credentials_not_background_request(self):
        req = SimpleNamespace(method='POST',post_data='{"email":"a@test","password":"p&x"}')
        self.assertTrue(carries_credentials(req,'a@test','p&x'))
        req.post_data='email=a%40test&password=p%26x'
        self.assertTrue(carries_credentials(req,'a@test','p&x'))
        req.post_data='{"email":"a@test"}'
        self.assertFalse(carries_credentials(req,'a@test','p&x'))

    async def run_submit(self, status):
        context = SimpleNamespace()
        callbacks = {}
        context.on = lambda event, callback: callbacks.update({event:callback})
        context.remove_listener = lambda event, callback: callbacks.pop(event)
        page, button, locator = AsyncMock(), AsyncMock(), AsyncMock()
        page.locator = lambda _: locator
        response = SimpleNamespace(url='https://lab.test/rest/user/login',status=status,
                    request=SimpleNamespace(method='POST',post_data='{"email":"a@test","password":"secret"}'),finished=AsyncMock())
        async def click():
            asyncio.get_running_loop().call_later(0.01, callbacks['response'], response)
        button.click.side_effect=click
        await submit_and_wait(context,page,button,'a@test','secret','https://lab.test/')
        self.assertFalse(callbacks)
        locator.wait_for.assert_awaited_once_with(state='hidden',timeout=15000)

    async def test_waits_for_response_and_ui(self):
        await self.run_submit(200)

    async def test_login_401_reported_directly(self):
        with self.assertRaisesRegex(BrowserAuthError,'HTTP 401'):
            await self.run_submit(401)
