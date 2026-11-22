import os
import unittest
from unittest.mock import patch
import httpx
from shared_recon import authenticate
from SQLi.generic_login import _extract_login_form

FORM = '<form action="/app/session" method="post"><input name="csrf" type="hidden" value="abc"><input name="email" autocomplete="username"><input name="password" type="password"><button name="submit" value="login">Login</button></form>'


class AutoAuthTests(unittest.IsolatedAsyncioTestCase):
    async def login(self, scenario):
        requests = []
        def handler(request):
            requests.append(request)
            logged = 'sid=valid' in request.headers.get('cookie', '')
            path = request.url.path
            if path == '/app/':
                return httpx.Response(200, text='<a href="/unusual-entry">Войти</a>')
            if path == '/unusual-entry':
                if logged:
                    return httpx.Response(302, headers={'location':'/app/account'})
                html = FORM if scenario != 'external' else FORM.replace('/app/session','https://evil.invalid/session')
                return httpx.Response(200, text=html, headers={'set-cookie':'csrf=abc; Path=/'})
            if path == '/app/session':
                if request.method != 'POST':
                    return httpx.Response(405)
                self.assertIn(b'csrf=abc', request.content)
                self.assertIn(b'submit=login', request.content)
                self.assertIn('csrf=abc', request.headers['cookie'])
                if scenario == 'bad':
                    return httpx.Response(200, text=FORM)
                return httpx.Response(302, headers={'location':'/app/account','set-cookie':'sid=valid; Path=/'})
            if path == '/app/account':
                if scenario == 'ambiguous':
                    return httpx.Response(200, text='Public landing page')
                if logged:
                    return httpx.Response(200, text='<a href="/app/logout">Logout</a><p>Private account</p>')
                return httpx.Response(302, headers={'location':'/unusual-entry'})
            return httpx.Response(404)
        real = httpx.AsyncClient
        with patch.dict(os.environ, {}, clear=True), patch('shared_recon.httpx.AsyncClient', side_effect=lambda **kw: real(transport=httpx.MockTransport(handler), **kw)):
            result = await authenticate('https://test.invalid/app/', 'A', 'user', 'password')
        return result, requests

    async def test_link_discovery_and_automatic_verification(self):
        session, requests = await self.login('success')
        self.assertTrue(session.authenticated)
        self.assertEqual(session.auth_evidence, 'anonymous access comparison')
        self.assertFalse(any(r.url.path == '/login' for r in requests))
        self.assertEqual(sum(r.method == 'POST' for r in requests), 1)

    async def test_wrong_password_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'не подтверждён'):
            await self.login('bad')

    async def test_new_cookie_and_public_page_not_success(self):
        with self.assertRaisesRegex(RuntimeError, 'неоднозначен'):
            await self.login('ambiguous')

    async def test_external_form_action_blocked(self):
        with self.assertRaisesRegex(ValueError, 'leaves configured origin'):
            await self.login('external')

    def test_signup_not_selected(self):
        signup = '<form action="/register"><input name="u"><input type="password" name="p"></form>'
        form = _extract_login_form(signup + FORM, 'https://test.invalid')
        self.assertEqual(form['action'], 'https://test.invalid/app/session')

    def test_ambiguous_forms_not_submitted(self):
        with self.assertRaises(RuntimeError):
            _extract_login_form(FORM + FORM, 'https://test.invalid')
