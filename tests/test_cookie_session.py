import unittest
from unittest.mock import patch
import httpx
from cookie_session import copy_cookies, cookie_header, cookie_key
from shared_recon import authenticate
from SQLi.sqli_scanner import _serialize_cookies


class CookieTests(unittest.IsolatedAsyncioTestCase):
    def jar(self):
        jar = httpx.Cookies()
        jar.set('security', 'root', domain='localhost.local', path='/')
        jar.set('security', 'specific', domain='localhost.local', path='/vulnerabilities/')
        jar.set('security', 'external', domain='external.test', path='/')
        return jar

    def test_duplicate_names_are_preserved_in_request_order(self):
        jar = self.jar()
        url = 'http://localhost:8081/vulnerabilities/sqli_blind/'
        value = _serialize_cookies(jar, url)
        self.assertEqual(value, 'security=specific; security=root')
        self.assertEqual(len(copy_cookies(jar).jar), 3)
        self.assertEqual(cookie_key(jar), cookie_key(copy_cookies(jar)))

    def test_scope_path_boundary_and_https(self):
        jar = self.jar()
        jar.set('secure_only', 'yes', domain='localhost.local', path='/')
        for cookie in jar.jar:
            if cookie.name == 'secure_only':
                cookie.secure = True
        self.assertEqual(cookie_header(jar,'http://localhost:8081/vulnerabilities-other/'), 'security=root')
        self.assertIn('secure_only=yes',cookie_header(jar,'https://localhost/'))
        self.assertNotIn('external',cookie_header(jar,'http://localhost/'))

    async def test_login_returns_full_jar_with_duplicate_security(self):
        form = '<form action="/session" method="POST"><input name="user"><input type="password" name="pass"></form>'
        def handler(req):
            if req.url.path == '/login':
                return httpx.Response(200,text=form,headers=[('set-cookie','security=root; Path=/')])
            if req.url.path == '/session':
                return httpx.Response(200,text='OK',headers=[('set-cookie','sid=test; Path=/'),('set-cookie','security=specific; Path=/vulnerabilities/')])
            return httpx.Response(200,text='Authenticated')
        real = httpx.AsyncClient
        with patch.dict('os.environ',{'AUTH_MODE':'html','AUTH_LOGIN_URL':'http://localhost:8081/login','AUTH_CHECK_URL':'http://localhost:8081/vulnerabilities/sqli_blind/','AUTH_SUCCESS_REGEX':'Authenticated'},clear=True), \
             patch('shared_recon.httpx.AsyncClient',side_effect=lambda **kw:real(transport=httpx.MockTransport(handler),**kw)):
            session = await authenticate('http://localhost:8081/vulnerabilities/sqli_blind/','A','admin','password')
        self.assertTrue(session.authenticated)
        value = cookie_header(session.cookies,'http://localhost:8081/vulnerabilities/sqli_blind/')
        self.assertIn('security=specific', value)
        self.assertIn('security=root', value)
