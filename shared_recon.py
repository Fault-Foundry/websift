"""One discovery inventory per identity, reused by every detector."""
from scan_safety import http_hooks, Limits, check_safety, engine_pause, request_rate
from dataclasses import dataclass, field
import asyncio
import math
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit, urljoin

import httpx
from cookie_session import copy_cookies, cookie_header, cookie_key
from SQLi.generic_login import _find_login_page, _extract_login_form, _has_password_field
from SQLi.recon import Crawler
from SQLi.sqli_scanner import ReconTarget


def origin(url):
    u = urlsplit(url)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password:
        raise ValueError('Expected HTTP(S) URL without credentials')
    if any(c.isspace() for c in url) or '\\' in url:
        raise ValueError('Invalid URL')
    return u.scheme, u.hostname.lower(), u.port or (443 if u.scheme == 'https' else 80)


@dataclass
class Session:
    label: str
    cookies: dict = field(default_factory=dict, repr=False)
    headers: dict = field(default_factory=dict, repr=False)
    authenticated: bool = False
    auth_evidence: str = "anonymous"
    browser_state: dict | None = field(default=None, repr=False)
    session_storage: dict = field(default_factory=dict, repr=False)
    browser_urls: list[str] = field(default_factory=list)
    auth_check_url: str = ''
    username: str = field(default='', repr=False)

    def __post_init__(self):
        from target_headers import _current
        current = _current.get()
        if current:
            self.headers = {**current[1], **self.headers}


@dataclass
class Inventory:
    session: Session
    urls: list[str] = field(default_factory=list)
    targets: list[ReconTarget] = field(default_factory=list)
    status: str = 'completed'
    errors: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


async def authenticate(url, label, username='', password=''):
    from SQLi.generic_login import LoginDiscoveryError
    mode = os.environ.get('AUTH_MODE', 'auto')
    if mode not in ('auto', 'html', 'browser'):
        raise ValueError('AUTH_MODE must be auto, html or browser')
    if not username and not password:
        return Session(label)
    if not username or not password:
        raise ValueError('Both username and password are required')
    if mode != 'browser':
        try:
            return await _html_authenticate(url, label, username, password)
        except LoginDiscoveryError:
            if mode == 'html':
                raise
    from browser_auth import browser_login
    return await browser_login(url, label, username, password)


async def _html_authenticate(url, label, username='', password=''):
    if not username and not password:
        return Session(label)
    if not username or not password:
        raise ValueError('Both username and password are required')
    marker = os.environ.get('AUTH_SUCCESS_REGEX')
    check_url = os.environ.get('AUTH_CHECK_URL', url)
    expected = origin(url)

    async def guard(request):
        if origin(str(request.url)) != expected:
            raise ValueError('Authentication request leaves configured origin')

    async with httpx.AsyncClient(follow_redirects=True, timeout=15,
                                event_hooks=http_hooks([guard])) as client:
        page, html = await _find_login_page(client, url, os.environ.get('AUTH_LOGIN_URL'))
        form = _extract_login_form(html, page)
        payload = dict(form['fields'])
        payload[form['username_field']] = username
        payload[form['password_field']] = password
        response = await client.request(form['method'], form['action'],
                                        **({'params': payload} if form['method'] == 'GET' else {'data': payload}))
        response.raise_for_status()
        if not client.cookies:
            raise RuntimeError('Вход не создал cookie-сессию; возможно, нужен браузерный сценарий.')
        if marker:
            check = await client.get(check_url)
            if check.status_code != 200 or _has_password_field(check.text) or not re.search(marker, check.text):
                raise RuntimeError(f'Login verification failed for {label}')
            return Session(label, copy_cookies(client.cookies), authenticated=True, auth_evidence='configured marker')

        # Compare the same GET under a separate anonymous cookie jar. A changed
        # page or a new cookie alone never establishes successful authentication.
        from bs4 import BeautifulSoup
        def logout_control(html):
            soup = BeautifulSoup(html, 'html.parser')
            return any(re.search(r'logout|log.out|sign.out|выход|выйти',
                                 node.get_text(' ', strip=True) + ' ' + str(node.get('href', node.get('action', ''))), re.I)
                       for node in soup.find_all(['a', 'form', 'button']))

        probes = list(dict.fromkeys([check_url, str(response.url), page]))
        async with httpx.AsyncClient(follow_redirects=True, timeout=15,
                                    event_hooks=http_hooks([guard])) as anonymous:
            for probe in probes:
                logged = await client.get(probe)
                guest = await anonymous.get(probe)
                if logged.status_code != 200 or _has_password_field(logged.text):
                    continue
                access_changed = probe != page and (guest.status_code in (401, 403) or _has_password_field(guest.text))
                new_logout = logout_control(logged.text) and not logout_control(guest.text)
                if not (access_changed or new_logout):
                    continue
                repeat = await client.get(probe)
                if repeat.status_code != 200 or _has_password_field(repeat.text):
                    continue
                if new_logout and not access_changed and not logout_control(repeat.text):
                    continue
                return Session(label, copy_cookies(client.cookies), authenticated=True,
                               auth_evidence='anonymous access comparison' if access_changed else 'session-only logout control')
        if _has_password_field(response.text):
            raise RuntimeError(f'Вход {label} не подтверждён: сервер вернул форму входа. Проверьте учётные данные или дополнительные требования входа.')
        raise RuntimeError(f'Вход {label} неоднозначен: cookie получена, но признаков доступа под аккаунтом нет. Возможны MFA/SPA; AUTH_CHECK_URL/AUTH_SUCCESS_REGEX доступны как необязательные подсказки.')



class ReconService:
    def __init__(self, url, mode='http', max_pages=None, max_depth=None):
        origin(url)
        if mode not in ('http', 'js', 'browser'):
            raise ValueError('RECON_MODE must be http, js or browser')
        from scan_safety import number
        if max_depth is None:
            max_depth = number('RECON_MAX_DEPTH', 3, 0, 100, int)
        self.url, self.mode = url, mode
        self.max_pages, self.max_depth = min(max_pages if max_pages is not None else float('inf'), Limits.load().pages or float('inf')), max_depth
        self._cache = {}

    async def discover(self, session):
        # Cache belongs to this target/batch, never persisted across sessions.
        key = (session.label, cookie_key(session.cookies), tuple(sorted(session.headers.items())))
        if key not in self._cache:
            self._cache[key] = asyncio.create_task(self._discover(session))
        return await self._cache[key]

    async def _discover(self, session):
        result = Inventory(session)
        crawler = Crawler(self.url, cookies=session.cookies, headers=session.headers or None,
                          max_pages=self.max_pages, max_depth=self.max_depth, concurrency=1)
        try:
            crawled = await crawler.crawl()
            result.sources.append('http')
            session.cookies = copy_cookies(crawler._all_cookies())
            if crawler.errors:
                result.status = 'incomplete'
                result.errors.extend(crawler.errors)
            if session.authenticated and any(_has_password_field(html) for html in crawler._visited_responses.values()):
                result.status = 'incomplete'
                result.errors.append('Password form encountered in authenticated crawl; verify session coverage')
            result.urls = sorted(crawler._visited_responses)
            result.targets = [ReconTarget(t.url, t.method, t.params, t.data,
                                          session.cookies, session.headers) for t in crawled.targets]
            if not result.urls:
                result.status = 'incomplete'
                result.errors.append('HTTP crawl returned no responses')
        except Exception as exc:
            result.status = 'incomplete'
            result.errors.append(f'HTTP: {exc}')
        if self.mode != 'http' or session.browser_state is not None:
            try:
                if session.browser_state is not None or self.mode == 'browser':
                    from browser_auth import browser_discover
                    discovered = await browser_discover(self.url, session, self.max_pages)
                else:
                    discovered = await self._katana(session)
                result.urls = sorted(set(result.urls + discovered))
                result.sources.append(('browser:session' if session.browser_state is not None else 'browser:anonymous')
                                      if session.browser_state is not None or self.mode == 'browser' else 'katana:' + self.mode)
                existing = {(t.url, t.method) for t in result.targets}
                for url in discovered:
                    if urlsplit(url).query and (url, 'GET') not in existing:
                        result.targets.append(ReconTarget(url, cookies=session.cookies, headers=session.headers))
                        existing.add((url, 'GET'))
            except Exception as exc:
                result.status = 'incomplete'
                result.errors.append(f'Katana: {exc}')
        return result

    async def _katana(self, session, timeout=None, binary=None):
        check_safety()
        await engine_pause()
        import signal
        root = urlsplit(self.url)
        scope = '^' + re.escape(f'{root.scheme}://{root.netloc}') + r'(?:/|$)'
        cmd = [binary or os.environ.get('KATANA_BIN', str(Path(__file__).parent / 'xss-orchestrator/bin/katana') if (Path(__file__).parent / 'xss-orchestrator/bin/katana').exists() else 'katana'), '-u', self.url, '-silent', '-duc',
               '-jc', '-cos', os.environ.get('RECON_EXCLUDE_REGEX', r'(?i:/(?:logout|signout|delete|destroy|reset|setup)(?:[/?]|$))'), '-d', str(self.max_depth), '-cs', scope, '-dr', '-rl', str(request_rate()), '-rd', str(math.ceil(Limits.load().interval) if Limits.load().interval >= 1 else 0), '-c', '1', '-p', '1']
        with tempfile.TemporaryDirectory() as tmp:
            headers = dict(session.headers)
            if session.cookies:
                headers['Cookie'] = cookie_header(session.cookies, self.url)
            if headers:
                path = Path(tmp) / 'headers.txt'
                path.write_text('\n'.join(f'{k}: {v}' for k,v in headers.items()))
                path.chmod(0o600)
                cmd += ['-H', str(path)]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE, start_new_session=True)
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout or float(os.environ.get('RECON_TIMEOUT', '300')))
            except (asyncio.TimeoutError, asyncio.CancelledError):
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await proc.wait()
                raise
            await engine_pause()
            if proc.returncode:
                raise RuntimeError(f'process exited {proc.returncode}')
        urls = []
        for line in out.decode(errors='replace').splitlines():
            try:
                if origin(line) == origin(self.url):
                    urls.append(line)
            except ValueError:
                continue
        return urls
