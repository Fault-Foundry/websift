"""Conservative read-only cross-account comparison of observed GET requests."""
from scan_safety import http_hooks
from dataclasses import dataclass, field, asdict
from enum import Enum
import asyncio
import hashlib
import httpx
from cookie_session import cookie_key
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit


class Severity(str, Enum):
    MEDIUM = 'medium'


@dataclass
class Finding:
    vuln_type: str
    param: str
    url: str
    severity: Severity
    confidence: float
    method_used: str
    evidence: str
    recommendation: str = 'Verify object ownership and expected access policy manually.'


@dataclass
class IdentityContext:
    label: str
    cookies: dict = field(default_factory=dict, repr=False)
    headers: dict = field(default_factory=dict, repr=False)
    owned_id: str = ''


def fingerprint(response):
    if response.status_code != 200 or not response.content:
        return None
    # Ignore serialization whitespace/key order, never ignore actual values.
    try:
        import json
        body = json.dumps(response.json(), sort_keys=True, separators=(',', ':')).encode()
    except ValueError:
        body = response.content
    return hashlib.sha256(body).hexdigest()


async def scan_inventories(inventories, request_delay=0.5, transport=None):
    from .idor_recon import observations
    if len(inventories) != 2 or not all(x.session.authenticated for x in inventories):
        raise ValueError('IDOR requires two verified authenticated sessions')
    a, b = inventories
    if cookie_key(a.session.cookies) == cookie_key(b.session.cookies) and a.session.headers == b.session.headers:
        raise ValueError('IDOR sessions must differ')
    candidates = [observations(x.urls) for x in inventories]
    findings, errors = [], []
    # Separate cookie jars prevent responses for A contaminating B/anonymous.
    clients = [httpx.AsyncClient(event_hooks=http_hooks(), cookies=x.session.cookies, headers=x.session.headers,
                                follow_redirects=False, timeout=10, transport=transport) for x in inventories]
    anonymous = httpx.AsyncClient(event_hooks=http_hooks(), follow_redirects=False, timeout=10, transport=transport)
    async def get(client, url):
        await asyncio.sleep(request_delay)
        return await client.get(url)
    try:
        for viewer, owner in ((0, 1), (1, 0)):
            for key in candidates[viewer].keys() & candidates[owner].keys():
                own_urls, other_urls = candidates[viewer][key], candidates[owner][key]
                for url in sorted(other_urls - own_urls):
                    try:
                        reference = await get(clients[owner], url)
                        public = await get(anonymous, url)
                        cross = await get(clients[viewer], url)
                        expected = fingerprint(reference)
                        if not expected or fingerprint(public) == expected or fingerprint(cross) != expected:
                            continue
                        # Exclude generic pages returned for every object, such as SPA shells.
                        own = await get(clients[viewer], sorted(own_urls)[0])
                        if fingerprint(own) == expected:
                            continue
                        repeated = await get(clients[viewer], url)
                        if fingerprint(repeated) != expected:
                            continue
                        findings.append(Finding('IDOR candidate (ownership unverified)', key[-1], url,
                            Severity.MEDIUM, 0.5, 'cross-account exact content comparison',
                            f'Аккаунт {inventories[viewer].session.label} получил то же содержимое, что '
                            f'{inventories[owner].session.label}, по URL из разведки второго аккаунта. '
                            f'HTTP: {inventories[viewer].session.label}={cross.status_code}, '
                            f'{inventories[owner].session.label}={reference.status_code}, гость={public.status_code}. '
                            'Ответ гостю отличается; повторный запрос совпал. Владение объектом не проверено.'))
                    except httpx.HTTPError as exc:
                        errors.append(type(exc).__name__)
    finally:
        for client in clients + [anonymous]:
            await client.aclose()
    return {'status': 'incomplete' if errors else ('completed' if any(candidates[0].keys() & candidates[1].keys()) else 'skipped'),
            'errors': errors, 'findings': [{**asdict(x), 'severity': x.severity.value} for x in findings]}


async def scan_single_url(url, sessions, transport=None):
    """Compare only the supplied resource; do not enumerate or invent IDs."""
    if len(sessions) != 2 or not all(s.authenticated for s in sessions):
        raise ValueError('IDOR требует два авторизованных аккаунта A и B.')
    if cookie_key(sessions[0].cookies) == cookie_key(sessions[1].cookies) and sessions[0].headers == sessions[1].headers:
        raise ValueError('Для IDOR нужны разные сессии A и B.')
    clients = [httpx.AsyncClient(event_hooks=http_hooks(), cookies=s.cookies, headers=s.headers, follow_redirects=False,
                                timeout=10, transport=transport) for s in sessions]
    guest = httpx.AsyncClient(event_hooks=http_hooks(), follow_redirects=False, timeout=10, transport=transport)
    result = {'status': 'completed', 'errors': [], 'findings': [],
              'notes': ['Один URL: сравнение A/B/гость без перебора ID. Владение объектом и ожидаемые права нужно проверить вручную.']}
    try:
        a, b, public = await clients[0].get(url), await clients[1].get(url), await guest.get(url)
        expected = fingerprint(a)
        if expected and fingerprint(b) == expected and fingerprint(public) != expected:
            repeated = [await client.get(url) for client in clients]
            if all(fingerprint(r) == expected for r in repeated):
                result['findings'].append({'vuln_type': 'IDOR candidate (ownership unverified)', 'param': 'single URL',
                                          'url': url, 'severity': 'medium',
                                          'evidence': f'Аккаунты {sessions[0].label} и {sessions[1].label} получили одинаковое содержимое. '
                                          f'HTTP: {sessions[0].label}={a.status_code}, {sessions[1].label}={b.status_code}, гость={public.status_code}. '
                                          'Ответ гостю отличается; повторные запросы совпали. Совместный доступ может быть разрешён.'})
        if any(r.status_code >= 500 or r.status_code == 429 or 300 <= r.status_code < 400 for r in (a,b,public)):
            result['status'] = 'incomplete'
            result['errors'].append('Редирект или ошибка сервера: сравнение одной страницы неполно.')
    finally:
        for client in clients + [guest]:
            await client.aclose()
    return result
