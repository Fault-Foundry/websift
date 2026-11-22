"""Поиск HTML-формы входа и авторизация."""

import logging
from typing import Optional
from urllib.parse import urljoin, urlsplit
import re

import httpx
from cookie_session import copy_cookies
from bs4 import BeautifulSoup

class LoginDiscoveryError(RuntimeError):
    """No usable HTML login; a browser may be required."""


logger = logging.getLogger(__name__)

_COMMON_LOGIN_PATHS = [
    "/login", "/login.php", "/signin", "/sign-in", "/wp-login.php",
    "/user/login", "/account/login", "/auth/login",
]


def _has_password_field(html: str) -> bool:
    soup = BeautifulSoup(html, "html.parser")
    return soup.find("input", {"type": "password"}) is not None


async def _find_login_page(client: httpx.AsyncClient, base_url: str, login_url: Optional[str]) -> tuple[str, str]:
    """Bounded same-origin discovery, prioritizing actual login links."""
    root = urlsplit(base_url)
    def same_origin(url):
        u = urlsplit(url)
        return (u.scheme, u.hostname, u.port or (443 if u.scheme == 'https' else 80)) == (root.scheme, root.hostname, root.port or (443 if root.scheme == 'https' else 80)) and not u.username
    directory = urljoin(base_url, './')
    site = f'{root.scheme}://{root.netloc}/'
    candidates = ([urljoin(base_url, login_url)] if login_url else []) + [base_url]
    for prefix in dict.fromkeys([directory, site]):
        candidates.extend(urljoin(prefix, p.lstrip('/')) for p in _COMMON_LOGIN_PATHS)
    seen = set()
    while candidates and len(seen) < 24:
        candidate = candidates.pop(0).split('#', 1)[0]
        if candidate in seen or not same_origin(candidate):
            continue
        seen.add(candidate)
        try:
            resp = await client.get(candidate)
        except httpx.HTTPError:
            continue
        if resp.status_code >= 400 or not same_origin(str(resp.url)):
            continue
        try:
            _extract_login_form(resp.text, str(resp.url))
            return str(resp.url), resp.text
        except RuntimeError:
            pass
        soup = BeautifulSoup(resp.text, 'html.parser')
        links = []
        for anchor in soup.find_all('a', href=True):
            href = urljoin(str(resp.url), anchor['href'])
            cue = anchor.get_text(' ', strip=True) + ' ' + anchor['href']
            if same_origin(href) and re.search(r'login|log.?in|sign.?in|вход|войти|account|кабинет', cue, re.I):
                links.append(href)
        candidates[0:0] = links[:10]
    raise LoginDiscoveryError('Не найдена однозначная HTML-форма входа. Возможны SPA/SSO/MFA; нужен браузерный сценарий или необязательная подсказка AUTH_LOGIN_URL.')


def _extract_login_form(html: str, page_url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    candidates = []
    for candidate in soup.find_all('form'):
        passwords = candidate.find_all('input', attrs={'type': re.compile('^password$', re.I)})
        if len(passwords) != 1 or passwords[0].get('autocomplete') == 'new-password':
            continue
        cue = str(candidate.get('action', '')) + ' ' + str(candidate.get('id', ''))
        if re.search(r'register|signup|sign-up|reset|change.password', cue, re.I):
            continue
        candidates.append((candidate, passwords[0]))
    if len(candidates) != 1:
        raise RuntimeError('Не найдена однозначная форма входа')
    form, pwd_input = candidates[0]

    action = form.get("action") or page_url
    action_url = str(httpx.URL(page_url).join(action))
    method = (form.get("method") or "GET").upper()

    fields: dict[str, str] = {}
    username_field = None
    password_field = pwd_input.get("name")

    for inp in form.find_all(["input", "button"]):
        name = inp.get("name")
        if not name or inp.has_attr("disabled"):
            continue
        itype = (inp.get("type") or "text").lower()
        if itype in ("checkbox", "radio") and not inp.has_attr("checked"):
            continue
        if itype in ("file", "reset"):
            continue
        fields[name] = inp.get("value", "")
        if inp.get("autocomplete") == "username":
            username_field = name
        if itype in ("text", "email") and username_field is None:
            username_field = name

    if username_field is None:
        for guess in ("username", "user", "login", "email", "uname"):
            if guess in fields:
                username_field = guess
                break

    if username_field is None or password_field is None:
        raise RuntimeError("Не удалось определить поля username/password внутри формы")

    return {
        "action": action_url,
        "method": method,
        "fields": fields,
        "username_field": username_field,
        "password_field": password_field,
    }


async def detect_login_fields(
    base_url: str,
    login_url: Optional[str] = None,
) -> dict:
    """Возвращает адрес формы, метод и имена полей для LoginConfig."""
    async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
        page_url, html = await _find_login_page(client, base_url, login_url)
    form = _extract_login_form(html, page_url)

    return {
        "login_url": form["action"],
        "login_page_url": page_url,
        "username_field": form["username_field"],
        "password_field": form["password_field"],
        "method": form["method"],
    }


async def generic_login(
    base_url: str,
    username: str,
    password: str,
    login_url: Optional[str] = None,
) -> dict[str, str]:
    """Возвращает cookies после отправки формы входа."""
    async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
        page_url, html = await _find_login_page(client, base_url, login_url)
        form = _extract_login_form(html, page_url)

        payload = dict(form["fields"])
        payload[form["username_field"]] = username
        payload[form["password_field"]] = password

        if form["method"] == "GET":
            resp = await client.get(form["action"], params=payload)
        else:
            resp = await client.post(form["action"], data=payload)
        resp.raise_for_status()

        if _has_password_field(resp.text):
            raise RuntimeError(
                f"Логин, похоже, не удался (password-поле всё ещё на странице после сабмита), "
                f"username={username}"
            )

        cookies = copy_cookies(client.cookies)
        logger.info("Логин OK (%s), cookies: %s", form["action"], list(cookies.keys()))
        return cookies