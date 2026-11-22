"""Обход ссылок и форм в пределах домена."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qsl

import httpx
from bs4 import BeautifulSoup
import re

from sqli_detector import ScanTarget


STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip",
}

API_PATH_RE = re.compile(r"['\"](\/(?:api|v\d+|rest|backend)[a-zA-Z0-9_\-\/]*)['\"]", re.IGNORECASE)

DEFAULT_MAX_PAGES = 100
DEFAULT_MAX_DEPTH = 3
DEFAULT_CONCURRENCY = 5


@dataclass
class LoginConfig:
    login_url: str
    username_field: str
    password_field: str
    username: str
    password: str
    method: str = "POST"
    extra_fields: dict[str, str] = field(default_factory=dict)
    # подстрока, которая должна появиться в ответе после успешного логина (например "Logout" или "Welcome")
    success_marker: str | None = None
    # подстрока, которая НЕ должна появляться (например "Invalid username or password")
    failure_marker: str | None = None


@dataclass
class CrawlResult:
    visited_pages: int = 0
    targets: list[ScanTarget] = field(default_factory=list)
    skipped_external: int = 0
    login_performed: bool = False
    login_confirmed: bool | None = None  # None = не было success/failure_marker для проверки


def _param_signature(path: str, param_names: tuple[str, ...]) -> str:
    """
    'Сигнатура' точки ввода — путь + отсортированный набор имён параметров,
    БЕЗ значений. Это и есть дедупликация: /product?id=1 и /product?id=2
    дают одну и ту же сигнатуру ('/product', ('id',)), поэтому сканер
    проверит только одну из них, а не обе.
    """
    return f"{path}::{','.join(sorted(param_names))}"


class Crawler:
    def __init__(
        self,
        start_url: str,
        max_pages: int = DEFAULT_MAX_PAGES,
        max_depth: int = DEFAULT_MAX_DEPTH,
        concurrency: int = DEFAULT_CONCURRENCY,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        login: LoginConfig | None = None,
    ):
        self.start_url = start_url
        self.domain = urlparse(start_url).netloc
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.cookies = cookies or {}
        self.headers = headers or {"User-Agent": "EduSecScanner/0.1 (student project; authorized testing only)"}
        self.login = login
        self._visited_urls: set[str] = set()
        self._visited_responses: dict[str, str] = {}
        self._seen_signatures: set[str] = set()

        self._session_cookies: dict[str, str] = {}

        self._visited_urls: set[str] = set()
        self._seen_signatures: set[str] = set()
        self._semaphore = asyncio.Semaphore(concurrency)

    async def crawl(self) -> CrawlResult:
        result = CrawlResult()
        queue: list[tuple[str, int]] = [(self.start_url, 0)]

        async with httpx.AsyncClient(
            follow_redirects=True, cookies=self.cookies, headers=self.headers, timeout=10.0
        ) as client:
            if self.login is not None:
                result.login_performed, result.login_confirmed = await self._do_login(client)
                self._session_cookies = dict(client.cookies)

            while queue and result.visited_pages < self.max_pages:
                batch = queue[: self._semaphore._value * 2 or 4]
                queue = queue[len(batch):]

                pages = await asyncio.gather(
                    *(self._fetch_and_parse(client, url, depth) for url, depth in batch)
                )

                for page in pages:
                    if page is None:
                        continue
                    result.visited_pages += 1
                    result.targets.extend(page["targets"])
                    if page["depth"] < self.max_depth:
                        for link in page["links"]:
                            if link not in self._visited_urls:
                                queue.append((link, page["depth"] + 1))

        return result

    async def _do_login(self, client: httpx.AsyncClient) -> tuple[bool, bool | None]:
        """Возвращает признаки попытки и подтверждения входа. Без маркеров результат подтверждения равен None."""
        cfg = self.login

        hidden_fields = {}
        try:
            login_page = await client.get(cfg.login_url)
            soup = BeautifulSoup(login_page.text, "html.parser")
            form = soup.find("form")
            if form:
                for input_tag in form.find_all("input", type="hidden"):
                    name = input_tag.get("name")
                    if name:
                        hidden_fields[name] = input_tag.get("value", "")

                # Некоторые серверы проверяют имя и значение нажатой кнопки.
                submit_input = form.find("input", type="submit")
                if submit_input:
                    submit_name = submit_input.get("name")
                    if submit_name:
                        hidden_fields[submit_name] = submit_input.get("value", "")
        except httpx.HTTPError:
            pass  # не удалось получить страницу логина — пробуем без hidden-полей/submit-кнопки

        payload = {
            cfg.username_field: cfg.username,
            cfg.password_field: cfg.password,
            **hidden_fields,       # CSRF-токен и прочие скрытые поля — ДО extra_fields,
            **cfg.extra_fields,    # чтобы явно заданные руками значения могли их переопределить
        }

        try:
            if cfg.method.upper() == "GET":
                resp = await client.get(cfg.login_url, params=payload)
            else:
                resp = await client.post(cfg.login_url, data=payload)
        except httpx.HTTPError:
            return False, None

        if cfg.success_marker is not None:
            return True, cfg.success_marker in resp.text
        if cfg.failure_marker is not None:
            return True, cfg.failure_marker not in resp.text
        return True, None

    async def _fetch_and_parse(self, client: httpx.AsyncClient, url: str, depth: int) -> dict | None:
        if url in self._visited_urls:
            return None
        self._visited_urls.add(url)

        async with self._semaphore:
            try:
                resp = await client.get(url)
                self._visited_responses[url] = resp.text
            except httpx.HTTPError:
                return None

        if self.login is not None:
            self._session_cookies = dict(client.cookies)

        content_type = resp.headers.get("content-type", "")
        if "text/html" not in content_type:
            return None

        soup = BeautifulSoup(resp.text, "html.parser")

        targets = []
        targets.extend(self._extract_link_targets(url))
        targets.extend(self._extract_form_targets(soup, url))

        js_targets = await self._extract_js_endpoints(client, soup, url)
        targets.extend(js_targets)

        links = self._extract_internal_links(soup, url)

        return {"targets": targets, "links": links, "depth": depth}

    async def _extract_js_endpoints(self, client: httpx.AsyncClient, soup: BeautifulSoup, page_url: str) -> list[ScanTarget]:
        targets = []
        script_tags = soup.find_all("script", src=True)
        
        for script in script_tags:
            src = script["src"]
            js_url = urljoin(page_url, src)
            parsed_js = urlparse(js_url)
            
            if parsed_js.netloc != self.domain:
                continue

            try:
                js_resp = await client.get(js_url)
                if js_resp.status_code != 200:
                    continue
                
                matches = API_PATH_RE.findall(js_resp.text)
                for path in set(matches):
                    if len(path) < 4 or "." in path.split("/")[-1] and not path.endswith(".json"):
                        continue
                    
                    full_endpoint_url = urljoin(self.start_url, path)
                    parsed_endpoint = urlparse(full_endpoint_url)
                    
                    sig = _param_signature(parsed_endpoint.path, ())
                    if sig in self._seen_signatures:
                        continue
                    self._seen_signatures.add(sig)

                    targets.append(ScanTarget(
                        url=full_endpoint_url,
                        method="GET",
                        params={},
                        cookies=self._all_cookies()
                    ))
            except Exception:
                continue

        return targets
    
    def _extract_link_targets(self, url: str) -> list[ScanTarget]:
        parsed = urlparse(url)
        if not parsed.query:
            return []

        params = dict(parse_qsl(parsed.query))
        if not params:
            return []

        path = parsed.path
        sig = _param_signature(path, tuple(params.keys()))
        if sig in self._seen_signatures:
            return []
        self._seen_signatures.add(sig)

        return [ScanTarget(url=url, method="GET", params=params, cookies=self._all_cookies())]

    def _all_cookies(self) -> dict[str, str]:
        """Статичные cookies, переданные руками, + сессионные, полученные после логина."""
        return {**self.cookies, **self._session_cookies}

    def _extract_form_targets(self, soup: BeautifulSoup, page_url: str) -> list[ScanTarget]:
        targets = []
        for form in soup.find_all("form"):
            action = form.get("action") or page_url
            full_url = urljoin(page_url, action)
            method = (form.get("method") or "GET").upper()

            field_names = []
            form_data = {}
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                if not name:
                    continue
                field_names.append(name)
                if input_tag.name == "select":
                    option = input_tag.find("option", selected=True) or input_tag.find("option")
                    form_data[name] = option.get("value", "") if option else ""
                else:
                    default_val = "1" if any(k in name.lower() for k in ["id", "num", "page", "limit"]) else "test"
                    form_data[name] = input_tag.get("value", "") or default_val
                    
            if not field_names:
                continue

            parsed_action = urlparse(full_url)
            sig = _param_signature(parsed_action.path, tuple(field_names))
            if sig in self._seen_signatures:
                continue
            self._seen_signatures.add(sig)

            if method == "GET":
                targets.append(ScanTarget(url=full_url, method="GET", params=form_data, cookies=self._all_cookies()))
            else:
                targets.append(ScanTarget(url=full_url, method="POST", data=form_data, cookies=self._all_cookies()))

        return targets

    def _extract_internal_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        links = []
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            full_url = urljoin(page_url, href)
            parsed = urlparse(full_url)

            if parsed.netloc != self.domain:
                continue
            if parsed.scheme not in ("http", "https"):
                continue
            if any(parsed.path.lower().endswith(ext) for ext in STATIC_EXTENSIONS):
                continue
            if "#" in full_url:
                full_url = full_url.split("#")[0]

            links.append(full_url)

        return links


async def run_recon(start_url: str, **kwargs) -> CrawlResult:
    crawler = Crawler(start_url, **kwargs)
    return await crawler.crawl()


if __name__ == "__main__":
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost/"

    async def _main():
        result = await run_recon(url, max_pages=50, max_depth=3)
        print(f"Обойдено страниц: {result.visited_pages}")
        print(f"Найдено точек ввода (после дедупликации): {len(result.targets)}")
        for t in result.targets:
            fields = t.params or t.data
            print(f"  [{t.method}] {t.url} -- поля: {list(fields.keys())}")

    asyncio.run(_main())