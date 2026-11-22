"""Сбор ссылок с параметрами и HTML-форм в авторизованной сессии."""

import logging
from typing import Optional
from urllib.parse import urlencode, urljoin, urlparse, parse_qs

import httpx
from bs4 import BeautifulSoup

from .sqli_scanner import ReconTarget

logger = logging.getLogger(__name__)


async def crawl_for_sqli_targets(
    start_url: str,
    cookies: Optional[dict[str, str]] = None,
    max_pages: int = 15,
    max_depth: int = 2,
) -> list[ReconTarget]:
    base_netloc = urlparse(start_url).netloc

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(start_url, 0)]
    targets: list[ReconTarget] = []
    seen_target_keys: set[tuple] = set()

    def _remember(target: ReconTarget) -> bool:
        key = (target.url, target.method, tuple(sorted((target.data or {}).items())))
        if key in seen_target_keys:
            return False
        seen_target_keys.add(key)
        return True

    async with httpx.AsyncClient(follow_redirects=True, timeout=15, cookies=cookies) as client:
        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)

            try:
                resp = await client.get(url)
            except httpx.TransportError as e:
                logger.warning("Recon: не смог получить %s: %s", url, e)
                continue
            if resp.status_code >= 400 or "text/html" not in resp.headers.get("content-type", ""):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            query = parse_qs(urlparse(url).query)
            if query:
                t = ReconTarget(url=url, method="GET", cookies=cookies)
                if _remember(t):
                    targets.append(t)

            for form in soup.find_all("form"):
                action = form.get("action") or url
                action_url = urljoin(url, action)
                if urlparse(action_url).netloc != base_netloc:
                    continue
                method = (form.get("method") or "GET").upper()

                data: dict[str, str] = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    itype = (inp.get("type") or "text").lower()
                    # Сервер может проверять значение submit при обработке формы.
                    if itype in ("button", "image", "reset", "file"):
                        continue
                    data[name] = inp.get("value", "test")

                if not data:
                    continue

                if method == "GET":
                    # Удаляем фрагмент, чтобы параметры запроса не попали после #.
                    action_no_fragment = action_url.split("#", 1)[0]
                    sep = "&" if "?" in action_no_fragment else "?"
                    full_url = f"{action_no_fragment}{sep}{urlencode(data)}"
                    t = ReconTarget(url=full_url, method="GET", cookies=cookies)
                else:
                    t = ReconTarget(url=action_url, method="POST", data=data, cookies=cookies)

                if _remember(t):
                    targets.append(t)

            if depth < max_depth:
                for a in soup.find_all("a", href=True):
                    link = urljoin(url, a["href"]).split("#", 1)[0]
                    if urlparse(link).netloc == base_netloc and link not in visited:
                        queue.append((link, depth + 1))

    logger.info("Recon: на %s нашёл %d потенциальных SQLi-точек (страниц обошёл: %d)",
                start_url, len(targets), len(visited))
    return targets