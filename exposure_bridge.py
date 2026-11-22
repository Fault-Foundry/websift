import importlib.util
from pathlib import Path
import sys
from urllib.parse import urlsplit, urlunsplit
import uuid

import httpx
from scan_safety import SafetyStop, http_hooks

_spec = importlib.util.spec_from_file_location(
    '_exposure_watch', Path(__file__).resolve().parent / 'exposure-watch' / 'scanner.py')
watch = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = watch
_spec.loader.exec_module(watch)


async def run_exposure(url):
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL credentials are not supported")
    target = watch.origin(urlunsplit((parts.scheme, parts.netloc, '', '', '')))
    report = {'status': 'completed', 'findings': [], 'errors': [],
              'notes': [f'Публичные ресурсы origin: {target}. Проверяется 13 фиксированных путей; результаты требуют ручной проверки.']}
    # No login, shared cookie jar, redirects or ambient proxies. Only bounded bodies.
    async with httpx.AsyncClient(follow_redirects=False, trust_env=False, timeout=10,
                                 event_hooks=http_hooks()) as client:
        async def get(path):
            client.cookies.clear()
            async with client.stream('GET', target + path, headers={
                'User-Agent': 'ExposureWatch/1.0 (authorized security testing)',
                'Accept-Encoding': 'identity', 'Range': 'bytes=0-65535',
            }) as response:
                body = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=4096):
                    body.extend(chunk[:65537 - len(body)])
                    if len(body) > 65536:
                        break
                return watch.Response(response.status_code, bytes(body[:65536]).decode('utf-8', errors='replace'),
                                      response.headers.get('content-type', ''), len(body) > 65536)
        try:
            controls = [await get('/__ew_' + uuid.uuid4().hex + suffix) for suffix in ('', '/.env')]
            for path, kind in watch.CHECKS.items():
                response = await get(path)
                if response.status not in (200, 206) or any(watch.same_page(response.body, b.body) for b in controls):
                    continue
                evidence = watch.detect(kind, response.body)
                if not evidence:
                    continue
                confirm = await get(path)
                if (confirm.status not in (200, 206) or not watch.detect(kind, confirm.body)
                        or any(watch.same_page(confirm.body, b.body) for b in controls)):
                    continue
                report['findings'].append({'url': target + path, 'check': kind,
                    'evidence': evidence, 'classification': 'review_required',
                    'truncated': response.truncated or confirm.truncated})
        except SafetyStop as exc:
            report.update(status='incomplete', retryable=exc.retryable)
            report['errors'].append(str(exc))
        except httpx.HTTPError:
            report['status'] = 'incomplete'
            report['errors'].append('Сетевая ошибка при проверке публичных ресурсов.')
    return report


def format_exposure(report):
    lines = [f"Кандидатов на раскрытие данных: {len(report.get('findings', []))}."]
    for finding in report.get('findings', []):
        lines.extend([f"  {finding['url']} — {finding['check']}", f"  {finding['evidence']}"])
    if report['status'] == 'completed' and not report.get('findings'):
        lines.append('На фиксированных путях совпадений нет; это не гарантирует отсутствие утечек.')
    return lines
