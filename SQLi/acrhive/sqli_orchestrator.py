"""Архивный CLI для проверки SQLi."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from collections import defaultdict
from dataclasses import asdict

import httpx

from recon import Crawler, LoginConfig, CrawlResult
from sqli_detector import SqliDetector, ScanTarget, Finding

DEFAULT_SCAN_CONCURRENCY = 2
DEFAULT_REQUEST_DELAY = 0.2        # секунд между запросами — защита от rate-limit/anti-automation

_LEN_PATTERN = re.compile(r"len=(\d+)")


def flag_cross_page_artifacts(findings: list[Finding]) -> list[Finding]:
    """
    Если одна и та же пара длин ответа (true, false) встречается у boolean-based
    находок на ДВУХ И БОЛЕЕ РАЗНЫХ URL в рамках одного прогона — это почти
    наверняка не специфичная для страницы SQLi, а что-то общее для всего сайта:
    WAF-баннер (как PHPIDS у DVWA), общий шаблон ошибки, middleware-перехватчик.
    Настоящая SQLi даёт разницу, зависящую от ДАННЫХ конкретной страницы —
    у разных таблиц/страниц она не может совпадать дословно.
    Находки не удаляются (чтобы не потерять сигнал), но явно помечаются и
    получают резко сниженный confidence.
    """
    signature_to_urls: dict[tuple[int, int], set[str]] = defaultdict(set)

    for f in findings:
        if "boolean-based" not in f.method_used:
            continue
        lens = _LEN_PATTERN.findall(f.evidence)
        if len(lens) < 2:
            continue
        signature = tuple(sorted(int(x) for x in lens[:2]))
        signature_to_urls[signature].add(f.url)

    suspicious_signatures = {sig for sig, urls in signature_to_urls.items() if len(urls) >= 2}
    if not suspicious_signatures:
        return findings

    flagged = []
    for f in findings:
        if "boolean-based" not in f.method_used:
            flagged.append(f)
            continue
        lens = _LEN_PATTERN.findall(f.evidence)
        if len(lens) < 2:
            flagged.append(f)
            continue
        signature = tuple(sorted(int(x) for x in lens[:2]))
        if signature in suspicious_signatures:
            flagged.append(Finding(
                vuln_type=f.vuln_type, param=f.param, url=f.url,
                severity=f.severity,
                confidence=min(f.confidence, 0.2),
                method_used=f.method_used + " [ПОХОЖЕ НА ОБЩИЙ WAF/IDS-БАННЕР, не специфично для страницы]",
                evidence=f.evidence + f" | та же пара длин встретилась на {len(signature_to_urls[signature])} разных URL",
                recommendation=f.recommendation,
            ))
        else:
            flagged.append(f)

    return flagged


async def run_pipeline(
    start_url: str,
    max_pages: int,
    max_depth: int,
    scan_concurrency: int,
    login: LoginConfig | None,
    extra_cookies: dict[str, str] | None,
    request_delay: float = 0.0,
) -> tuple[CrawlResult, list[Finding], float, float]:

    t0 = time.monotonic()

    crawler = Crawler(
        start_url,
        max_pages=max_pages,
        max_depth=max_depth,
        cookies=extra_cookies or {},
        login=login,
    )
    crawl_result = await crawler.crawl()
    t1 = time.monotonic()

    if login is not None and crawl_result.login_confirmed is False:
        print(
            "ВНИМАНИЕ: логин, похоже, не удался (failure_marker найден / "
            "success_marker не найден в ответе). Recon продолжится неавторизованным.",
            file=sys.stderr,
        )

    sem = asyncio.Semaphore(scan_concurrency)
    all_findings: list[Finding] = []

    async def bounded_scan(client: httpx.AsyncClient, target: ScanTarget) -> list[Finding]:
        async with sem:
            detector = SqliDetector(client, request_delay=request_delay)
            return await detector.scan(target)

    async with httpx.AsyncClient(follow_redirects=True) as client:
        results = await asyncio.gather(
            *(bounded_scan(client, target) for target in crawl_result.targets)
        )

    for findings in results:
        all_findings.extend(findings)

    # дополнительная проверка на ложное срабатывание уровня ВСЕГО прогона
    # (а не одного параметра) — ищет паттерны, общие для разных страниц,
    # которые обычный confirmation re-run (per-param) увидеть не может
    all_findings = flag_cross_page_artifacts(all_findings)

    t2 = time.monotonic()

    return crawl_result, all_findings, t1 - t0, t2 - t1


def print_report(crawl_result: CrawlResult, findings: list[Finding], recon_time: float, scan_time: float):
    print("=" * 70)
    print("ОТЧЁТ СКАНИРОВАНИЯ")
    print("=" * 70)
    print(f"Обойдено страниц:        {crawl_result.visited_pages}")
    print(f"Найдено точек ввода:     {len(crawl_result.targets)}")
    if crawl_result.login_performed:
        status = {True: "успешно", False: "НЕ УДАЛСЯ", None: "не проверялся"}[crawl_result.login_confirmed]
        print(f"Логин:                   выполнен ({status})")
    print(f"Время recon:             {recon_time:.1f}s")
    print(f"Время scan:              {scan_time:.1f}s")
    print(f"Найдено уязвимостей:     {len(findings)}")
    print("-" * 70)

    if not findings:
        print("Уязвимостей не обнаружено.")
    else:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for f in sorted(findings, key=lambda x: severity_order.get(x.severity.value, 9)):
            print(f"[{f.severity.value.upper():8}] {f.vuln_type} | param='{f.param}' | {f.url}")
            print(f"           method={f.method_used}, confidence={f.confidence}")
            print(f"           evidence: {f.evidence}")
            print()

    print("=" * 70)


def save_json_report(path: str, crawl_result: CrawlResult, findings: list[Finding]):
    report = {
        "summary": {
            "pages_visited": crawl_result.visited_pages,
            "targets_found": len(crawl_result.targets),
            "login_performed": crawl_result.login_performed,
            "login_confirmed": crawl_result.login_confirmed,
            "vulnerabilities_found": len(findings),
        },
        "findings": [
            {**asdict(f), "severity": f.severity.value} for f in findings
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Standalone SQLi-сканер: recon -> scan -> verify -> report")
    parser.add_argument("url", help="Стартовый URL для сканирования")
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--scan-concurrency", type=int, default=DEFAULT_SCAN_CONCURRENCY)
    parser.add_argument(
        "--request-delay", type=float, default=DEFAULT_REQUEST_DELAY,
        help="Пауза в секундах перед каждым запросом (защита от rate-limit/нестабильных сессий). 0 — без паузы.",
    )
    parser.add_argument("--cookie", help="Статичные cookies в формате 'k1=v1; k2=v2' (например PHPSESSID)")
    parser.add_argument("--json-out", help="Путь для сохранения JSON-отчёта")
    parser.add_argument(
        "--debug-targets",
        help="Сохранить в указанный файл РЕАЛЬНЫЕ url/method/params/cookies "
             "каждой найденной цели — для точного воспроизведения через debug_param.py",
    )

    login_group = parser.add_argument_group("авторизация (опционально)")
    login_group.add_argument("--login-url")
    login_group.add_argument("--login-user")
    login_group.add_argument("--login-pass")
    login_group.add_argument("--login-user-field", default="username")
    login_group.add_argument("--login-pass-field", default="password")
    login_group.add_argument("--login-method", default="POST")
    login_group.add_argument("--login-success-marker", help="Подстрока в ответе, подтверждающая успешный логин")
    login_group.add_argument("--login-failure-marker", help="Подстрока в ответе, означающая провал логина")

    return parser


def parse_cookie_string(raw: str | None) -> dict[str, str]:
    cookies = {}
    if raw:
        for pair in raw.split(";"):
            if "=" in pair:
                k, v = pair.strip().split("=", 1)
                cookies[k] = v
    return cookies


def main():
    args = build_arg_parser().parse_args()

    login = None
    if args.login_url and args.login_user and args.login_pass:
        login = LoginConfig(
            login_url=args.login_url,
            username_field=args.login_user_field,
            password_field=args.login_pass_field,
            username=args.login_user,
            password=args.login_pass,
            method=args.login_method,
            success_marker=args.login_success_marker,
            failure_marker=args.login_failure_marker,
        )

    extra_cookies = parse_cookie_string(args.cookie)

    crawl_result, findings, recon_time, scan_time = asyncio.run(
        run_pipeline(
            start_url=args.url,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            scan_concurrency=args.scan_concurrency,
            login=login,
            extra_cookies=extra_cookies,
            request_delay=args.request_delay,
        )
    )

    if args.debug_targets:
        dump = [
            {"url": t.url, "method": t.method, "params": t.params, "data": t.data, "cookies": t.cookies}
            for t in crawl_result.targets
        ]
        with open(args.debug_targets, "w", encoding="utf-8") as fh:
            json.dump(dump, fh, ensure_ascii=False, indent=2)
        print(f"Реальные цели сканера сохранены: {args.debug_targets}")

    print_report(crawl_result, findings, recon_time, scan_time)

    if args.json_out:
        save_json_report(args.json_out, crawl_result, findings)
        print(f"\nJSON-отчёт сохранён: {args.json_out}")


if __name__ == "__main__":
    main()