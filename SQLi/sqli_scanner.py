"""Проверка целей SQLi через sqlmap и преобразование результатов в Finding."""

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional
from cookie_session import cookie_header
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

from .finding import Confidence, Finding, Severity, VulnType
from .profile import ScanProfile, build_profile
from .sqlmap_client import SqlmapClient, SqlmapTarget
from .waf_detect import detect_waf

logger = logging.getLogger(__name__)


@dataclass
class ReconTarget:
    url: str
    method: str = "GET"
    params: Optional[dict] = None
    data: Optional[dict] = None
    cookies: Optional[dict] = None
    headers: Optional[dict] = None


def _build_get_url(url: str, params: Optional[dict]) -> str:
    """
    Собирает финальный URL для GET-цели: срезает fragment (action="#" и т.п. —
    иначе параметры уйдут в fragment и никогда не долетят до сервера по HTTP),
    мержит params с уже существующим query string (не дублируя одинаковые ключи).
    """
    url_no_fragment = url.split("#", 1)[0]
    if not params:
        return url_no_fragment

    parsed = urlparse(url_no_fragment)
    scheme, netloc, path, query_str = parsed.scheme, parsed.netloc, parsed.path, parsed.query
    existing = dict(parse_qsl(query_str))
    merged = {**existing, **params}  # params из формы/рекона перекрывают дубли из самого url
    new_query = urlencode(merged)
    return urlunparse((scheme, netloc, path, "", new_query, ""))


# Служебные поля исключаются при сокращённом повторе.
_NON_INJECTABLE_FIELD_HINTS = {
    "submit", "login", "change", "upload", "sign", "clear", "send",
    "create_db", "seclev_submit", "max_file_size",
}


def _pick_test_parameters(params: Optional[dict], data: Optional[dict]) -> Optional[str]:
    """Список полей для повторной проверки или None для полного набора."""
    all_fields = {**(params or {}), **(data or {})}
    candidates = [k for k in all_fields if k.lower() not in _NON_INJECTABLE_FIELD_HINTS]
    if not candidates or len(candidates) == len(all_fields):
        return None
    return ",".join(candidates)


def _serialize_data(data: Optional[dict]) -> Optional[str]:
    if not data:
        return None
    return urlencode(data, doseq=True)


def _serialize_cookies(cookies, url: str) -> Optional[str]:
    if not cookies:
        return None
    return cookie_header(cookies, url) or None


# В ответе sqlmapapi записи с type=1 содержат найденные уязвимости.
# Ключи внутри "data" — это sqlmap'овский PAYLOAD.TECHNIQUE id (lib/core/enums.py):
# 1=boolean-based, 2=error-based, 3=inline query, 4=stacked queries, 5=time-based, 6=UNION
_HIGH_CONFIDENCE_TECHNIQUE_IDS = {"3", "4", "6"}  # inline/stacked/UNION — самые однозначные


def _map_to_findings(target: ReconTarget, raw_results: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for item in raw_results:
        if item.get("type") != 1:
            continue

        vulns = item.get("value") or []
        for vuln in vulns:
            parameter = vuln.get("parameter", "unknown")
            dbms = vuln.get("dbms")
            techniques = vuln.get("data") or {}

            for tech_id, tech in techniques.items():
                is_high_conf = tech_id in _HIGH_CONFIDENCE_TECHNIQUE_IDS
                findings.append(Finding(
                    vuln_type=VulnType.SQLI,
                    url=target.url,
                    parameter=parameter,
                    severity=Severity.CRITICAL if is_high_conf else Severity.HIGH,
                    confidence=Confidence.HIGH if is_high_conf else Confidence.MEDIUM,
                    description=f"SQL Injection ({tech.get('title', 'unknown technique')})",
                    evidence=tech.get("payload", ""),
                    remediation="Используйте параметризованные запросы (prepared statements) "
                                "вместо конкатенации пользовательского ввода в SQL.",
                    extra={"dbms": dbms, "technique_id": tech_id, "vector": tech.get("vector")},
                ))
    return findings


async def scan_target(
    target: ReconTarget,
    sqlmap_client: SqlmapClient,
    *,
    is_trusted_target: bool = False,
    max_level: int = 5,
    max_risk: int = 3,
    scan_timeout: float = 600.0,
    diagnostics: list[str] | None = None,
) -> list[Finding]:
    final_url = _build_get_url(target.url, target.params) if target.method == "GET" else target.url.split("#", 1)[0]

    logger.info("SQLi: начинаю скан %s %s", target.method, final_url)

    waf_result = await detect_waf(final_url, cookies=target.cookies, headers=target.headers)
    if waf_result.detected:
        logger.info("SQLi: WAF обнаружен на %s: %s", final_url, waf_result.name)
    profile: ScanProfile = build_profile(
        waf_result,
        max_level=max_level,
        max_risk=max_risk,
        is_trusted_target=is_trusted_target,
    )

    from .options import SQLiOptions
    options = SQLiOptions.load()
    sqlmap_target = SqlmapTarget(
        url=final_url,
        method=target.method,
        data=_serialize_data(target.data),
        cookie=_serialize_cookies(target.cookies, final_url),
        headers=target.headers or {},
        level=profile.level,
        risk=profile.risk,
        tamper=profile.tamper,
        random_agent=profile.random_agent,
        delay=profile.delay,
        techniques=options.techniques,
        time_sec=options.time_sec,
        # Первый проход охватывает все поля, включая кнопки.
    )

    raw_results, timed_out = await sqlmap_client.scan(sqlmap_target, timeout=scan_timeout)
    logger.info("SQLi[%s]: сырой ответ sqlmapapi (%d записей, timed_out=%s): %r",
                final_url, len(raw_results), timed_out, raw_results)

    # Повтор с меньшим набором полей нужен после таймаута.
    initial_timeout = timed_out
    if not raw_results and timed_out:
        narrowed = _pick_test_parameters(target.params, target.data)
        if narrowed:
            logger.warning(
                "SQLi[%s]: первый проход не уложился в таймаут — повторяю суженно "
                "только по вероятным параметрам (%s), чтобы успеть хоть что-то проверить",
                final_url, narrowed,
            )
            sqlmap_target.test_parameter = narrowed
            raw_results, timed_out = await sqlmap_client.scan(sqlmap_target, timeout=scan_timeout)
            logger.info("SQLi[%s]: сырой ответ (суженный повтор, %d записей): %r",
                        final_url, len(raw_results), raw_results)

    if initial_timeout or timed_out:
        parts = urlparse(final_url)
        safe_url = urlunparse((parts.scheme, parts.netloc, parts.path, '', '', ''))
        message = (f"SQLi: {target.method} {safe_url} — превышен лимит {scan_timeout:g} с на проход; "
                   "проверка неполная, отсутствие SQLi не установлено.")
        if timed_out and not raw_results:
            raise TimeoutError(message)
        if diagnostics is not None:
            diagnostics.append(message)
    findings = _map_to_findings(target, raw_results)

    logger.info("SQLi: %s — найдено %d потенциальных инъекций", final_url, len(findings))
    return findings


async def scan_targets(
    targets: list[ReconTarget],
    sqlmap_client: SqlmapClient,
    *,
    concurrency: int = 3,
    **scan_kwargs,
) -> list[Finding]:
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(target: ReconTarget) -> list[Finding]:
        async with semaphore:
            try:
                return await scan_target(target, sqlmap_client, **scan_kwargs)
            except Exception as e:
                logger.error("SQLi: ошибка при скане %s: %s", target.url, e)
                return []

    results = await asyncio.gather(*(_bounded(t) for t in targets))
    return [f for sublist in results for f in sublist]