"""Shared load controls for Python HTTP/browser traffic and engine settings.

External engines use their own throttles; their requests are not counted here.
"""
import asyncio
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import math
import os
import time
from weakref import WeakKeyDictionary


_profile = ContextVar('scan_profile', default='bounty')


def current_profile():
    return _profile.get()


@contextmanager
def use_profile(name):
    if name not in ('fast', 'bounty'):
        raise ValueError('Unknown scan profile')
    token = _profile.set(name)
    try:
        yield
    finally:
        _profile.reset(token)


def request_rate():
    return max(1, math.floor(1 / Limits.load().interval))



class SafetyStop(RuntimeError):
    def __init__(self, message, retryable=False):
        super().__init__(message)
        self.retryable = retryable


def number(name, default, minimum, maximum, kind=float):
    try:
        value = kind(os.environ.get(name, str(default)))
        if not math.isfinite(value) or not minimum <= value <= maximum:
            raise ValueError
        return value
    except (ValueError, OverflowError):
        raise ValueError(f'{name}: expected {minimum}..{maximum}') from None


@dataclass(frozen=True)
class Limits:
    interval: float
    requests: int
    pages: int
    targets: int
    seconds: float
    browser_forms: bool

    @classmethod
    def load(cls):
        forms = os.environ.get('SCAN_BROWSER_FORMS', '1')
        if forms not in ('0', '1'):
            raise ValueError('SCAN_BROWSER_FORMS: expected 0 or 1')
        interval = (number('FAST_REQUEST_INTERVAL', 0.1, 0.1, 60) if current_profile() == 'fast'
                    else number('SCAN_REQUEST_INTERVAL', 1, 1, 60))
        return cls(interval,
                   number('SCAN_MAX_REQUESTS', 0, 0, 10000000, int),
                   number('SCAN_MAX_PAGES', 0, 0, 1000000, int),
                   number('SCAN_MAX_TARGETS', 0, 0, 1000000, int),
                   number('SCAN_TIMEOUT', 0, 0, 31536000), forms == '1')


class TrafficGuard:
    def __init__(self, limits):
        self.limits = limits
        self.lock = asyncio.Lock()
        self.next_request = 0.0
        self.count = 0
        self.reason = ''
        self.retryable = False

    def check(self):
        if self.reason:
            raise SafetyStop(self.reason, self.retryable)

    async def acquire(self):
        async with self.lock:
            self.check()
            if self.limits.requests and self.count >= self.limits.requests:
                self.reason = 'Остановка: исчерпан лимит HTTP/браузерных запросов.'
                self.check()
            await asyncio.sleep(max(0, self.next_request - time.monotonic()))
            self.check()
            self.count += 1
            self.next_request = time.monotonic() + self.limits.interval

    def observe(self, status):
        if status == 429 or status >= 500:
            self.retryable = True
            self.reason = f'Остановка: цель вернула HTTP {status}; проверку нужно продолжить вручную позже.'


_current = ContextVar('scan_traffic_guard', default=None)
_locks = WeakKeyDictionary()


def current_guard():
    return _current.get()


def check_safety():
    guard = current_guard()
    if guard:
        guard.check()


async def engine_pause():
    """Leave a quiet interval when handing traffic to/from an external engine."""
    guard = current_guard()
    if guard:
        guard.check()
        await asyncio.sleep(guard.limits.interval)
        guard.check()


@asynccontextmanager
async def scan_session():
    """Serialize complete scans across callers, including separate Telegram batches."""
    limits = Limits.load()
    loop = asyncio.get_running_loop()
    lock = _locks.setdefault(loop, asyncio.Lock())
    async with lock:
        guard = TrafficGuard(limits)
        token = _current.set(guard)
        try:
            async with asyncio.timeout(limits.seconds or None):
                yield guard
            guard.check()
        finally:
            _current.reset(token)


def http_hooks(extra_request=()):
    async def request_hook(request):
        from target_headers import apply_headers
        await apply_headers(request)
        guard = current_guard()
        if guard:
            await guard.acquire()

    async def response_hook(response):
        guard = current_guard()
        if guard:
            guard.observe(response.status_code)
            if guard.reason:
                await response.aclose()
                guard.check()

    return {'request': [*extra_request, request_hook], 'response': [response_hook]}
