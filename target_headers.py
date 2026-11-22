import json
import re
from contextlib import contextmanager
from contextvars import ContextVar

_current = ContextVar('target_headers', default=None)
# Authentication belongs to individual scanner sessions, not the whole target.
_RESERVED = {'host', 'cookie', 'authorization', 'proxy-authorization', 'connection',
             'content-length', 'transfer-encoding', 'upgrade', 'te', 'trailer'}


def validate_headers(headers):
    if not isinstance(headers, dict) or len(headers) > 32:
        raise ValueError('Заголовки должны быть JSON-объектом (до 32 полей).')
    result = {}
    for name, value in headers.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or name.lower() in _RESERVED or name.lower() in result
                or not isinstance(value, str) or len(value) > 4096
                or any(ord(c) < 32 or ord(c) > 126 for c in value)):
            raise ValueError('Недопустимый HTTP-заголовок; используйте уникальные имена и печатные ASCII-значения. Авторизация задаётся отдельно.')
        result[name.lower()] = value
    return result


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key.lower() in result:
            raise ValueError('Повторяющийся заголовок.')
        result[key.lower()] = value
    return result


def parse_target(line):
    from shared_recon import origin
    # The NUL suffix is the existing internal representation for --data-file.
    head, sep, body = line.partition('\0')
    url, tab, raw = head.strip().partition('\t')
    try:
        headers = validate_headers(json.loads(raw, object_pairs_hook=_unique_pairs)) if tab else {}
        origin(url)
    except (ValueError, TypeError):
        raise ValueError('Ожидается URL или URL<TAB>{"Header":"value"}; некорректная цель/заголовки.') from None
    return url + (sep + body if sep else ''), headers


def parse_lines(content):
    lines = []
    for number, line in enumerate(content.lstrip('\ufeff').splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        try:
            if '\0' in line:
                raise ValueError('NUL in target file')
            parse_target(line)
        except ValueError:
            raise ValueError(f'Строка {number}: неверный URL или JSON заголовков.') from None
        lines.append(line.strip())
    return lines


@contextmanager
def use_target_headers(url, headers):
    from shared_recon import origin
    token = _current.set((origin(url.split('\0', 1)[0]), validate_headers(headers)))
    try:
        yield
    finally:
        _current.reset(token)


def headers_for(url):
    from shared_recon import origin
    current = _current.get()
    return dict(current[1]) if current and origin(str(url)) == current[0] else {}


async def apply_headers(request):
    from shared_recon import origin
    current = _current.get()
    if current and current[1]:
        if origin(str(request.url)) != current[0]:
            raise ValueError('Request leaves target header origin')
        request.headers.update(current[1])
