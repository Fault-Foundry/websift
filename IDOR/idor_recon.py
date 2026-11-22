import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


def is_id(value):
    return bool(re.fullmatch(r'\d+|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', value))


def observations(urls):
    result = {}
    for url in urls:
        parsed = urlsplit(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        parts = parsed.path.split('/')
        for i, part in enumerate(parts):
            if is_id(part):
                template = parts.copy()
                template[i] = '{id}'
                key = (parsed.scheme, parsed.netloc, '/'.join(template), tuple(query), f'path:{i}')
                result.setdefault(key, set()).add(url)
        for i, (name, value) in enumerate(query):
            if is_id(value):
                template = query.copy()
                template[i] = (name, '{id}')
                key = (parsed.scheme, parsed.netloc, parsed.path, tuple(template), f'query:{name}:{i}')
                result.setdefault(key, set()).add(url)
    return result
