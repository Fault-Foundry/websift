"""Cookie-jar utilities: preserve domain/path and duplicate cookie names."""
import httpx


def copy_cookies(cookies):
    return httpx.Cookies(cookies)


def cookie_header(cookies, url):
    request = httpx.Request('GET', url)
    copy_cookies(cookies).set_cookie_header(request)
    return request.headers.get('cookie', '')


def cookie_key(cookies):
    return tuple(sorted((c.domain, c.path, c.name, c.value, c.secure, c.expires or 0)
                        for c in copy_cookies(cookies).jar))
