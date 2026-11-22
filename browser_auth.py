"""Bounded browser login for same-origin SPA forms; no guessed storage tokens."""
from scan_safety import http_hooks, current_guard, SafetyStop
import asyncio
import os
import re
import shutil
from urllib.parse import urljoin, urlsplit

import httpx

LOGIN_CUE = re.compile(r'log.?in|sign.?in|войти|вход|account|кабинет', re.I)
EXCLUDE = re.compile(r'logout|sign.?out|register|signup|delete|reset|destroy', re.I)


class BrowserAuthError(RuntimeError):
    pass


def identity_value(data, username):
    """Only explicit identity fields count; arbitrary reflection is insufficient."""
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in ('email', 'username', 'login') and isinstance(value, str) and value.casefold() == username.casefold():
                return True
            if isinstance(value, (dict, list)) and identity_value(value, username):
                return True
    if isinstance(data, list):
        return any(identity_value(x, username) for x in data)
    return False


async def verify_session(url, username, cookies, headers, probes, transport=None):
    """Replay only observed same-origin GETs; compare against a fresh guest jar."""
    from shared_recon import origin
    from SQLi.generic_login import _has_password_field
    async with httpx.AsyncClient(event_hooks=http_hooks(), cookies=cookies, headers=headers, follow_redirects=False, timeout=10, transport=transport) as logged, \
               httpx.AsyncClient(event_hooks=http_hooks(), follow_redirects=False, timeout=10, transport=transport) as guest:
        for probe in list(dict.fromkeys(probes))[:20]:
            path = urlsplit(probe).path
            if origin(probe) != origin(url) or EXCLUDE.search(path) or path.startswith(('/socket.io/', '/assets/')):
                continue
            try:
                a, b = await logged.get(probe), await guest.get(probe)
                if a.status_code != 200 or not a.content or _has_password_field(a.text):
                    continue
                denied = b.status_code in (401, 403) or _has_password_field(b.text)
                identifies = False
                try:
                    identifies = identity_value(a.json(), username) and not identity_value(b.json(), username)
                except ValueError:
                    pass
                if not (denied or identifies):
                    continue
                repeat = await logged.get(probe)
                if repeat.status_code != 200 or _has_password_field(repeat.text):
                    continue
                if identifies and not denied and not identity_value(repeat.json(), username):
                    continue
                return probe
            except (httpx.HTTPError, ValueError):
                continue
    raise BrowserAuthError(f'Не удалось подтвердить перенос браузерной сессии в HTTP-клиент: Authorization={"есть" if headers.get("Authorization") else "нет"}, cookies={len(cookies)}. Наблюдавшиеся API не подтвердили доступ или личность аккаунта. Это не доказательство неверного пароля или MFA.')


def browser_options():
    executable = os.environ.get('BROWSER_EXECUTABLE') or shutil.which('google-chrome') or shutil.which('chromium')
    return {'headless': True, **({'executable_path': executable} if executable else {})}


async def scoped_context(browser, url, state=None, session_storage=None):
    from shared_recon import origin
    import json
    context = await browser.new_context(storage_state=state, service_workers='block')
    context.set_default_timeout(8000)
    traffic = current_guard()
    if traffic:
        context.on('response', lambda response: traffic.observe(response.status))
    async def route(request_route):
        try:
            allowed = origin(request_route.request.url) == origin(url)
        except ValueError:
            allowed = False
        if allowed:
            try:
                if traffic:
                    await traffic.acquire()
            except SafetyStop:
                await request_route.abort()
                return
            from target_headers import headers_for
            custom = headers_for(request_route.request.url)
            if custom:
                # Fetch one hop only: Playwright header overrides otherwise persist
                # across redirects even when routing doesn't see the next hop.
                response = await request_route.fetch(
                    headers={**await request_route.request.all_headers(), **custom}, max_redirects=0)
                await request_route.fulfill(response=response)
            else:
                await request_route.continue_()
        else:
            await request_route.abort()
    await context.route('**/*', route)
    if session_storage:
        expected = f'{urlsplit(url).scheme}://{urlsplit(url).netloc}'
        await context.add_init_script('if (location.origin === ' + json.dumps(expected) + ') { for (const [k,v] of Object.entries(' + json.dumps(session_storage) + ')) sessionStorage.setItem(k,v); }')
    return context


async def wait_render(page):
    try:
        await page.wait_for_load_state('networkidle', timeout=3000)
    except Exception:
        pass


async def browser_step(operation, stage):
    """Expose actionability failure without leaking Playwright's filled-value logs."""
    try:
        return await operation
    except asyncio.CancelledError:
        raise
    except BrowserAuthError:
        raise
    except Exception as exc:
        message = str(exc).lower()
        if 'intercepts pointer events' in message or 'intercept' in message:
            reason = 'элемент перекрыт окном или другим элементом страницы'
        elif 'not enabled' in message or 'not editable' in message or 'disabled' in message:
            reason = 'элемент отключён или недоступен для ввода'
        elif 'not visible' in message:
            reason = 'элемент не виден'
        elif 'timeout' in type(exc).__name__.lower():
            reason = 'истекло время ожидания элемента или ответа страницы'
        else:
            reason = f'ошибка браузера ({type(exc).__name__})'
        raise BrowserAuthError(f'Этап «{stage}»: {reason}.') from None


async def dismiss_intro(page):
    """Close reachable intro overlays first; never force clicks through another UI."""
    close_name = re.compile(r'^(close|dismiss|close welcome banner|закрыть|понятно)(?:\s.*)?$', re.I)
    for _ in range(6):
        candidates = []
        # Cookie banners may sit above modal dialogs and use a link as a button.
        for control in await page.locator('.cc-window .cc-dismiss, [aria-label="dismiss cookie message"]').all():
            if await control.is_visible():
                candidates.append((control, control))
        for dialog in reversed(await page.get_by_role('dialog').all()):
            if not await dialog.is_visible() or await dialog.locator('input[type="password"], input[type="email"], input[type="text"], input:not([type]), textarea').count():
                continue
            buttons = dialog.get_by_role('button', name=close_name)
            if await buttons.count() == 1:
                candidates.append((buttons.first, dialog))
        if not candidates:
            return
        closed = False
        blocked = []
        for button, overlay in candidates:
            try:
                # Trial checks actual hit-testing without clicking; a hidden lower
                # dialog must not prevent us from dismissing the topmost banner.
                await button.click(trial=True, timeout=700)
            except Exception as exc:
                if 'timeout' not in type(exc).__name__.lower():
                    raise BrowserAuthError('Не удалось проверить доступность кнопки закрытия окна.') from None
                try:
                    blocker = await button.evaluate("""el => {
                        const r = el.getBoundingClientRect();
                        const top = document.elementFromPoint(r.x+r.width/2, r.y+r.height/2);
                        return top ? top.tagName.toLowerCase() + (top.getAttribute('role') ? '[role='+top.getAttribute('role')+']' : '') + '.' + Array.from(top.classList).slice(0,3).join('.') : 'outside viewport';
                    }""")
                    blocked.append(str(blocker)[:180])
                except Exception:
                    pass
                continue
            await browser_step(button.click(timeout=2000), 'закрытие приветственного окна')
            await browser_step(overlay.wait_for(state='hidden', timeout=2500), 'ожидание закрытия окна')
            closed = True
            break
        if not closed:
            detail = '; '.join(dict.fromkeys(blocked)) or 'не удалось определить'
            raise BrowserAuthError('Кнопки закрытия перекрыты или недоступны. Элемент сверху: ' + detail + '. Автовход остановлен до ввода пароля.')
    raise BrowserAuthError('Окна продолжают появляться после закрытия; автопоиск входа остановлен.')


async def login_controls(page):
    # ARIA menus override the implicit role of their <button> elements.
    return (await page.get_by_role('menuitem', name=LOGIN_CUE).all()
            + await page.get_by_role('button', name=LOGIN_CUE).all())


async def find_login(page, url):
    from shared_recon import origin
    candidates = [os.environ.get('AUTH_LOGIN_URL') or url]
    visited = set()
    buttons_clicked = set()
    for _ in range(12):
        if candidates:
            candidate = candidates.pop(0)
            if candidate in visited or origin(candidate) != origin(url):
                continue
            visited.add(candidate)
            await browser_step(page.goto(candidate, wait_until='domcontentloaded'), 'открытие страницы для поиска входа')
            await wait_render(page)
        await dismiss_intro(page)
        password = page.locator('input[type="password"]:visible')
        if await password.count() == 1 and await password.first.get_attribute('autocomplete') != 'new-password':
            return password.first
        # Real links include hash routes; keep fragments intact.
        for anchor in await page.locator('a[href]:visible').all():
            href = await anchor.get_attribute('href')
            target = urljoin(page.url, href or '')
            cue = (await anchor.inner_text()) + ' ' + (href or '')
            try:
                if LOGIN_CUE.search(cue) and not EXCLUDE.search(cue) and origin(target) == origin(url) and target not in visited:
                    candidates.append(target)
            except ValueError:
                continue
        if candidates:
            continue
        clicked = False
        for control in await login_controls(page):
            name = (await control.get_attribute('aria-label') or '') + ' ' + (await control.inner_text() or '')
            if name not in buttons_clicked and not EXCLUDE.search(name) and await control.is_visible():
                buttons_clicked.add(name)
                await dismiss_intro(page)
                await browser_step(control.click(), 'переход через меню входа')
                await wait_render(page)
                clicked = True
                break
        if not clicked:
            break
    raise BrowserAuthError(f'Не удалось найти форму входа: просмотрено страниц {len(visited)}, нажато элементов меню {len(buttons_clicked)}. Это ошибка автоматического поиска, а не признак MFA. Можно передать URL страницы входа напрямую.')


def carries_credentials(request, username, password):
    """Recognize the form's actual auth request without logging its body."""
    import json
    from urllib.parse import parse_qsl
    if request.method not in ('POST', 'PUT'):
        return False
    body = request.post_data or ''
    try:
        data = json.loads(body)
        def values(value):
            if isinstance(value, dict):
                return [v for item in value.values() for v in values(item)]
            if isinstance(value, list):
                return [v for item in value for v in values(item)]
            return [value] if isinstance(value, str) else []
        fields = values(data)
    except ValueError:
        fields = [value for _, value in parse_qsl(body, keep_blank_values=True)]
    return username in fields and password in fields


async def submit_and_wait(context, page, submit, username, password, url):
    from shared_recon import origin
    result = asyncio.get_running_loop().create_future()
    tasks = set()
    async def inspect(response):
        try:
            if origin(response.url) != origin(url) or not carries_credentials(response.request, username, password):
                return
            await response.finished()
            if not result.done():
                result.set_result(response.status)
        except Exception:
            if not result.done():
                result.set_exception(BrowserAuthError('Ответ на запрос входа не удалось прочитать.'))
    def capture(response):
        task = asyncio.create_task(inspect(response))
        tasks.add(task)
        task.add_done_callback(tasks.discard)
    context.on('response', capture)
    try:
        await browser_step(submit.click(), 'нажатие кнопки входа')
        try:
            status = await asyncio.wait_for(result, timeout=20)
        except TimeoutError:
            raise BrowserAuthError('После клика не получен ответ на запрос с учётными данными. Возможно, форма не отправлена или приложение использует другой формат входа.') from None
        if status in (401, 403):
            raise BrowserAuthError(f'Сервер отклонил запрос входа: HTTP {status}. Проверьте данные аккаунта; сессия ещё не создана.')
        if status >= 400:
            raise BrowserAuthError(f'Запрос входа завершился ошибкой HTTP {status}.')
        await browser_step(page.locator('input[type="password"]:visible').wait_for(state='hidden', timeout=15000),
                           'завершение входа после ответа сервера (форма должна исчезнуть)')
    finally:
        context.remove_listener('response', capture)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def browser_login(url, label, username, password):
    try:
        return await _browser_login(url, label, username, password)
    except BrowserAuthError:
        raise
    except TimeoutError:
        raise BrowserAuthError('Истёк таймаут браузерного входа; сессия не подтверждена.') from None
    except Exception as exc:
        # Browser exceptions can contain filled values in call logs.
        raise BrowserAuthError(f'Браузерный вход не завершён ({type(exc).__name__}). Не удалось определить этап ошибки; вход не подтверждён.') from None


async def _browser_login(url, label, username, password):
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise BrowserAuthError('Для SPA-входа установите зависимости requirements-browser.txt и Chromium (python -m playwright install chromium).') from None
    from shared_recon import Session, origin
    async with asyncio.timeout(float(os.environ.get('BROWSER_AUTH_TIMEOUT', '90'))):
        async with async_playwright() as playwright:
            browser = await browser_step(playwright.chromium.launch(**browser_options()), 'запуск Chromium')
            try:
                context = await scoped_context(browser, url)
                page = await context.new_page()
                page.set_default_navigation_timeout(15000)
                password_input = await find_login(page, url)
                if EXCLUDE.search(page.url):
                    raise BrowserAuthError('Страница похожа на регистрацию или восстановление пароля; вход не отправлен.')
                # Prefer the password's form, but SPA controls need not use <form>.
                form = password_input.locator('xpath=ancestor::form[1]')
                container = form if await form.count() else page
                user_input = container.locator('input[autocomplete="username"]:visible, input[type="email"]:visible')
                if await user_input.count() == 0:
                    user_input = container.locator('input[type="text"]:visible, input:not([type]):visible')
                if await user_input.count() != 1:
                    raise BrowserAuthError('Не удалось однозначно выбрать поле пользователя в SPA.')
                await dismiss_intro(page)
                await browser_step(user_input.fill(username), 'заполнение поля пользователя')
                await browser_step(password_input.fill(password), 'заполнение поля пароля')
                submit = container.get_by_role('button', name=re.compile(r'^(log.?in|sign.?in|войти|вход)$', re.I))
                if await submit.count() != 1:
                    submit = container.locator('button[type="submit"]:visible, input[type="submit"]:visible')
                if await submit.count() != 1:
                    raise BrowserAuthError('Не удалось однозначно выбрать кнопку входа в SPA.')
                observed = []
                async def capture(response):
                    request = response.request
                    if request.method == 'GET' and request.resource_type in ('xhr', 'fetch') and 200 <= response.status < 300:
                        if origin(request.url) == origin(url):
                            headers = await request.all_headers()
                            observed.append((request.url, headers.get('authorization')))
                context.on('response', capture)
                await submit_and_wait(context, page, submit, username, password, url)
                await wait_render(page)
                # Reload verifies that the SPA actually persisted its session.
                await browser_step(page.reload(wait_until='domcontentloaded'), 'проверка сессии после перезагрузки')
                await wait_render(page)
                tokens = {auth for _, auth in observed if auth}
                if len(tokens) > 1:
                    raise BrowserAuthError('Наблюдалось несколько Authorization-токенов; нельзя выбрать общую сессию автоматически.')
                headers = {'Authorization': next(iter(tokens))} if tokens else {}
                cookies_list = await context.cookies([url])
                cookies = {item['name']: item['value'] for item in cookies_list}
                if len(cookies) != len(cookies_list):
                    raise BrowserAuthError('Одноимённые cookies с разными путями требуют отдельного адаптера сессии.')
                if not headers and not cookies:
                    raise BrowserAuthError('SPA не предоставила переносимую HTTP-сессию.')
                probe = await verify_session(url, username, cookies, headers, [u for u,_ in observed])
                state = await context.storage_state()
                storage = await page.evaluate('Object.fromEntries(Object.entries(sessionStorage))')
                return Session(label, cookies, headers, True, 'browser + anonymous API comparison',
                               browser_state=state, session_storage=storage, browser_urls=list(dict.fromkeys([url, page.url] + [u for u,_ in observed])),
                               auth_check_url=probe, username=username)
            finally:
                await browser.close()


async def browser_discover(url, session, max_pages=30):
    """Use captured browser state instead of reducing localStorage to cookies."""
    from playwright.async_api import async_playwright
    from shared_recon import origin
    found = set(session.browser_urls)
    async with asyncio.timeout(float(os.environ.get('RECON_TIMEOUT', '300'))):
        async with async_playwright() as playwright:
            browser = await browser_step(playwright.chromium.launch(**browser_options()), 'запуск Chromium')
            try:
                context = await scoped_context(browser, url, session.browser_state, session.session_storage)
                page = await context.new_page()
                async def capture(request):
                    try:
                        if request.method == 'GET' and origin(request.url) == origin(url) and request.resource_type in ('document', 'xhr', 'fetch'):
                            found.add(request.url)
                    except ValueError:
                        pass
                context.on('request', capture)
                queue, visited = [url], set()
                while queue and len(visited) < max_pages:
                    target = queue.pop(0)
                    if target in visited or origin(target) != origin(url) or EXCLUDE.search(target):
                        continue
                    visited.add(target)
                    await page.goto(target, wait_until='domcontentloaded')
                    await wait_render(page)
                    found.add(page.url)
                    for href in await page.locator('a[href]').evaluate_all('(nodes) => nodes.map(x => x.href)'):
                        try:
                            if origin(href) == origin(url) and not EXCLUDE.search(href) and href not in visited:
                                queue.append(href)
                        except ValueError:
                            continue
                # Tokens may expire/rotate during navigation. Do not silently report
                # an authenticated crawl using a stale exported HTTP token.
                await verify_session(url, session.username, session.cookies, session.headers, [session.auth_check_url])
                return sorted(found)
            finally:
                await browser.close()
