import asyncio
import secrets
from urllib.parse import urlsplit
from browser_auth import browser_options, scoped_context, wait_render
from shared_recon import origin

FIELDS = 'textarea, input:not([type]), input[type=text], input[type=search]'
SUBMIT = 'button[type=submit], input[type=submit], button:not([type])'


async def check_forms(url, session, single=False):
    result = {'status': 'completed', 'tested': 0, 'findings': [], 'pages': [], 'attempts': [], 'errors': []}
    try:
        from playwright.async_api import async_playwright
        async with asyncio.timeout(120):
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(**browser_options())
                try:
                    async def new_page():
                        context = await scoped_context(browser, url, session.browser_state, session.session_storage)
                        if session.headers:
                            await context.set_extra_http_headers(session.headers)
                        if session.cookies:
                            from cookie_session import copy_cookies
                            jar = copy_cookies(session.cookies)
                            cookies = []
                            for c in jar.jar:
                                cookies.append({'name': c.name, 'value': c.value, **({'domain': c.domain, 'path': c.path or '/', 'secure': c.secure} if c.domain else {'url': url})})
                            await context.add_cookies(cookies)
                        page = await context.new_page()
                        return context, page

                    context, page = await new_page()
                    probes = []
                    try:
                        await page.goto(url, wait_until='domcontentloaded')
                        await wait_render(page)
                        body = await page.locator('body').inner_text()
                        if "haven't passed the previous level" in body.lower():
                            result['pages'].append(page.url)
                            result['blocked_reason'] = 'Сайт требует cookie прохождения предыдущего уровня. В этой сессии открылась заглушка, а не игра; поля ввода не проверены.'
                            result['errors'].append(result['blocked_reason'])
                            result['status'] = 'incomplete'
                            return result
                        for frame in page.frames:
                            try:
                                if origin(frame.url) != origin(url):
                                    continue
                                if single and urlsplit(frame.url).path != urlsplit(url).path:
                                    continue
                            except ValueError:
                                continue
                            result['pages'].append(frame.url)
                            forms = frame.locator('form')
                            for fi in range(min(await forms.count(), 8)):
                                form = forms.nth(fi)
                                if await form.locator('input[type=password]').count():
                                    continue
                                if not await form.locator(SUBMIT).count():
                                    continue
                                fields = form.locator(FIELDS)
                                for ii in range(min(await fields.count(), 4)):
                                    field = fields.nth(ii)
                                    if await field.is_visible() and await field.is_editable():
                                        probes.append((frame.url, fi, ii, await field.get_attribute('name') or await field.get_attribute('id') or f'field[{ii}]'))
                    finally:
                        await context.close()
                    confirmed_fields = set()
                    for (frame_url, fi, ii, name), variant in [(probe, variant) for probe in probes[:12] for variant in ('svg', 'img')]:
                        field_key = (frame_url, fi, ii)
                        if field_key in confirmed_fields:
                            continue
                        context, page = await new_page()
                        marker = 'xss_probe_' + secrets.token_hex(10)
                        callback_name = 'probe_' + secrets.token_hex(10)
                        payload = f'<svg onload="window[\'{callback_name}\']?.(\'{marker}\');alert(\'{marker}\')">'
                        if variant == 'img':
                            payload = f'<img src="data:image/png;base64,AA==" onerror="window[\'{callback_name}\']?.(\'{marker}\');alert(\'{marker}\')">'
                        hits = []
                        executed = asyncio.Event()
                        async def execution(source, value):
                            if value == marker and origin(source['frame'].url) == origin(url):
                                hits.append('callback')
                                executed.set()
                        await context.expose_binding(callback_name, execution)
                        async def dialog(d):
                            if d.type == 'alert' and d.message == marker:
                                hits.append('dialog')
                                executed.set()
                            await d.dismiss()
                        page.on('dialog', dialog)
                        try:
                            await page.goto(url, wait_until='domcontentloaded')
                            await wait_render(page)
                            frame = next((f for f in page.frames if f.url == frame_url), None)
                            if frame is None:
                                raise RuntimeError('frame disappeared')
                            form = frame.locator('form').nth(fi)
                            await form.locator(FIELDS).nth(ii).fill(payload)
                            result['attempts'].append({'url': frame_url, 'form': fi, 'field': name, 'payload': payload, 'filled': await form.locator(FIELDS).nth(ii).input_value() == payload})
                            await form.locator(SUBMIT).first.click(timeout=5000)
                            result['tested'] += 1
                            try:
                                await asyncio.wait_for(executed.wait(), timeout=5)
                            except asyncio.TimeoutError:
                                pass
                            if hits:
                                confirmed_fields.add(field_key)
                                result['findings'].append({'url': frame_url, 'form': fi, 'param': name,
                                                           'payload': payload, 'evidence': 'Вызов контрольной функции или alert с уникальным маркером из отправленного ввода; JavaScript выполнен браузером'})
                        except Exception as exc:
                            result['errors'].append(f'Браузерная проверка формы: {type(exc).__name__}')
                        finally:
                            await context.close()
                finally:
                    await browser.close()
    except Exception as exc:
        result['errors'].append(f'Браузерная проверка XSS недоступна или прервана: {type(exc).__name__}. Проверьте Playwright и Chromium.')
    if result['errors']:
        result['status'] = 'incomplete'
    elif not result['tested']:
        result['status'] = 'skipped'
    return result
