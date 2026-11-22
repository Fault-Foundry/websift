import unittest
from unittest.mock import AsyncMock, patch
from browser_auth import find_login, dismiss_intro


class Items:
    def __init__(self, values=()):
        self.values = list(values)
    async def all(self): return self.values
    async def count(self): return len(self.values)
    @property
    def first(self): return self.values[0]


class Control:
    def __init__(self, page, name, next_state):
        self.page, self.name, self.next_state = page, name, next_state
    async def inner_text(self): return self.name
    async def get_attribute(self, name): return self.name if name == 'aria-label' else None
    async def is_visible(self): return True
    async def click(self): self.page.stage = self.next_state


class MenuPage:
    def __init__(self):
        self.stage = 'home'
        self.url = 'https://lab.test/'
    async def goto(self, url, **kw): self.url = url
    async def wait_for_load_state(self, *args, **kw): pass
    def locator(self, selector):
        if selector.startswith('input') and self.stage == 'login':
            return Items([Control(self,'password','login')])
        return Items()
    def get_by_role(self, role, **kw):
        if role == 'button' and self.stage == 'home':
            return Items([Control(self,'Show/hide account menu','menu')])
        if role == 'menuitem' and self.stage == 'menu':
            return Items([Control(self,'Go to login page','login')])
        return Items()


class LoginNavigationTests(unittest.IsolatedAsyncioTestCase):
    async def test_account_menuitem_reaches_login(self):
        page = MenuPage()
        with patch.dict('os.environ', {}, clear=True):
            password = await find_login(page, page.url)
        self.assertEqual(page.stage, 'login')
        self.assertEqual(password.name, 'password')

    async def test_dismiss_intro_does_not_submit_form(self):
        page = AsyncMock()
        dialog = AsyncMock()
        dialog.is_visible.return_value = True
        dialog.locator = lambda selector: Items([object()])
        page.get_by_role = lambda *a, **kw: Items([dialog])
        page.locator = lambda selector: Items()
        await dismiss_intro(page)
        dialog.get_by_role.assert_not_called()

    async def test_welcome_checkbox_does_not_block_dismiss(self):
        page = AsyncMock()
        dialog = AsyncMock()
        button = AsyncMock()
        dialog.is_visible.return_value = True
        def locator(selector):
            return Items([object()]) if selector == 'input' else Items()
        dialog.locator = locator
        dialog.get_by_role = lambda *a, **kw: Items([button])
        page.get_by_role = lambda *a, **kw: Items([dialog])
        page.locator = lambda selector: Items()
        async def hidden(**kwargs):
            dialog.is_visible.return_value = False
        dialog.wait_for.side_effect = hidden
        await dismiss_intro(page)
        self.assertEqual(button.click.await_count, 2)
        dialog.wait_for.assert_awaited_once_with(state='hidden', timeout=2500)

    async def test_action_error_reports_stage_without_secrets(self):
        from browser_auth import browser_step, BrowserAuthError
        async def failed():
            raise TimeoutError('fill("very-secret-password"): overlay intercepts pointer events')
        with self.assertRaises(BrowserAuthError) as result:
            await browser_step(failed(), 'заполнение поля пароля')
        self.assertIn('заполнение поля пароля', str(result.exception))
        self.assertIn('перекрыт', str(result.exception))
        self.assertNotIn('very-secret-password', str(result.exception))

    async def test_top_cookie_banner_closed_before_welcome(self):
        page = AsyncMock()
        banner, welcome, close = AsyncMock(), AsyncMock(), AsyncMock()
        banner.is_visible.return_value = True
        welcome.is_visible.return_value = True
        welcome.locator = lambda _: Items()
        welcome.get_by_role = lambda *a, **kw: Items([close])
        page.locator = lambda _: Items([banner])
        page.get_by_role = lambda *a, **kw: Items([welcome])
        order = []
        async def banner_click(**kw):
            if not kw.get('trial'): order.append('cookie')
        async def close_click(**kw):
            if banner.is_visible.return_value:
                raise TimeoutError('cookie banner intercepts pointer events')
            if not kw.get('trial'): order.append('welcome')
        async def hide_banner(**kw): banner.is_visible.return_value = False
        async def hide_welcome(**kw): welcome.is_visible.return_value = False
        banner.click.side_effect = banner_click
        close.click.side_effect = close_click
        banner.wait_for.side_effect = hide_banner
        welcome.wait_for.side_effect = hide_welcome
        await dismiss_intro(page)
        self.assertEqual(order, ['cookie', 'welcome'])

    async def test_unknown_overlay_is_reported_without_force_click(self):
        from browser_auth import BrowserAuthError
        page, dialog, button = AsyncMock(), AsyncMock(), AsyncMock()
        page.locator = lambda _: Items()
        page.get_by_role = lambda *a, **kw: Items([dialog])
        dialog.is_visible.return_value = True
        dialog.locator = lambda _: Items()
        dialog.get_by_role = lambda *a, **kw: Items([button])
        button.click.side_effect = TimeoutError('intercepts pointer events')
        button.evaluate.return_value = 'div.overlay'
        with self.assertRaisesRegex(BrowserAuthError, 'div.overlay'):
            await dismiss_intro(page)
        button.click.assert_awaited_once_with(trial=True, timeout=700)
