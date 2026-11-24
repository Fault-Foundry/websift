import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import bot


class BotCredentialTests(unittest.IsolatedAsyncioTestCase):
    async def submit(self, text, second_password="saved-pass"):
        message = SimpleNamespace(text=text, reply=AsyncMock())
        state = AsyncMock()
        with patch.multiple(bot, DEFAULT_USER_A="saved-a", DEFAULT_PASS_A="saved-pass",
                            DEFAULT_USER_B="saved-b", DEFAULT_PASS_B=second_password), \
                patch.object(bot, "enqueue_scan", new_callable=AsyncMock) as enqueue:
            await bot.handle_creds_input(message, state, None)
        return message, state, enqueue

    async def test_account_selection(self):
        for text, expected in [
            ("-", ["", "", "", ""]),
            ("defaults", ["saved-a", "saved-pass", "saved-b", "saved-pass"]),
            ("alice:x:y", ["alice", "x:y", "", ""]),
            ("alice:x bob:y", ["alice", "x", "bob", "y"]),
        ]:
            with self.subTest(text=text):
                message, state, enqueue = await self.submit(text)
                enqueue.assert_awaited_once_with(message, state.get_data.return_value, expected)
                state.clear.assert_awaited_once()

    async def test_invalid_input_keeps_prompt_and_never_enqueues(self):
        for text in ("", "typo", "alice:", ":pass", "alice:x typo", "a:x b:y c:z", "defaults"):
            with self.subTest(text=text):
                message, state, enqueue = await self.submit(text, second_password="")
                enqueue.assert_not_awaited()
                state.clear.assert_not_awaited()
                message.reply.assert_awaited_once()
