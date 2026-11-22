import unittest
from unittest.mock import AsyncMock
from aiogram import Bot, Dispatcher, Router
from aiogram.types import Update
from bot import AccessMiddleware, parse_allowed_users


class AccessTests(unittest.IsolatedAsyncioTestCase):
    def test_config(self):
        self.assertEqual(parse_allowed_users('123, 456,123'), {123, 456})
        for value in ('', '123,', '-1', '0', '@friend', '123,no', '１２３'):
            with self.assertRaises(ValueError):
                parse_allowed_users(value)

    async def test_updates_are_gated_before_handlers(self):
        dp = Dispatcher()
        dp.update.outer_middleware(AccessMiddleware({123, 456}))
        router = Router()
        handled = []
        async def record(event):
            handled.append(event)
        router.message.register(record)
        router.callback_query.register(record)
        dp.include_router(router)
        bot = Bot('123456:TEST_TOKEN')
        bot.session = AsyncMock()
        try:
            for user_id, kind, chat_type, expected in (
                (123, 'message', 'private', True),
                (456, 'message', 'private', True),
                (789, 'message', 'private', False),
                (123, 'message', 'group', True),
                (456, 'message', 'supergroup', True),
                (789, 'message', 'group', False),
                (789, 'message', 'supergroup', False),
                (123, 'callback_query', 'private', True),
                (789, 'callback_query', 'private', False),
                (123, 'callback_query', 'group', True),
                (789, 'callback_query', 'group', False),
                (123, 'message', 'channel', False),
                (123, 'edited_message', 'private', False)):
                user = {'id': user_id, 'is_bot': False, 'first_name': 'Test'}
                message = {'message_id': 1, 'date': 0, 'chat': {'id': user_id, 'type': chat_type},
                           'from': user, 'text': '/sqli https://lab.test'}
                payload = message if kind != 'callback_query' else {
                    'id': 'query', 'from': user, 'chat_instance': 'test', 'message': message, 'data': 'scan'}
                before = len(handled)
                await dp.feed_update(bot, Update.model_validate({'update_id': 1, kind: payload}))
                self.assertEqual(len(handled) - before, int(expected), (user_id, kind, chat_type))
        finally:
            await dp.storage.close()
            await bot.session.close()
