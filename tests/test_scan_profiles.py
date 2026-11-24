import asyncio
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from scan_safety import Limits, use_profile, current_profile, request_rate
from SQLi.options import SQLiOptions
from durable_queue import QueueStore


class ProfileTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        env = patch.dict(os.environ, {}, clear=True)
        env.start()
        self.addCleanup(env.stop)

    async def test_profiles_are_task_local_and_keep_detection_options(self):
        async def inspect(name):
            with use_profile(name):
                await asyncio.sleep(0)
                return Limits.load().interval, request_rate(), SQLiOptions.load()
        fast, bounty = await asyncio.gather(inspect('fast'), inspect('bounty'))
        self.assertEqual(fast[:2], (0.1, 10))
        self.assertEqual(bounty[:2], (1, 1))
        self.assertEqual(fast[2], bounty[2])
        self.assertEqual(current_profile(), 'bounty')

    async def test_queued_profile_reaches_scanner(self):
        from websift_tg_bot import scan_queued_job
        seen = []
        async def pipeline(*args, **kwargs):
            seen.append(Limits.load().interval)
            return {}
        with patch('scan_pipeline.run_pipeline', pipeline):
            for profile in ('fast', 'bounty'):
                await scan_queued_job({'mode': 'xss', 'url': 'https://lab.test/',
                                       'credentials': '["", "", "", ""]', 'profile': profile})
        self.assertEqual(seen, [0.1, 1])

    async def test_profile_selection_precedes_credentials(self):
        from websift_tg_bot import save_urls_and_ask_creds, choose_profile, ScanStates
        state, message = AsyncMock(), AsyncMock()
        await save_urls_and_ask_creds(message, state, 'all', ['https://lab.test/'])
        state.set_state.assert_awaited_with(ScanStates.waiting_for_profile)
        message.text = 'fast'
        await choose_profile(message, state)
        state.update_data.assert_awaited_with(profile='fast')
        state.set_state.assert_awaited_with(ScanStates.waiting_for_creds)
        message.text = 'unknown'
        state.reset_mock()
        await choose_profile(message, state)
        state.set_state.assert_not_awaited()

    def test_profile_survives_restart_and_legacy_schema_migrates(self):
        with tempfile.TemporaryDirectory() as directory:
            store = QueueStore(directory)
            # Reproduce a database produced by the previous version.
            store.db.execute('ALTER TABLE jobs DROP COLUMN profile')
            store.db.commit()
            store.close()
            store = QueueStore(directory)
            store.enqueue(1, 1, ['https://lab.test/'], 'xss', ['', '', '', ''], profile='fast')
            store.close()
            store = QueueStore(directory)
            try:
                self.assertEqual(store.claim()['profile'], 'fast')
                with self.assertRaises(ValueError):
                    store.enqueue(1, 1, ['https://lab.test/'], 'xss', [], profile='typo')
            finally:
                store.close()

    def test_bounty_interval_cannot_be_lowered_by_fast_setting(self):
        with patch.dict(os.environ, {'FAST_REQUEST_INTERVAL': '0.2', 'SCAN_REQUEST_INTERVAL': '3'}):
            with use_profile('fast'):
                self.assertEqual(Limits.load().interval, 0.2)
            self.assertEqual(Limits.load().interval, 3)
        with patch.dict(os.environ, {'FAST_REQUEST_INTERVAL': '0'}), use_profile('fast'):
            with self.assertRaises(ValueError):
                Limits.load()
