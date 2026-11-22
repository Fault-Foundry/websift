import asyncio
import json
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

from durable_queue import QueueStore
from site_watch import canonical, fingerprint, katana_snapshot


class WatchStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.queue = QueueStore(self.tmp.name)
        self.watches = self.queue.watches
        self.watches.add(7, 7, ['https://example.test', 'https://example.test/'])

    def tearDown(self):
        self.queue.close()
        self.tmp.cleanup()

    def finish_watch(self, snapshot):
        self.watches.schedule({7})
        job = self.queue.claim()
        self.assertEqual(job['mode'], 'watch')
        report = {'watch': {'status': 'completed', 'snapshot': snapshot, 'errors': []}}
        self.queue.complete(job, report, [])
        child = self.queue.claim()
        self.assertEqual(child['profile'], 'bounty')
        self.queue.complete(child, {'scan': {'status': 'completed'}}, [])
        self.queue.db.execute('UPDATE watches SET next_due=0')
        self.queue.db.commit()
        return child, report

    def test_first_unchanged_changed_and_weekly(self):
        self.assertEqual(len(self.watches.rows(7, 7)), 1)
        child, report = self.finish_watch({'GET https://example.test/': 'one'})
        self.assertEqual(child['mode'], 'all')
        self.assertNotIn('snapshot', report['watch'])
        child, _ = self.finish_watch({'GET https://example.test/': 'one'})
        self.assertEqual(child['mode'], 'exposure')
        child, _ = self.finish_watch({'GET https://example.test/': 'two'})
        self.assertEqual(child['mode'], 'all')
        self.queue.db.execute('UPDATE watches SET last_full=?', (time.time() - 8 * 86400,))
        self.queue.db.commit()
        child, _ = self.finish_watch({'GET https://example.test/': 'two'})
        self.assertEqual(child['mode'], 'all')

    def test_failed_snapshot_preserved_and_no_duplicate(self):
        self.finish_watch({'old': 'hash'})
        self.watches.schedule({7})
        self.watches.schedule({7})
        self.assertEqual(self.queue.db.execute("SELECT count(*) FROM jobs WHERE status='queued'").fetchone()[0], 1)
        job = self.queue.claim()
        self.queue.complete(job, {'watch': {'status': 'incomplete', 'errors': ['timeout']}}, [])
        row = self.watches.rows(7, 7)[0]
        self.assertEqual(json.loads(row['snapshot']), {'old': 'hash'})
        self.assertEqual(row['last_error'], 'timeout')
        self.assertGreater(row['next_due'], time.time())

    def test_permissions_pause_resume_and_restart(self):
        ident = self.watches.rows(7, 7)[0]['id']
        self.assertEqual(self.watches.control(ident, 8, 7, 'remove'), 0)
        self.watches.schedule({8})
        self.assertIsNone(self.queue.claim())
        self.watches.schedule({7})
        job = self.queue.claim()
        self.watches.control(ident, 7, 7, 'pause')
        self.queue.complete(job, {'watch': {'status': 'completed', 'snapshot': {'new': 'hash'}}}, [])
        self.assertIsNone(self.queue.claim())
        self.assertIsNone(self.watches.rows(7, 7)[0]['snapshot'])
        self.watches.control(ident, 7, 7, 'resume')
        self.queue.close()
        self.queue = QueueStore(self.tmp.name)
        self.watches = self.queue.watches
        self.watches.schedule({7})
        self.assertEqual(self.queue.claim()['mode'], 'watch')

    def test_reject_headers_query_credentials(self):
        for url in ['https://user:pass@example.test', 'https://example.test/?token=secret',
                    'https://example.test/\t{"User-Agent":"test"}']:
            with self.assertRaises(ValueError):
                self.watches.add(7, 7, [url])

    def test_bounty_all_saves_and_bootstraps_without_duplicate_scan(self):
        batch, _ = self.queue.enqueue(8, 8, ['https://new.test/app?token=secret'], 'all', ['', '', '', ''], 'bounty')
        row = self.watches.rows(8, 8)[0]
        self.assertEqual(row['url'], 'https://new.test/app')
        self.assertNotIn('secret', row['url'])
        self.watches.schedule({8})
        initial = self.queue.claim(batch)
        self.assertEqual(initial['watch_id'], row['id'])
        self.assertEqual(self.queue.db.execute("SELECT count(*) FROM jobs WHERE mode='watch'").fetchone()[0], 0)
        self.queue.complete(initial, {'sqli': {'status': 'completed'}}, [])
        self.watches.schedule({8})
        job = self.queue.claim()
        self.assertEqual(job['mode'], 'watch')
        self.queue.complete(job, {'watch': {'status': 'completed', 'snapshot': {'page': 'hash'}}}, [])
        self.assertIsNone(self.queue.claim())
        row = self.watches.rows(8, 8)[0]
        self.assertEqual(json.loads(row['snapshot']), {'page': 'hash'})

    def test_fast_and_other_modes_are_once(self):
        self.queue.enqueue(8, 8, ['https://new.test/'], 'all', ['', '', '', ''], 'fast')
        self.queue.enqueue(8, 8, ['https://new.test/'], 'sqli', ['', '', '', ''], 'bounty')
        self.assertEqual(self.watches.rows(8, 8), [])

    def test_bounty_headers_preserved_and_repeated_targets_deduplicated(self):
        line = 'https://new.test/\t{"X-Researcher":"test"}'
        batch, _ = self.queue.enqueue(8, 8, [line], 'all', ['', '', '', ''], 'bounty')
        row = self.watches.rows(8, 8)[0]
        self.assertEqual(json.loads(row['headers']), {'x-researcher': 'test'})
        self.watches.control(row['id'], 8, 8, 'pause')
        self.queue.enqueue(8, 8, [line], 'all', ['', '', '', ''], 'bounty')
        rows = self.watches.rows(8, 8)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]['enabled'])

    def test_conflicting_headers_roll_back_jobs_and_watches(self):
        with self.assertRaises(ValueError):
            self.queue.enqueue(8, 8, ['https://new.test/?a=1\t{"X-Test":"a"}',
                                      'https://new.test/?a=2\t{"X-Test":"b"}'],
                               'all', ['', '', '', ''], 'bounty')
        self.assertEqual(self.watches.rows(8, 8), [])
        self.assertEqual(self.queue.db.execute('SELECT count(*) FROM jobs').fetchone()[0], 0)


class SnapshotTests(unittest.TestCase):
    def test_structure_js_and_query_redaction(self):
        record = {'request': {'endpoint': 'https://example.test/?token=secret'},
                  'response': {'status_code': 200, 'body': 'dynamic timestamp 123',
                               'forms': [{'action': '/login', 'parameters': ['csrf', 'user']} ]}}
        key, old = fingerprint(record, 'https://example.test')
        self.assertNotIn('secret', key)
        record['response']['body'] = 'timestamp 456'
        self.assertEqual(fingerprint(record, 'https://example.test')[1], old)
        record['response']['forms'][0]['parameters'].append('new')
        self.assertNotEqual(fingerprint(record, 'https://example.test')[1], old)
        record['request']['endpoint'] = 'https://example.test/app.js'
        old = fingerprint(record, 'https://example.test')[1]
        record['response']['body'] = 'changed javascript'
        self.assertNotEqual(fingerprint(record, 'https://example.test')[1], old)
        record['request']['endpoint'] = 'https://other.test/'
        self.assertIsNone(fingerprint(record, 'https://example.test'))


class ProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_json_stream_and_bounty_flags(self):
        stream = asyncio.StreamReader()
        stream.feed_data(json.dumps({'request': {'endpoint': 'https://example.test/'},
                                   'response': {'status_code': 200}}).encode() + b'\n')
        stream.feed_eof()
        class Process:
            stdout = stream
            returncode = 0
            async def wait(self):
                return 0
        with patch('asyncio.create_subprocess_exec', AsyncMock(return_value=Process())) as spawn:
            result = await katana_snapshot('https://example.test/')
        self.assertIn('GET https://example.test/', result)
        args = spawn.call_args.args
        self.assertEqual(args[args.index('-rl') + 1], '1')
        self.assertIn('-dr', args)
        self.assertIn('-cs', args)

    async def test_failure_kills_process(self):
        stream = asyncio.StreamReader()
        stream.feed_data(b'{"response":{"status_code":429}}\n')
        stream.feed_eof()
        class Process:
            stdout = stream
            returncode = None
            pid = 999999
            wait = AsyncMock()
        with patch('asyncio.create_subprocess_exec', AsyncMock(return_value=Process())), patch('os.killpg') as kill:
            with self.assertRaises(RuntimeError):
                await katana_snapshot('https://example.test/')
        kill.assert_called_once()

class BotWatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_registration_skips_profile_and_credentials(self):
        from types import SimpleNamespace
        from bot import save_urls_and_ask_creds
        message, state = AsyncMock(), AsyncMock()
        message.from_user.id, message.chat.id = 7, 7
        with tempfile.TemporaryDirectory() as directory:
            queue = QueueStore(directory)
            try:
                with patch('bot.queue_worker', SimpleNamespace(store=queue)):
                    await save_urls_and_ask_creds(message, state, 'watch', ['https://example.test/'])
                self.assertEqual(len(queue.watches.rows(7, 7)), 1)
                state.clear.assert_awaited_once()
                state.set_state.assert_not_awaited()
                self.assertIn('bounty', message.answer.call_args.args[0])
            finally:
                queue.close()
