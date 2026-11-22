import asyncio
import json
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from durable_queue import QueueStore, QueueWorker


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = QueueStore(self.tmp.name)
    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()
    def add(self, urls=None):
        return self.store.enqueue(7, 8, urls or ['https://lab.test/?q=1'], 'sqli', ['', '', '', ''])[0]
    def test_recovery_preserves_finished_report_and_requeues_running(self):
        self.add(['https://lab.test/?q=1', 'https://lab.test/?q=2'])
        first = self.store.claim()
        self.store.complete(first, {'sqli': {'status': 'completed'}}, ['result'])
        second = self.store.claim()
        self.store.close()
        self.store = QueueStore(self.tmp.name)
        self.assertEqual(self.store.claim()['id'], second['id'])
        self.assertEqual(self.store.next_message()[2], 'result')
        self.store.acknowledge(first['id'])
        self.assertIsNone(self.store.next_message())
        row = self.store.db.execute('SELECT credentials,report FROM jobs WHERE id=?', (first['id'],)).fetchone()
        self.assertEqual(row['credentials'], '[]')
        self.assertIn('completed', row['report'])
    def test_dedup_and_validation_are_atomic(self):
        self.add(['https://lab.test/', 'https://lab.test/'])
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM jobs').fetchone()[0], 1)
        with self.assertRaises(ValueError):
            self.add(['https://lab.test/ok', 'invalid'])
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM jobs').fetchone()[0], 1)
    def test_controls_are_owner_and_chat_scoped(self):
        batch = self.add()
        self.assertEqual(self.store.control(batch, 99, 8, 'cancel'), 0)
        self.assertEqual(self.store.control(batch, 7, 99, 'cancel'), 0)
        self.assertEqual(self.store.control(batch, 7, 8, 'pause'), 1)
        self.assertIsNone(self.store.claim())
        self.store.control(batch, 7, 8, 'resume')
        self.assertIsNotNone(self.store.claim())
        self.store.control(batch, 7, 8, 'cancel')
        self.assertEqual(self.store.db.execute('SELECT credentials FROM jobs').fetchone()[0], '[]')
    def test_cooldown_skips_same_host_but_other_hosts_continue(self):
        self.add(['https://lab.test/1', 'https://lab.test/2', 'https://other.test/'])
        self.store.postpone(self.store.claim(), 300)
        self.assertEqual(self.store.claim()['host'], 'other.test')
        self.assertIsNone(self.store.claim())
    def test_second_process_cannot_recover_live_jobs(self):
        with self.assertRaises(RuntimeError):
            QueueStore(self.tmp.name)


class WorkerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = QueueStore(self.tmp.name)
        self.batch, _ = self.store.enqueue(7, 8, ['https://lab.test/'], 'xss', ['', '', '', ''])
    async def asyncTearDown(self):
        self.store.close()
        self.tmp.cleanup()
    async def test_pause_cancels_engine_and_survives_restart(self):
        entered = asyncio.Event()
        stopped = asyncio.Event()
        async def scan(job):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()
        worker = QueueWorker(self.store, scan, AsyncMock(), {7}, lambda *args: 'report')
        task = asyncio.create_task(worker.work())
        await entered.wait()
        await worker.control(self.batch, 7, 8, 'pause')
        await stopped.wait()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        self.assertEqual(self.store.db.execute('SELECT status FROM jobs').fetchone()[0], 'paused')
    async def test_worker_continues_after_engine_failure(self):
        self.store.enqueue(7, 8, ['https://other.test/'], 'xss', ['', '', '', ''])
        called = asyncio.Event()
        scan = AsyncMock(side_effect=[RuntimeError('secret'), {'xss': {'status': 'completed'}}])
        def formatted(url, report):
            if 'other' in url:
                called.set()
            return json.dumps(report)
        worker = QueueWorker(self.store, scan, AsyncMock(), {7}, formatted)
        task = asyncio.create_task(worker.work())
        await asyncio.wait_for(called.wait(), 5)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        rows = self.store.db.execute('SELECT status,report FROM jobs').fetchall()
        self.assertEqual([r['status'] for r in rows], ['done', 'done'])
        self.assertNotIn('secret', rows[0]['report'])
    async def test_shutdown_requeues_active_target(self):
        entered = asyncio.Event()
        async def scan(job):
            entered.set()
            await asyncio.Event().wait()
        worker = QueueWorker(self.store, scan, AsyncMock(), {7}, lambda *args: '')
        task = asyncio.create_task(worker.work())
        await entered.wait()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        self.assertEqual(self.store.db.execute('SELECT status FROM jobs').fetchone()[0], 'queued')
    async def test_overload_is_deferred_not_reported_as_complete(self):
        scan = AsyncMock(return_value={'xss': {'status': 'incomplete', 'retryable': True}})
        worker = QueueWorker(self.store, scan, AsyncMock(), {7}, lambda *args: '')
        task = asyncio.create_task(worker.work())
        for _ in range(20):
            await asyncio.sleep(0)
            if self.store.db.execute('SELECT count(*) FROM cooldowns').fetchone()[0]:
                break
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        row = self.store.db.execute('SELECT status,report FROM jobs').fetchone()
        self.assertEqual(row['status'], 'queued')
        self.assertIsNone(row['report'])

    async def test_delivery_failure_does_not_block_other_reports_or_rescan(self):
        first = self.store.claim()
        self.store.complete(first, {}, ['first'])
        self.store.enqueue(7, 9, ['https://other.test/'], 'xss', ['', '', '', ''])
        second = self.store.claim()
        self.store.complete(second, {}, ['second'])
        delivered = asyncio.Event()
        async def send(chat, text):
            if text == 'first':
                raise RuntimeError('Telegram temporarily unavailable')
            delivered.set()
        scan = AsyncMock()
        worker = QueueWorker(self.store, scan, send, {7}, lambda *args: '')
        task = asyncio.create_task(worker.deliver())
        await asyncio.wait_for(delivered.wait(), 2)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        scan.assert_not_awaited()
        rows = self.store.db.execute('SELECT sent,status FROM jobs ORDER BY id').fetchall()
        self.assertEqual([r['sent'] for r in rows], [0, -1])
        self.assertEqual([r['status'] for r in rows], ['done', 'done'])

    async def test_all_keeps_other_engines_when_sqlmap_cannot_start(self):
        from bot import scan_queued_job
        engine = AsyncMock()
        engine.__aenter__.side_effect = RuntimeError('unavailable')
        with patch('bot.SqlmapClient', return_value=engine), \
             patch('scan_pipeline.run_pipeline', AsyncMock(return_value={'sqli': {'status': 'error'}})) as pipeline:
            await scan_queued_job({'url': 'https://lab.test/', 'mode': 'all',
                                   'credentials': '["", "", "", ""]'})
        self.assertIsNone(pipeline.call_args.args[3])
