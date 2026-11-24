import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import websift
from durable_queue import QueueStore, QueueWorker


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = self.tmp.name
        self.output = io.StringIO()
    def command(self, *args):
        with patch('websift.load_dotenv'), contextlib.redirect_stdout(self.output), contextlib.redirect_stderr(self.output):
            return websift.main(['--queue-dir', self.directory, *args])
    def test_enqueue_and_management_work_while_worker_holds_lock(self):
        store = QueueStore(self.directory)
        try:
            self.assertEqual(self.command('scan', 'https://lab.test/', '--enqueue', '--profile', 'fast'), 0)
            batch = store.db.execute('SELECT batch FROM jobs').fetchone()[0]
            self.assertEqual(self.command('queue'), 0)
            self.assertEqual(self.command('pause', batch), 0)
            self.assertIsNone(store.claim())
            self.assertEqual(self.command('resume', batch), 0)
            self.assertEqual(store.claim()['profile'], 'fast')
            # A management command must not recover a live running target.
            self.command('queue')
            self.assertEqual(store.db.execute('SELECT status FROM jobs').fetchone()[0], 'running')
            self.assertEqual(self.command('cancel', batch), 0)
        finally:
            store.close()
    def test_foreground_scan_uses_core_and_exports_without_telegram(self):
        scan = AsyncMock(return_value={'xss': {'status': 'completed', 'findings': []}})
        with patch('scan_runner.scan_queued_job', scan):
            self.assertEqual(self.command('scan', 'https://lab.test/', '--mode', 'xss', '--profile', 'fast'), 0)
        self.assertEqual(scan.await_count, 1)
        files = list(Path(self.directory).glob('reports/*/*.json'))
        self.assertEqual(len(files), 1)
        report = json.loads(files[0].read_text())
        self.assertEqual(report['results']['xss']['status'], 'completed')
        self.assertNotIn('credentials', report)
        self.assertTrue(files[0].with_suffix('.txt').exists())
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
    def test_failure_returns_nonzero_but_preserves_report(self):
        with patch('scan_runner.scan_queued_job', AsyncMock(side_effect=RuntimeError('secret'))):
            self.assertEqual(self.command('scan', 'https://lab.test/', '--mode', 'xss'), 1)
        self.assertNotIn('secret', self.output.getvalue())
        self.assertTrue(list(Path(self.directory).glob('reports/*/*.json')))
    def test_file_input_duplicates_and_invalid_url(self):
        source = Path(self.directory) / 'targets.txt'
        source.write_text('# targets\nhttps://lab.test/\nhttps://lab.test/\n')
        self.assertEqual(self.command('scan', '--file', str(source), '--enqueue'), 0)
        self.assertEqual(self.command('scan', 'invalid', '--enqueue'), 2)
        store = QueueStore(self.directory, worker=False)
        self.assertEqual(store.db.execute('SELECT count(*) FROM jobs').fetchone()[0], 1)
        store.close()
    def test_cli_rejects_telegram_queue_without_recovery(self):
        store = QueueStore(self.directory)
        store.enqueue(123, 456, ['https://lab.test/'], 'xss', ['', '', '', ''])
        store.claim()
        store.close()
        self.assertEqual(self.command('worker', '--once'), 2)
        store = QueueStore(self.directory, worker=False)
        self.assertEqual(store.db.execute('SELECT status FROM jobs').fetchone()[0], 'running')
        store.close()
    def test_imports_do_not_require_telegram_packages(self):
        code = '''
import importlib.abc, sys
class NoTelegram(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, *args):
        if fullname.split('.')[0] in ('aiogram', 'bot'):
            raise AssertionError('Telegram import: ' + fullname)
sys.meta_path.insert(0, NoTelegram())
import websift, scan_runner, scan_pipeline, durable_queue
'''
        result = subprocess.run([sys.executable, '-c', code], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class ExternalControlTests(unittest.IsolatedAsyncioTestCase):
    async def test_external_pause_cancels_active_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = QueueStore(tmp)
            batch, _ = store.enqueue(0, 0, ['https://lab.test/'], 'xss', ['', '', '', ''])
            entered, stopped = asyncio.Event(), asyncio.Event()
            async def scan(job):
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    stopped.set()
            worker = QueueWorker(store, scan, AsyncMock(), {0}, lambda *args: '')
            task = asyncio.create_task(worker.work())
            try:
                await asyncio.wait_for(entered.wait(), 2)
                client = QueueStore(tmp, worker=False)
                client.control(batch, 0, 0, 'pause')
                client.close()
                await asyncio.wait_for(stopped.wait(), 2)
                self.assertEqual(store.db.execute('SELECT status FROM jobs').fetchone()[0], 'paused')
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                store.close()
