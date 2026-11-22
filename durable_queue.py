"""Single-worker durable URL queue; management clients may connect concurrently."""
import asyncio
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid


class QueueStore:
    def __init__(self, directory, *, worker=True, expected_owner=None):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        self.lock = None
        if worker:
            self.lock = (directory / 'worker.lock').open('a')
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                self.lock.close()
                raise RuntimeError('Очередь уже обслуживается другим процессом; используйте scan --enqueue.') from None
        path = directory / 'queue.sqlite3'
        path.touch(mode=0o600, exist_ok=True)
        path.chmod(0o600)
        self.db = sqlite3.connect(path, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY, batch TEXT NOT NULL, owner INTEGER NOT NULL,
                chat INTEGER NOT NULL, url TEXT NOT NULL, host TEXT NOT NULL,
                mode TEXT NOT NULL, credentials TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
                report TEXT, chunks TEXT, sent INTEGER NOT NULL DEFAULT 0, delivery_after REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS cooldowns (host TEXT PRIMARY KEY, until REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status, id);
        ''')
        if 'profile' not in {row['name'] for row in self.db.execute('PRAGMA table_info(jobs)')}:
            self.db.execute("ALTER TABLE jobs ADD COLUMN profile TEXT NOT NULL DEFAULT 'bounty'")
        if 'headers' not in {row['name'] for row in self.db.execute('PRAGMA table_info(jobs)')}:
            self.db.execute("ALTER TABLE jobs ADD COLUMN headers TEXT NOT NULL DEFAULT '{}'")
        if 'watch_id' not in {row['name'] for row in self.db.execute('PRAGMA table_info(jobs)')}:
            self.db.execute('ALTER TABLE jobs ADD COLUMN watch_id TEXT')
        from site_watch import WatchStore
        self.watches = WatchStore(self)
        if expected_owner is not None and any(
                self.db.execute(f'SELECT 1 FROM {table} WHERE owner!=? OR chat!=? LIMIT 1',
                                (expected_owner, expected_owner)).fetchone()
                for table in ('jobs', 'watches')):
            self.close()
            raise ValueError('Этот каталог принадлежит другому интерфейсу. Выберите отдельный --queue-dir для CLI.')
        # A scan cannot be resumed inside an external engine; only its URL is retried.
        if worker:
            self.db.execute("UPDATE jobs SET status='queued' WHERE status='running'")
        self.db.commit()

    def close(self):
        self.db.close()
        if self.lock:
            self.lock.close()

    def enqueue(self, owner, chat, urls, mode, credentials, profile="bounty"):
        if profile not in ("fast", "bounty"):
            raise ValueError("Unknown scan profile")
        from shared_recon import origin
        from target_headers import parse_target
        unique = {}
        for line in urls:
            url, headers = parse_target(line)
            encoded = json.dumps(headers, sort_keys=True)
            if url in unique and unique[url] != encoded:
                raise ValueError('Один URL указан с разными заголовками.')
            unique[url] = encoded
        hosts = [origin(url.split('\0', 1)[0])[1] for url in unique]
        if not unique:
            raise ValueError('Список целей пуст.')
        batch = uuid.uuid4().hex[:12]
        with self.db:
            self.db.executemany('INSERT INTO jobs(batch,owner,chat,url,host,mode,credentials,profile,headers) VALUES(?,?,?,?,?,?,?,?,?)',
                [(batch, owner, chat, url, host, mode, json.dumps(credentials), profile, unique[url]) for url, host in zip(unique, hosts)])
            if mode == 'all' and profile == 'bounty':
                self.watches.follow_batch(batch)
        return batch, len(unique)

    def claim(self, batch=None):
        if self.lock is None:
            raise RuntimeError('Only the worker may claim jobs')
        with self.db:
            row = self.db.execute("""SELECT * FROM jobs WHERE status='queued' AND (? IS NULL OR batch=?)
                AND NOT EXISTS (SELECT 1 FROM cooldowns c WHERE c.host=jobs.host AND c.until>?)
                ORDER BY id LIMIT 1""", (batch, batch, time.time())).fetchone()
            if row:
                changed = self.db.execute("UPDATE jobs SET status='running', attempts=attempts+1 WHERE id=? AND status='queued'", (row['id'],)).rowcount
                if not changed:
                    return None
                return dict(self.db.execute('SELECT * FROM jobs WHERE id=?', (row['id'],)).fetchone())

    def complete(self, job, report, chunks):
        with self.db:
            state = self.db.execute('SELECT status FROM jobs WHERE id=?', (job['id'],)).fetchone()
            if state is None or state[0] != 'running':
                return
            self.watches.complete(job, report)
            if job['mode'] == 'watch':
                from scan_pipeline import format_results
                text = format_results(job['url'], report)
                chunks = [text[i:i+3900] for i in range(0, len(text), 3900)]
            self.db.execute("UPDATE jobs SET status='done', report=?, chunks=?, credentials='[]', headers='{}' WHERE id=? AND status='running'",
                            (json.dumps(report), json.dumps(chunks), job['id']))

    def cooldown(self, host, seconds):
        with self.db:
            self.db.execute('INSERT INTO cooldowns VALUES(?,?) ON CONFLICT(host) DO UPDATE SET until=max(until,excluded.until)',
                            (host, time.time() + seconds))

    def postpone(self, job, seconds):
        with self.db:
            self.db.execute("UPDATE jobs SET status='queued' WHERE id=? AND status='running'", (job['id'],))
            self.db.execute('INSERT INTO cooldowns VALUES(?,?) ON CONFLICT(host) DO UPDATE SET until=max(until,excluded.until)',
                            (job['host'], time.time() + seconds))

    def recover(self, job):
        with self.db:
            self.db.execute("UPDATE jobs SET status='queued' WHERE id=? AND status='running'", (job['id'],))

    def control(self, batch, owner, chat, action):
        if action == 'resume':
            clause, state = "status='paused'", 'queued'
        else:
            clause, state = "status IN ('queued','running','paused')", 'paused' if action == 'pause' else 'cancelled'
        with self.db:
            cursor = self.db.execute(f'UPDATE jobs SET status=? WHERE batch=? AND owner=? AND chat=? AND {clause}',
                                     (state, batch, owner, chat))
            if state == 'cancelled':
                self.db.execute("UPDATE jobs SET credentials='[]', headers='{}' WHERE status='cancelled'")
        return cursor.rowcount

    def status(self, owner, chat):
        return self.db.execute('''SELECT batch,profile,status,count(*) AS count FROM jobs
            WHERE owner=? AND chat=? AND batch IN
            (SELECT batch FROM jobs WHERE owner=? AND chat=? GROUP BY batch ORDER BY max(id) DESC LIMIT 10)
            GROUP BY batch,profile,status ORDER BY max(id) DESC''', (owner, chat, owner, chat)).fetchall()

    def next_message(self):
        for row in self.db.execute("SELECT id,chat,chunks,sent FROM jobs WHERE chunks IS NOT NULL AND sent>=0 AND delivery_after<=? ORDER BY id", (time.time(),)):
            chunks = json.loads(row['chunks'])
            if row['sent'] < len(chunks):
                return row['id'], row['chat'], chunks[row['sent']]
        return None

    def delay_delivery(self, job_id):
        with self.db:
            self.db.execute('UPDATE jobs SET delivery_after=? WHERE id=?', (time.time() + 30, job_id))

    def acknowledge(self, job_id):
        with self.db:
            self.db.execute('UPDATE jobs SET sent=sent+1 WHERE id=?', (job_id,))
            self.db.execute("UPDATE jobs SET sent=-1 WHERE id=? AND sent>=json_array_length(chunks)", (job_id,))


class QueueWorker:
    def __init__(self, store, scan, send, allowed_users, formatter):
        self.store, self.scan, self.send = store, scan, send
        self.allowed_users, self.formatter = allowed_users, formatter
        self.active = self.job = None

    async def work(self, *, batch=None, stop_when_idle=False):
        while True:
            if batch is None:
                self.store.watches.schedule(self.allowed_users)
            job = self.store.claim(batch)
            if not job:
                pending = self.store.db.execute("SELECT 1 FROM jobs WHERE status IN ('queued','running') AND (? IS NULL OR batch=?) LIMIT 1", (batch, batch)).fetchone()
                if stop_when_idle and not pending:
                    return
                await asyncio.sleep(1)
                continue
            if job['owner'] not in self.allowed_users:
                self.store.control(job['batch'], job['owner'], job['chat'], 'pause')
                continue
            self.job = job
            self.active = asyncio.create_task(self.scan(job))
            try:
                try:
                    while not self.active.done():
                        await asyncio.wait([self.active], timeout=0.25)
                        status = self.store.db.execute('SELECT status FROM jobs WHERE id=?', (job['id'],)).fetchone()[0]
                        if status != 'running':
                            self.active.cancel()
                    report = await self.active
                except asyncio.CancelledError:
                    self.active.cancel()
                    await asyncio.gather(self.active, return_exceptions=True)
                    self.store.recover(job)
                    if asyncio.current_task().cancelling():
                        raise
                    continue
                except Exception as exc:
                    # Exceptions can contain session secrets; retain only the type.
                    report = {'scan': {'status': 'error', 'findings': [], 'errors': [type(exc).__name__]}}
                retryable = any(item.get('retryable') for item in report.values())
                if retryable:
                    self.store.cooldown(job['host'], 300 * min(job['attempts'], 3))
                if retryable and job['attempts'] < 3:
                    self.store.postpone(job, 300 * job['attempts'])
                else:
                    text = f"Пакет {job['batch']} · {job['profile']} · цель #{job['id']}\n" + self.formatter(job['url'].split('\0', 1)[0], report)
                    chunks = [text[i:i+3900] for i in range(0, len(text), 3900)]
                    self.store.complete(job, report, chunks)
            finally:
                self.active = self.job = None
                from scan_safety import Limits
                await asyncio.sleep(Limits.load().interval)

    async def deliver(self):
        while True:
            message = self.store.next_message()
            if not message:
                await asyncio.sleep(1)
                continue
            job_id, chat, text = message
            try:
                await self.send(chat, text)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.store.delay_delivery(job_id)
            else:
                self.store.acknowledge(job_id)

    async def control(self, batch, owner, chat, action):
        count = self.store.control(batch, owner, chat, action)
        if count and action != 'resume' and self.job and self.job['batch'] == batch and self.active:
            self.active.cancel()
        return count
