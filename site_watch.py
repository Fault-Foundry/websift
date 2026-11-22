"""Persistent bounty-only watches; Katana snapshots contain no response bodies."""
import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import time
import tempfile
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
import uuid

from scan_safety import Limits, number, use_profile
from shared_recon import origin


def settings():
    return (number('WATCH_INTERVAL_HOURS', 24, 1, 720) * 3600,
            number('WATCH_FULL_DAYS', 7, 1, 90) * 86400)


def canonical(url):
    origin(url)
    p = urlsplit(url)
    host = p.hostname.lower()
    if ':' in host:
        host = '[' + host + ']'
    if p.port and p.port != (443 if p.scheme == 'https' else 80):
        host += ':' + str(p.port)
    return urlunsplit((p.scheme, host, p.path or '/',
                      urlencode([(name, '') for name in sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})]), ''))


def fingerprint(record, seed):
    request, response = record.get('request') or {}, record.get('response') or {}
    url = request.get('endpoint', '')
    if origin(url) != origin(seed):
        return None
    forms = []
    for form in response.get('forms', []):
        action = urljoin(url, form.get('action') or url)
        if origin(action) == origin(seed):
            forms.append([form.get('method', 'GET').upper(), canonical(action),
                          form.get('enctype', ''), sorted(set(form.get('parameters') or []))])
    headers = response.get('headers') or {}
    content_type = headers.get('content-type', '').lower()
    is_js = urlsplit(url).path.lower().endswith(('.js', '.mjs')) or 'javascript' in content_type
    body_hash = hashlib.sha256(response.get('body', '').encode()).hexdigest() if is_js else None
    value = [response.get('status_code'), sorted(forms), body_hash]
    key = request.get('method', 'GET').upper() + ' ' + canonical(url)
    return key, hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


async def katana_snapshot(url, headers=None):
    """Stream bounded JSONL in memory, stop on errors and never persist raw output."""
    origin(url)
    limits = Limits.load()
    pages = number('WATCH_MAX_PAGES', 200, 1, 10000, int)
    if limits.pages:
        pages = min(pages, limits.pages)
    if limits.requests:
        pages = min(pages, limits.requests)
    timeout = number('WATCH_RECON_TIMEOUT', 300, 10, 3600)
    if limits.seconds:
        timeout = min(timeout, limits.seconds)
    bundled = Path(__file__).parent / 'xss-orchestrator/bin/katana'
    binary = os.environ.get('KATANA_BIN', str(bundled) if bundled.exists() else 'katana')
    p = urlsplit(url)
    scope = '^' + re.escape(f'{p.scheme}://{p.netloc}') + r'(?:/|$)'
    cmd = [binary, '-u', url, '-silent', '-duc', '-j', '-or', '-fx', '-jc', '-duf', '-iqp',
           '-dr', '-cs', scope, '-cos', os.environ.get('RECON_EXCLUDE_REGEX',
           r'(?i:/(?:logout|signout|delete|destroy|reset|setup)(?:[/?]|$))'),
           '-d', str(number('RECON_MAX_DEPTH', 3, 0, 100, int)),
           '-c', '1', '-p', '1', '-rl', '1', '-rd', str(math.ceil(limits.interval)),
           '-mdp', str(pages), '-mrs', '262144', '-timeout', '10', '-retry', '0']
    with tempfile.TemporaryDirectory() as tmp:
        if headers:
            from target_headers import validate_headers
            header_file = Path(tmp) / 'headers.txt'
            header_file.write_text('\n'.join(f'{k}: {v}' for k, v in validate_headers(headers).items()))
            header_file.chmod(0o600)
            cmd += ['-H', str(header_file)]
        return await _read_katana(cmd, url, pages, timeout)


async def _read_katana(cmd, url, pages, timeout):
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, start_new_session=True, limit=2 * 1024 * 1024)
    snapshot, count, root_seen = {}, 0, False
    try:
        async with asyncio.timeout(timeout):
            async for line in proc.stdout:
                record = json.loads(line)
                if record.get('error'):
                    raise RuntimeError('Katana: неполный обход (сетевая ошибка).')
                response = record.get('response') or {}
                status = response.get('status_code', 0)
                if status == 429 or status >= 500:
                    raise RuntimeError(f'Katana: остановка на HTTP {status}.')
                if response.get('content_length', 0) >= 262144:
                    raise RuntimeError('Katana: ответ достиг лимита размера; снимок не обновлён.')
                if not status:
                    raise RuntimeError('Katana: ответ без HTTP-статуса.')
                item = fingerprint(record, url)
                if item:
                    count += 1
                    if count >= pages:
                        raise RuntimeError('Katana: достигнут лимит страниц; снимок не обновлён.')
                    key, value = item
                    snapshot[key] = value
                    root_seen |= canonical(record['request']['endpoint']) == canonical(url)
            await proc.wait()
            if proc.returncode or not snapshot or not root_seen:
                raise RuntimeError('Katana: обход не завершён или начальная страница отсутствует.')
            return snapshot
    finally:
        if proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await proc.wait()


async def scan_watch(url, headers=None):
    try:
        with use_profile('bounty'):
            snapshot = await katana_snapshot(url, headers)
        return {'watch': {'status': 'completed', 'snapshot': snapshot, 'findings': [], 'errors': []}}
    except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
        # Parser/subprocess errors must never include raw responses or secrets.
        message = str(exc) if isinstance(exc, RuntimeError) else f'Katana: {type(exc).__name__}; снимок не обновлён.'
        return {'watch': {'status': 'incomplete', 'findings': [], 'errors': [message]}}


class WatchStore:
    def __init__(self, queue):
        self.queue, self.db = queue, queue.db
        self.db.executescript('''CREATE TABLE IF NOT EXISTS watches (
            id TEXT PRIMARY KEY, owner INTEGER NOT NULL, chat INTEGER NOT NULL,
            url TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
            next_due REAL NOT NULL DEFAULT 0, snapshot TEXT, last_full REAL NOT NULL DEFAULT 0,
            last_error TEXT NOT NULL DEFAULT '', UNIQUE(owner,chat,url));''')
        if 'headers' not in {r['name'] for r in self.db.execute('PRAGMA table_info(watches)')}:
            self.db.execute("ALTER TABLE watches ADD COLUMN headers TEXT NOT NULL DEFAULT '{}'")

    def add(self, owner, chat, urls):
        from target_headers import parse_target
        clean = []
        for line in urls:
            url, headers = parse_target(line)
            if headers or '\0' in url:
                raise ValueError('Наблюдение принимает только URL без заголовков и POST-тел.')
            p = urlsplit(url)
            if p.query or p.fragment:
                raise ValueError('Для наблюдения укажите начальный URL без query и fragment.')
            clean.append(canonical(url))
        if not clean:
            raise ValueError('Список целей пуст.')
        with self.db:
            for url in dict.fromkeys(clean):
                self.db.execute('INSERT OR IGNORE INTO watches(id,owner,chat,url) VALUES(?,?,?,?)',
                                (uuid.uuid4().hex[:12], owner, chat, url))
        return len(set(clean))

    def follow_batch(self, batch):
        """Register bounty /all targets in the enqueue transaction; link initial scans."""
        rows = self.db.execute('SELECT * FROM jobs WHERE batch=?', (batch,)).fetchall()
        seeds = {}
        for job in rows:
            p = urlsplit(job['url'])
            seed = canonical(urlunsplit((p.scheme, p.netloc, p.path, '', '')))
            if seed in seeds and seeds[seed] != job['headers']:
                raise ValueError('У одной цели наблюдения разные заголовки.')
            seeds[seed] = job['headers']
            self.db.execute("""INSERT INTO watches(id,owner,chat,url,headers) VALUES(?,?,?,?,?)
                ON CONFLICT(owner,chat,url) DO UPDATE SET enabled=1,headers=excluded.headers""",
                (uuid.uuid4().hex[:12], job['owner'], job['chat'], seed, job['headers']))
            row = self.db.execute('SELECT id FROM watches WHERE owner=? AND chat=? AND url=?',
                                  (job['owner'], job['chat'], seed)).fetchone()
            self.db.execute('UPDATE jobs SET watch_id=? WHERE id=?', (row['id'], job['id']))

    def rows(self, owner, chat):
        return self.db.execute('SELECT * FROM watches WHERE owner=? AND chat=? ORDER BY url', (owner, chat)).fetchall()

    def control(self, ident, owner, chat, action):
        with self.db:
            row = self.db.execute('SELECT * FROM watches WHERE id=? AND owner=? AND chat=?', (ident, owner, chat)).fetchone()
            if row is None:
                return 0
            if action == 'remove':
                self.db.execute('DELETE FROM watches WHERE id=?', (ident,))
            else:
                self.db.execute('UPDATE watches SET enabled=?,next_due=0 WHERE id=?', (action == 'resume', ident))
            if action != 'resume':
                self.db.execute("UPDATE jobs SET status='cancelled',credentials='[]',headers='{}' WHERE watch_id=? AND status IN ('queued','running','paused')", (ident,))
        return 1

    def _insert(self, row, mode):
        batch = uuid.uuid4().hex[:12]
        self.db.execute('''INSERT INTO jobs(batch,owner,chat,url,host,mode,credentials,profile,watch_id,headers)
            VALUES(?,?,?,?,?,?,?,'bounty',?,?)''', (batch, row['owner'], row['chat'], row['url'],
            origin(row['url'])[1], mode, '["", "", "", ""]', row['id'], row['headers']))
        return batch

    def schedule(self, allowed_users):
        now = time.time()
        with self.db:
            for row in self.db.execute('SELECT * FROM watches WHERE enabled=1 AND next_due<=?', (now,)).fetchall():
                if row['owner'] not in allowed_users:
                    continue
                if self.db.execute("SELECT 1 FROM jobs WHERE watch_id=? AND status IN ('queued','running','paused')", (row['id'],)).fetchone():
                    continue
                self._insert(row, 'watch')
                self.db.execute('UPDATE watches SET next_due=? WHERE id=?', (now + settings()[0], row['id']))

    def complete(self, job, report):
        """Called inside QueueStore.complete's transaction, including scan enqueue."""
        if job['mode'] == 'all' and job.get('watch_id'):
            successful = all(r.get('status') in ('completed', 'skipped') for r in report.values())
            self.db.execute('UPDATE watches SET last_full=? WHERE id=?',
                            (time.time() if successful else 0, job['watch_id']))
        if job['mode'] != 'watch':
            return
        row = self.db.execute('SELECT * FROM watches WHERE id=? AND enabled=1', (job.get('watch_id'),)).fetchone()
        if row is None:
            return
        result = report.setdefault('watch', {'status': 'incomplete', 'findings': [],
            'errors': ['Наблюдение прервано; предыдущий снимок сохранён.']})
        now = time.time()
        self.db.execute('UPDATE watches SET next_due=? WHERE id=?', (now + settings()[0], row['id']))
        if result['status'] != 'completed':
            self.db.execute('UPDATE watches SET last_error=? WHERE id=?', ('; '.join(result.get('errors', [])), row['id']))
            return
        snapshot = result.pop('snapshot')
        previous = json.loads(row['snapshot']) if row['snapshot'] is not None else None
        added = sorted(set(snapshot) - set(previous or {}))
        removed = sorted(set(previous or {}) - set(snapshot))
        changed = sorted(k for k in snapshot if previous and k in previous and snapshot[k] != previous[k])
        full = (previous is None and not row['last_full']) or (previous is not None and bool(added or removed or changed)) or now - row['last_full'] >= settings()[1]
        bootstrap = previous is None and not full
        batch = None if bootstrap else self._insert(row, 'all' if full else 'exposure')
        result['notes'] = [f"Наблюдение {row['id']} · bounty. " + ('Первый снимок.' if previous is None else
            f'Добавлено: {len(added)}, удалено: {len(removed)}, изменено: {len(changed)}.'),
            ("Наблюдение включено после /all; повторная проверка сейчас не нужна." if bootstrap else
             f"Пакет {batch}: {'полная проверка цели' if full else 'плановая проверка Exposure Watch'}.")]
        result['notes'] += ['+ ' + k for k in added[:15]] + ['~ ' + k for k in changed[:15]] + ['− ' + k for k in removed[:15]]
        self.db.execute('UPDATE watches SET snapshot=?,last_full=?,last_error=? WHERE id=?',
            (json.dumps(snapshot, sort_keys=True), now if full else row['last_full'], '', row['id']))
