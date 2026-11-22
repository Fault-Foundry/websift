#!/usr/bin/env python3
"""Exposure Watch: bounded, exact-origin exposure checks. Python 3.11+."""
import argparse
import contextlib
import datetime as dt
import difflib
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass

LOG = logging.getLogger('exposure-watch')
CHECKS = {
    '/.env': 'env', '/.env.production': 'env', '/.env.local': 'env',
    '/.git/HEAD': 'git_head', '/.git/config': 'git_config',
    '/backup.sql': 'sql', '/dump.sql': 'sql',
    '/phpinfo.php': 'phpinfo', '/info.php': 'phpinfo',
    '/server-status': 'apache_status',
    '/backup/': 'listing', '/backups/': 'listing', '/uploads/': 'listing',
}


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def origin(value):
    p = urllib.parse.urlsplit(value)
    if (p.scheme not in ('http', 'https') or not p.hostname or p.username
            or p.password or p.path not in ('', '/') or p.query or p.fragment):
        raise ValueError('Each target must be an exact http(s) origin, without path or credentials')
    _ = p.port  # validate port
    return value.rstrip('/')


def load_config(path):
    c = json.loads(Path(path).read_text())
    targets = c.get('targets', [])
    if not isinstance(targets, list) or not targets or not all(isinstance(t, str) for t in targets):
        raise ValueError('Set a nonempty targets array in config.json')
    c['targets'] = list(dict.fromkeys(origin(t) for t in targets))
    for key, default, low, high in (
        ('request_interval_seconds', 1, .2, 3600), ('timeout_seconds', 10, 1, 120),
        ('interval_hours', 24, 1, 720), ('max_body_bytes', 65536, 1024, 262144),
        ('max_consecutive_errors', 3, 1, 20), ('retention_days', 30, 1, 3650),
    ):
        value = c.get(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
            raise ValueError(f'Invalid {key}: expected {low}..{high}')
        if key in ('max_body_bytes', 'max_consecutive_errors', 'retention_days') and int(value) != value:
            raise ValueError(f'{key} must be an integer')
        c[key] = value
    c.setdefault('user_agent', 'ExposureWatch/1.0 (authorized security testing)')
    if not isinstance(c['user_agent'], str) or '\n' in c['user_agent'] or '\r' in c['user_agent']:
        raise ValueError('Invalid user_agent')
    return c


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class Response:
    status: int
    body: str
    content_type: str = ''
    truncated: bool = False


class Fetcher:
    def __init__(self, config):
        self.c = config
        # Do not inherit ambient proxy settings or persist cookies between checks.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.next_request = 0

    def get(self, url):
        time.sleep(max(0, self.next_request - time.monotonic()))
        req = urllib.request.Request(url, headers={
            'User-Agent': self.c['user_agent'], 'Accept-Encoding': 'identity',
            'Range': f"bytes=0-{self.c['max_body_bytes'] - 1}",
        })
        try:
            try:
                response = self.opener.open(req, timeout=self.c['timeout_seconds'])
            except urllib.error.HTTPError as e:
                response = e
            with response:
                limit = int(self.c['max_body_bytes'])
                body = response.read(limit + 1)
                return Response(response.code, body[:limit].decode('utf-8', errors='replace'),
                                response.headers.get('Content-Type', ''), len(body) > limit)
        finally:
            # Delay starts after completion, including errors and slow responses.
            self.next_request = time.monotonic() + self.c['request_interval_seconds']


def fingerprint(body):
    text = body.lower()
    text = re.sub(r'[0-9a-f]{16,}|\b\d+\b|/__ew_[\w./-]+', '#', text)
    return re.sub(r'\s+', ' ', text).strip()[:16000]


def same_page(a, b):
    a, b = fingerprint(a), fingerprint(b)
    return a == b or (bool(a) and bool(b) and
                       difflib.SequenceMatcher(None, a, b, autojunk=True).ratio() >= .95)


def detect(kind, body):
    """Return structural evidence only; never return secret values or file bodies."""
    if kind == 'env' and not re.search(r'<(?:!doctype|html|body)\b', body, re.I):
        names = re.findall(r'^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=\s*.+$', body, re.M)
        sensitive = [n for n in names if re.search(r'PASSWORD|SECRET|TOKEN|PRIVATE_KEY|API_KEY|DATABASE_URL|DB_PASS', n)]
        if len(set(names)) >= 3 and sensitive:
            return f'{len(set(names))} configuration keys, including sensitive key names; values omitted'
    if kind == 'git_head' and re.fullmatch(r'\s*(?:ref: refs/heads/[\w./-]+|[a-f0-9]{40})\s*', body):
        return 'Valid Git HEAD structure; reference omitted'
    if kind == 'git_config' and re.search(r'^\s*\[core\]\s*$', body, re.M) and re.search(r'^\s*repositoryformatversion\s*=\s*\d+', body, re.M):
        return 'Git core section and repository format version; configuration omitted'
    if kind == 'sql' and re.search(r'(?:-- (?:MySQL|PostgreSQL) database dump|-- MySQL dump)', body) and re.search(r'\bCREATE TABLE\b|\bCOPY\s+\S+\s*\(', body, re.I):
        return 'Database dump signature and table structure; records omitted'
    if kind == 'phpinfo' and re.search(r'PHP Version\s*\d', body, re.I) and re.search(r'PHP (?:Credits|License)|Configuration File \(php.ini\) Path', body, re.I):
        return 'Multiple phpinfo signatures; runtime details omitted'
    if kind == 'apache_status' and 'Apache Server Status' in body and re.search(r'Server (?:Version|Uptime)', body):
        return 'Apache status page signatures; runtime details omitted'
    if kind == 'listing' and re.search(r'<title>\s*Index of ', body, re.I) and re.search(r'href=[\"\x27][^\"\x27]+[\"\x27]', body, re.I):
        return 'Directory index with links; filenames omitted (impact requires review)'
    return None


def scan_target(target, fetcher, c):
    findings, events = [], []
    errors = 0

    def get(path):
        nonlocal errors
        try:
            r = fetcher.get(target + path)
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            errors += 1
            events.append({'target': target, 'path': path, 'event': 'network_error'})
            return None
        if r.status in (429, 503):
            events.append({'target': target, 'path': path, 'event': 'rate_limited_or_unavailable'})
            raise StopIteration
        errors = errors + 1 if r.status >= 500 else 0
        return r

    try:
        # Two missing-path controls catch soft 404s and wildcard responses.
        controls = [get('/__ew_' + uuid.uuid4().hex + suffix) for suffix in ('', '/.env')]
        if any(r is None or r.status >= 500 for r in controls):
            events.append({'target': target, 'event': 'baseline_failed'})
            return findings, events
        for path, kind in CHECKS.items():
            if errors >= c['max_consecutive_errors']:
                events.append({'target': target, 'event': 'error_threshold'})
                break
            r = get(path)
            if r is None or r.status not in (200, 206):
                continue
            if any(same_page(r.body, b.body) for b in controls):
                continue
            evidence = detect(kind, r.body)
            if not evidence:
                continue
            confirm = get(path)
            if confirm is None or confirm.status not in (200, 206) or not detect(kind, confirm.body):
                continue
            if any(same_page(confirm.body, b.body) for b in controls):
                continue
            findings.append({'url': target + path, 'check': kind, 'status': confirm.status,
                             'evidence': evidence, 'classification': 'review_required',
                             'truncated': r.truncated or confirm.truncated})
    except StopIteration:
        pass
    return findings, events


def run(c, directory):
    started = utcnow()
    fetcher = Fetcher(c)
    findings, events = [], []
    for target in c['targets']:
        LOG.info('Checking %s', target)
        f, e = scan_target(target, fetcher, c)
        findings.extend(f)
        events.extend(e)
    with sqlite3.connect(directory / 'history.sqlite3') as db:
        db.execute('CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT)')
        for f in findings:
            key = hashlib.sha256((f['url'] + '|' + f['check']).encode()).hexdigest()
            existing = db.execute('SELECT first_seen FROM findings WHERE id=?', (key,)).fetchone()
            f['new'] = existing is None
            f['first_seen'] = existing[0] if existing else started
            db.execute('INSERT INTO findings VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen',
                       (key, f['first_seen'], started))
    report = {'started': started, 'finished': utcnow(), 'targets': c['targets'],
              'findings': findings, 'events': events}
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
    reports = directory / 'reports'
    reports.mkdir(exist_ok=True)
    atomic_json(reports / (stamp + '.json'), report)
    atomic_json(directory / 'latest.json', report)
    lines = ['# Exposure Watch', '', f'Run: {started}', '',
             'Structural matches require review. No secret values or response bodies are stored.', '']
    for f in findings:
        lines += [f"- {f['url']} — {f['check']} ({'NEW' if f['new'] else 'seen before'})", f"  {f['evidence']}"]
    if not findings:
        lines.append('No structural exposure matches in the configured checks.')
    lines += ['', f'Events / skipped checks: {len(events)}. See latest.json for details.']
    temporary = directory / 'latest.md.tmp'
    temporary.write_text('\n'.join(lines) + '\n')
    temporary.replace(directory / 'latest.md')
    cutoff = time.time() - c['retention_days'] * 86400
    for p in reports.glob('*.json'):
        if p.stat().st_mtime < cutoff:
            p.unlink()
    LOG.info('Finished: %d candidates (%d new), %d events', len(findings),
             sum(f['new'] for f in findings), len(events))
    return report


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='config.json')
    parser.add_argument('--data', default='data')
    parser.add_argument('--watch', action='store_true', help='Repeat after interval_hours; reload config each cycle')
    args = parser.parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    directory = Path(args.data)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        with (directory / '.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            while True:
                c = load_config(args.config)
                run(c, directory)
                if not args.watch:
                    break
                time.sleep(c['interval_hours'] * 3600)
    except BlockingIOError:
        parser.exit(2, 'Another scanner is using this data directory.\n')
    except (OSError, ValueError, sqlite3.Error) as e:
        parser.exit(2, f'Scanner stopped: {type(e).__name__}. Check configuration, data permissions and logs.\n')
    except KeyboardInterrupt:
        LOG.info('Stopped')


if __name__ == '__main__':
    main()
