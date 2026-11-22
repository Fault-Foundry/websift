import contextlib
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest

from scanner import Fetcher, detect, load_config, origin, run, scan_target

ENV = 'APP_ENV=production\nDB_HOST=localhost\nDB_PASSWORD=private-test-value\n'


@contextlib.contextmanager
def server(mode):
    requests = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            code, body = 404, 'Missing'
            if mode == 'soft404':
                code, body = 200, ENV
            elif mode == 'throttle':
                code = 429
            elif self.path == '/.env':
                code, body = 200, ENV
            elif self.path == '/.git/HEAD':
                code, body = 200, 'ref: refs/heads/main\n'
            elif self.path == '/backup.sql':
                code, body = 302, ''
            elif self.path == '/info.php':
                code, body = 200, 'PHP Version 8.2.0 PHP Credits'
            self.send_response(code)
            if code == 302:
                self.send_header('Location', '/must-not-follow')
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass
    s = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    try:
        yield f'http://127.0.0.1:{s.server_port}', requests
    finally:
        s.shutdown()
        s.server_close()
        t.join()


def config(target):
    return {'targets': [target], 'request_interval_seconds': 0,
            'timeout_seconds': 2, 'max_body_bytes': 65536,
            'max_consecutive_errors': 3, 'retention_days': 30,
            'user_agent': 'ExposureWatch-test'}


class ScannerTests(unittest.TestCase):
    def test_real_http_detection_and_no_redirect(self):
        with server('normal') as (target, requests):
            c = config(target)
            found, events = scan_target(target, Fetcher(c), c)
        self.assertEqual({f['check'] for f in found}, {'env', 'git_head', 'phpinfo'})
        self.assertNotIn('/must-not-follow', requests)
        self.assertEqual(requests.count('/.env'), 2)
        self.assertNotIn('private-test-value', json.dumps(found))
        self.assertEqual(events, [])

    def test_soft404_with_convincing_content_is_rejected(self):
        with server('soft404') as (target, _):
            c = config(target)
            found, _ = scan_target(target, Fetcher(c), c)
        self.assertEqual(found, [])

    def test_rate_limited_host_stops_immediately(self):
        with server('throttle') as (target, requests):
            c = config(target)
            found, events = scan_target(target, Fetcher(c), c)
        self.assertEqual(found, [])
        self.assertEqual(len(requests), 1)
        self.assertEqual(events[0]['event'], 'rate_limited_or_unavailable')

    def test_reports_history_and_redaction(self):
        with server('normal') as (target, _), tempfile.TemporaryDirectory() as tmp:
            c = config(target)
            first = run(c, Path(tmp))
            second = run(c, Path(tmp))
            self.assertTrue(all(f['new'] for f in first['findings']))
            self.assertFalse(any(f['new'] for f in second['findings']))
            self.assertTrue((Path(tmp) / 'latest.md').is_file())
            for path in Path(tmp).rglob('*.json'):
                self.assertNotIn('private-test-value', path.read_text())

    def test_false_signature_and_html_env(self):
        self.assertIsNone(detect('env', '<html>' + ENV + '</html>'))
        self.assertIsNone(detect('sql', 'CREATE TABLE example (id int)'))
        self.assertIsNone(detect('git_head', '<html>ref: refs/heads/main</html>'))

    def test_scope_and_config_validation(self):
        for bad in ('ftp://example.com', 'https://a.example/path', 'https://u:p@a.example',
                    'https://a.example/?q=1', 'https://a.example:invalid'):
            with self.assertRaises(ValueError):
                origin(bad)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'config.json'
            p.write_text(json.dumps({'targets': ['https://example.com']}))
            self.assertEqual(load_config(p)['request_interval_seconds'], 1)
            p.write_text(json.dumps({'targets': ['https://example.com'], 'interval_hours': 0}))
            with self.assertRaises(ValueError):
                load_config(p)


if __name__ == '__main__':
    unittest.main()
