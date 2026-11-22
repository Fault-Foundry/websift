import asyncio
import math
import json
from cookie_session import cookie_header
import os
from pathlib import Path
import signal
import tempfile
from urllib.parse import urlsplit


class XSSRun:
    def __init__(self, url, script, output_root):
        parsed = urlsplit(url)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or any(c.isspace() for c in url)
                or "\\" in url):
            raise ValueError("XSS requires an HTTP(S) URL without credentials")
        _ = parsed.port
        self.url = url
        self.script = Path(script).resolve()
        root = Path(output_root).resolve()
        root.mkdir(parents=True, exist_ok=True)
        self.project = Path(tempfile.mkdtemp(prefix="target-", dir=root))
        (self.project / "origins.txt").write_text(f"{parsed.scheme}://{parsed.netloc}\n")
        (self.project / "seeds.txt").write_text(url + "\n")
        (self.project / "exclude.txt").write_text(os.environ.get("XSS_EXCLUDE_REGEX", os.environ.get("RECON_EXCLUDE_REGEX", r"(?i:/(?:logout|signout|delete|destroy|reset|setup)(?:[/?]|$))")))
        self.run = None

    def restrict_to_page(self, url):
        import re
        parsed = urlsplit(url)
        # Payloads may change query values, never the target origin/path.
        scope = '^' + re.escape(f'{parsed.scheme}://{parsed.netloc}{parsed.path or "/"}') + r'(?:[?#].*)?$'
        (self.project / 'single-scope.regex').write_text(scope)

    async def execute(self, phase, timeout):
        from scan_safety import Limits, check_safety, engine_pause, current_profile, request_rate
        check_safety()
        await engine_pause()
        limits = Limits.load()
        env = os.environ.copy()
        env.update(SCAN_PROFILE=current_profile(), RPS=str(request_rate()), WORKERS='1', SCAN_REQUEST_INTERVAL=str(limits.interval),
                   SCAN_DELAY_MS=str(math.ceil(limits.interval * 1000)),
                   STAGE_SECONDS=str(max(1, int(limits.seconds or 7200))))
        env["PATH"] = str(self.script.parent / "bin") + os.pathsep + env.get("PATH", "")
        if (self.project / "session.http").exists():
            env["XSS_COOKIE_REQUEST"] = str(self.project / "session.http")
        if (self.project / "session.config.json").exists():
            env["XSS_SESSION_CONFIG"] = str(self.project / "session.config.json")
        args = ["bash", str(self.script), str(self.project), phase]
        if phase == "scan":
            if self.run is None:
                raise RuntimeError("XSS recon has not completed")
            args.append(str(self.run))
        with (self.project / f"{phase}.log").open("wb") as log:
            proc = await asyncio.create_subprocess_exec(*args, env=env, stdout=log,
                                                       stderr=log, start_new_session=True)
            try:
                await asyncio.wait_for(proc.wait(), timeout)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await proc.wait()
                raise
        await engine_pause()
        if phase == "recon" and proc.returncode == 0:
            runs = list((self.project / "runs").glob("*/recon.complete"))
            if len(runs) != 1:
                raise RuntimeError("Missing or ambiguous XSS recon output")
            self.run = runs[0].parent
        if proc.returncode != 0:
            raise RuntimeError(f"XSS {phase}: exit {proc.returncode}; logs: {self.project}")

    def urls(self):
        return (self.run / "allowed.txt").read_text().splitlines()

    def report(self):
        result = {"artifacts": str(self.project),
                  "single_page": (self.project / 'single-scope.regex').exists()}
        coverage_path = self.project / 'coverage.json'
        if coverage_path.exists():
            result['coverage'] = json.loads(coverage_path.read_text())
        if result.get('coverage', {}).get('limited_urls'):
            result['status'] = 'incomplete'
            result['errors'] = ['Достигнут SCAN_MAX_TARGETS; часть XSS-адресов не проверена.']
        metadata_path = self.run / 'metadata.json'
        if metadata_path.exists():
            metadata = json.loads(metadata_path.read_text())
            if isinstance(metadata, dict):
                result['metadata'] = metadata
        for key in ("strong_candidates", "dom_candidates", "reflections", "other"):
            value = json.loads((self.run / f"{key}.json").read_text())
            if not isinstance(value, list):
                raise ValueError(f"Invalid XSS report: {key}")
            result[key] = value
        return result

    async def import_inventory(self, inventory):
        """Prepare the original scope-filtered Dalfox inputs without another crawl."""
        import importlib.util
        import shutil
        spec = importlib.util.spec_from_file_location('xss_glue', self.script.parent / 'glue.py')
        glue = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(glue)
        self.run = self.project / 'runs' / 'shared'
        (self.run / 'input').mkdir(parents=True)
        for name in ('origins.txt', 'seeds.txt', 'exclude.txt'):
            shutil.copyfile(self.project / name, self.run / 'input' / name)
        from SQLi.sqli_scanner import _build_get_url
        # GET forms may never have been navigated to by the crawler. Preserve
        # their actual input names/values for Dalfox's injection stage.
        supplied = list(inventory.urls)
        for target in inventory.targets:
            if target.method.upper() == 'GET':
                supplied.append(_build_get_url(target.url, target.params))
        unique = list(dict.fromkeys(supplied))
        from scan_safety import Limits
        urls = '\n'.join(unique) + '\n'
        (self.project / 'coverage.json').write_text(json.dumps({
            'supplied_urls': len(set(supplied)),
            'get_form_targets': sum(t.method.upper() == 'GET' and bool(t.params) for t in inventory.targets),
            'post_targets_not_imported': sum(t.method.upper() != 'GET' for t in inventory.targets),
        }))
        (self.run / 'input' / 'urls.txt').write_text(urls)
        (self.run / 'supplied.txt').write_text(urls)
        glue.prepare(self.run)
        glue.filter_urls(self.run, self.run / 'supplied.txt', self.run / 'allowed.txt')
        allowed = self.urls()
        limited = allowed[:Limits.load().targets or None]
        (self.run / 'allowed.txt').write_text('\n'.join(limited) + ('\n' if limited else ''))
        coverage_path = self.project / 'coverage.json'
        coverage = json.loads(coverage_path.read_text())
        coverage.update(supplied_urls=len(limited), discovered_urls=len(unique),
                        limited_urls=len(allowed) - len(limited))
        coverage_path.write_text(json.dumps(coverage))
        glue.split(self.run)
        (self.run / 'recon.complete').touch()
        if inventory.session.cookies:
            # Dalfox's supported raw-request cookie import avoids credentials in argv.
            cookie = cookie_header(inventory.session.cookies, self.url)
            request = self.project / 'session.http'
            request.write_text(f'GET / HTTP/1.1\r\nCookie: {cookie}\r\n\r\n')
            request.chmod(0o600)

        if inventory.session.headers:
            config = self.project / 'session.config.json'
            config.write_text(json.dumps({'scan': {'headers': [f'{k}: {v}' for k, v in inventory.session.headers.items()]}}))
            config.chmod(0o600)
