import os
import asyncio
import fcntl
from pathlib import Path
from contextlib import asynccontextmanager
from SQLi.sqlmap_client import SqlmapClient


@asynccontextmanager
async def engine_slot():
    # Both interfaces in this checkout share the local sqlmap API port.
    path = Path(__file__).resolve().parent / '.scan-engine.lock'
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                await asyncio.sleep(0.25)
        yield
    finally:
        os.close(fd)


async def scan_queued_job(job, *, sqlmap_factory=None, sqlmap_dir=None):
    from scan_safety import use_profile
    from target_headers import use_target_headers
    import json
    with use_profile(job.get('profile', 'bounty')), use_target_headers(job['url'], json.loads(job.get('headers', '{}'))):
        async with engine_slot():
            return await _scan_queued_job(job, sqlmap_factory or SqlmapClient, sqlmap_dir or os.environ.get("SQLMAP_DIR", "/usr/share/sqlmap"))


async def _scan_queued_job(job, sqlmap_factory, sqlmap_dir):
    if job['mode'] == 'watch':
        from site_watch import scan_watch
        import json
        return await scan_watch(job['url'], json.loads(job.get('headers', '{}')))
    from scan_pipeline import run_pipeline, run_single
    import json
    a, pa, b, pb = json.loads(job['credentials'])
    url, mode = job['url'], job['mode']
    async def scan(client):
        if mode == 'sqli_check':
            target, _, body = url.partition('\0')
            return {'sqli': await run_single(target, body, (a, pa), client)}
        return await run_pipeline(url, mode.removesuffix('_check'), [(a, pa), (b, pb)], client,
                                  single=mode.endswith('_check'))
    if mode in ('sqli', 'sqli_check', 'all'):
        from contextlib import AsyncExitStack
        async with AsyncExitStack() as stack:
            try:
                client = await stack.enter_async_context(sqlmap_factory(sqlmap_dir=sqlmap_dir))
            except Exception:
                if mode != 'all':
                    raise
                client = None
            return await scan(client)
    return await scan(None)

