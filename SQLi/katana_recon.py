"""Compatibility adapter. New callers should use shared_recon.ReconService."""
async def run_katana(url, cookies=None, depth=3, timeout=120.0, katana_bin='katana'):
    from shared_recon import ReconService, Session
    from SQLi.sqli_scanner import ReconTarget
    from urllib.parse import urlsplit
    service = ReconService(url, 'js', max_depth=depth)
    urls = await service._katana(Session('legacy', cookies or {}), timeout=timeout, binary=katana_bin)
    return [ReconTarget(url=u, cookies=cookies) for u in urls if urlsplit(u).query]
