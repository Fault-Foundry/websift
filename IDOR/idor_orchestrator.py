"""Standalone entry point using the same session/discovery pipeline as the bot."""
import argparse
import asyncio
import json
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from shared_recon import ReconService, authenticate
from IDOR.idor_detector import scan_inventories


async def run(args):
    service = ReconService(args.url, args.recon_mode, args.max_pages, args.max_depth)
    sessions = [await authenticate(args.url, label, user, password) for label, user, password in
                [('A', args.user_a, args.pass_a), ('B', args.user_b, args.pass_b)]]
    inventories = [await service.discover(s) for s in sessions]
    report = await scan_inventories(inventories, args.request_delay)
    if any(i.status != 'completed' for i in inventories):
        report['status'] = 'incomplete'
        report['errors'].extend(e for i in inventories for e in i.errors)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    for arg in ('user-a', 'pass-a', 'user-b', 'pass-b'):
        parser.add_argument('--' + arg, required=True)
    parser.add_argument('--recon-mode', choices=['http', 'js', 'browser'], default='http')
    parser.add_argument('--max-pages', type=int, default=50)
    parser.add_argument('--max-depth', type=int, default=3)
    parser.add_argument('--request-delay', type=float, default=0.5)
    parser.add_argument('--json-out')
    args = parser.parse_args()
    try:
        report = asyncio.run(run(args))
    except Exception as exc:
        report = {'status': 'error', 'errors': [str(exc)], 'findings': []}
    text = json.dumps(report, ensure_ascii=False, indent=2)
    print(text)
    if args.json_out:
        Path(args.json_out).write_text(text)
    return 0 if report['status'] in ('completed', 'skipped') else 2


if __name__ == '__main__':
    raise SystemExit(main())
