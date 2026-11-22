#!/usr/bin/env python3
"""Offline URL/scope and report glue only. Network scanning belongs to tools."""
import csv
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit


def lines(p):
    return [v.strip() for v in p.read_text().splitlines() if v.strip() and not v.lstrip().startswith('#')]


def normalize(value):
    if any(ord(c) <= 32 or ord(c) >= 127 for c in value) or '\\' in value:
        raise ValueError('non-ASCII, whitespace or backslash')
    s = urlsplit(value)
    if s.scheme.lower() not in ('http', 'https') or not s.hostname or s.username is not None or s.password is not None:
        raise ValueError('invalid scheme/host or userinfo')
    host = s.hostname.lower()
    if not re.fullmatch(r'[a-z0-9.-]+', host) or host.endswith('.'):
        raise ValueError('unsupported hostname (use ASCII DNS or IPv4)')
    port = s.port
    authority = host if port is None or port == {'http': 80, 'https': 443}[s.scheme.lower()] else f'{host}:{port}'
    return urlunsplit((s.scheme.lower(), authority, s.path or '/', s.query, s.fragment))


def origin(u):
    s = urlsplit(u)
    return f'{s.scheme}://{s.netloc}'


def prepare(run):
    origins = sorted({origin(normalize(x)) for x in lines(run/'input/origins.txt')})
    if not origins:
        raise ValueError('origins.txt is empty')
    # origins.txt must contain complete origins, not path-restricted scope rules.
    for value in lines(run/'input/origins.txt'):
        s = urlsplit(normalize(value))
        if s.path != '/' or s.query or s.fragment:
            raise ValueError('origins.txt accepts origins only; put path restrictions in exclude.txt')
    scope = '^(?:' + '|'.join(re.escape(x) for x in origins) + ')(?:/|[?#]|$)'
    # Portable Go/Rust/Python regexes: no lookaround/backreferences.
    patterns = lines(run/'input/exclude.txt')
    patterns += [r'(?i:/(?:logout|signout|delete|remove|unsubscribe)(?:/|[?#]|$))']
    for p in patterns:
        re.compile(p)
    exclude = '|'.join('(?:' + x + ')' for x in patterns)
    (run/'scope.regex').write_text(scope + '\n')
    (run/'exclude.regex').write_text(exclude + '\n')
    (run/'origins.normalized.txt').write_text('\n'.join(origins)+'\n')
    (run/'hosts.txt').write_text('\n'.join(sorted({urlsplit(x).hostname for x in origins}))+'\n')
    seeds = lines(run/'input/seeds.txt') or [x+'/' for x in origins]
    (run/'seeds.txt').write_text('\n'.join(seeds)+'\n')


STATIC = re.compile(r'\.(?:png|jpe?g|gif|webp|avif|ico|woff2?|ttf|eot|mp[34]|avi|mov|pdf|zip|gz|tar|rar|7z|css)$', re.I)


def filter_urls(run, src, dst):
    allowed = set(lines(run/'origins.normalized.txt'))
    exclude = re.compile((run/'exclude.regex').read_text().strip())
    kept = set()
    with (run/'rejected.jsonl').open('a') as log:
        for raw in lines(src):
            reason = None
            try:
                u = normalize(raw)
                if origin(u) not in allowed:
                    reason = 'out_of_scope_origin'
                elif exclude.search(u) or exclude.search(unquote(u)):
                    reason = 'excluded'
                elif STATIC.search(unquote(urlsplit(u).path)):
                    reason = 'static_extension'
                else:
                    kept.add(u)
            except ValueError as e:
                reason = str(e)
            if reason:
                log.write(json.dumps({'url': raw, 'reason': reason})+'\n')
    dst.write_text(''.join(u+'\n' for u in sorted(kept)))


def split(run):
    urls = lines(run/'allowed.txt')
    # Preserve query values, repeated keys, empty values, and hash routes.
    query_targets = [u for u in urls if urlsplit(u).query]
    # Also allow HTML input-name mining on pages without a query string.
    reflected = urls
    (run/'query_targets.txt').write_text(''.join(u+'\n' for u in query_targets))
    (run/'reflected.txt').write_text(''.join(u+'\n' for u in reflected))
    (run/'dom.txt').write_text(''.join(u+'\n' for u in urls))
    with (run/'inputs.tsv').open('w', newline='') as f:
        w = csv.writer(f, delimiter='\t')
        w.writerow(['method', 'url', 'source', 'parameter'])
        for u in urls:
            s = urlsplit(u)
            if not s.query:
                w.writerow(['GET', u, 'page_for_input_name_mining', ''])
            for name, _ in parse_qsl(s.query, keep_blank_values=True):
                w.writerow(['GET', u, 'query', name])
            if s.fragment:
                w.writerow(['GET', u, 'fragment_for_browser_review', s.fragment])
    (run/'counts.json').write_text(json.dumps({'allowed': len(urls), 'reflected': len(reflected), 'dom': len(urls)}, indent=2)+'\n')


def report(run):
    buckets = {k: [] for k in ('strong_candidates', 'dom_candidates', 'reflections', 'other')}
    summaries = {}
    incomplete = False
    seen = set()
    for mode in ('reflected', 'dom'):
        try:
            data = json.loads((run/f'{mode}.json').read_text())
            if not isinstance(data.get('findings'), list) or not isinstance(data.get('meta'), dict):
                raise ValueError('unexpected Dalfox report schema')
            meta = data['meta']
            summaries[mode] = meta
            bad = meta.get('incomplete', False) or any(x.get('status') in ('skipped', 'incomplete') for x in meta.get('target_summary', []))
            incomplete |= bad
            for finding in data['findings']:
                key = json.dumps(finding, sort_keys=True)
                if key in seen:
                    continue
                seen.add(key)
                if finding.get('detection_method') == 'ast':
                    bucket = 'dom_candidates'
                elif finding.get('type') == 'V':
                    bucket = 'strong_candidates'
                elif finding.get('type') == 'R':
                    bucket = 'reflections'
                else:
                    bucket = 'other'
                buckets[bucket].append(finding)
        except (OSError, ValueError, TypeError) as e:
            incomplete = True
            summaries[mode] = {'error': str(e)}
        exitfile = run/f'{mode}.exit'
        if exitfile.exists() and int(exitfile.read_text()) > 1:
            incomplete = True
    for k, findings in buckets.items():
        (run/f'{k}.json').write_text(json.dumps(findings, indent=2)+'\n')
    (run/'metadata.json').write_text(json.dumps(summaries, indent=2)+'\n')
    text = ('Status: ' + ('INCOMPLETE (check metadata/logs)' if incomplete else 'COMPLETED') + '\n'
            + '\n'.join(f'{k}: {len(v)}' for k, v in buckets.items())
            + '\nBrowser-confirmed: NOT TESTED. Static candidates are not ready-made bounty reports.\n')
    (run/'summary.txt').write_text(text)
    if incomplete:
        raise SystemExit(3)


if __name__ == '__main__':
    command, directory, *args = sys.argv[1:]
    run = Path(directory)
    if command == 'prepare': prepare(run)
    elif command == 'filter': filter_urls(run, Path(args[0]), Path(args[1]))
    elif command == 'split': split(run)
    elif command == 'report': report(run)
    else: raise SystemExit('Unknown command')
