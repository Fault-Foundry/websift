#!/usr/bin/env python3
import argparse
import asyncio
import getpass
import json
import os
from pathlib import Path
import signal
import sys
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent


def parser():
    root = argparse.ArgumentParser(description='WebSift — CLI без Telegram')
    root.add_argument('--queue-dir', default=os.environ.get('CLI_QUEUE_DIR', str(BASE / 'cli_queue_data')),
                      help='каталог CLI-очереди (перед подкомандой)')
    sub = root.add_subparsers(dest='command', required=True)
    scan = sub.add_parser('scan', help='проверить URL/файл или добавить пакет в очередь')
    scan.add_argument('urls', nargs='*')
    scan.add_argument('--file', type=Path)
    scan.add_argument('--mode', choices=['exposure', 'all', 'sqli', 'xss', 'idor', 'sqli_check', 'xss_check', 'idor_check'], default='all')
    scan.add_argument('--profile', choices=['fast', 'bounty'], default='bounty')
    scan.add_argument('--enqueue', action='store_true', help='только сохранить пакет для отдельного worker')
    scan.add_argument('--data-file', type=Path, help='тело POST для одной цели sqli_check')
    auth = scan.add_mutually_exclusive_group()
    auth.add_argument('--auth', action='store_true', help='интерактивный ввод логинов/паролей')
    auth.add_argument('--defaults', action='store_true', help='DEFAULT_USER/PASS_A/B из .env')
    auth.add_argument('--credentials-file', type=Path, help='JSON-массив [userA,passA,userB,passB]')
    watch = sub.add_parser('watch', help='управление наблюдением (bounty)')
    watch.add_argument('action', choices=['add', 'list', 'pause', 'resume', 'remove'])
    watch.add_argument('targets', nargs='*', help='URL для add, ID для управления')
    watch.add_argument('--file', type=Path)
    sub.add_parser('queue', help='последние десять пакетов')
    worker = sub.add_parser('worker', help='обслуживать сохранённую очередь')
    worker.add_argument('--once', action='store_true', help='завершиться, когда очередь обработана/приостановлена')
    for name in ('pause', 'resume', 'cancel', 'report'):
        item = sub.add_parser(name)
        item.add_argument('batch')
    return root


def credentials(args):
    if args.credentials_file:
        result = json.loads(args.credentials_file.read_text())
    elif args.defaults:
        result = [os.environ.get(key, '') for key in ('DEFAULT_USER_A', 'DEFAULT_PASS_A', 'DEFAULT_USER_B', 'DEFAULT_PASS_B')]
    elif args.auth:
        result = [input('Логин A: '), getpass.getpass('Пароль A: '), '', '']
        if args.mode in ('all', 'idor', 'idor_check'):
            result[2:] = [input('Логин B (Enter — пропустить): '), getpass.getpass('Пароль B: ')]
    else:
        result = ['', '', '', '']
    if not isinstance(result, list) or len(result) != 4 or not all(isinstance(x, str) for x in result):
        raise ValueError('Файл аккаунтов должен содержать массив из четырёх строк.')
    if any(bool(result[i]) != bool(result[i+1]) for i in (0, 2)):
        raise ValueError('Для каждого аккаунта нужны и логин, и пароль.')
    return result


def export_reports(store, directory, *, batch=None, pending=False):
    """Publish complete artifacts before acknowledging delivery; safe to repeat."""
    from scan_pipeline import format_results
    rows = store.db.execute("SELECT id,batch,url,mode,profile,report FROM jobs WHERE status='done' AND owner=0 AND chat=0 AND (? IS NULL OR batch=?) AND (?=0 OR sent>=0) ORDER BY id",
                            (batch, batch, int(pending))).fetchall()
    for row in rows:
        dest = Path(directory) / 'reports' / row['batch']
        dest.mkdir(parents=True, exist_ok=True, mode=0o700)
        report = json.loads(row['report'])
        url = row['url'].split('\0', 1)[0]
        text = format_results(url, report)
        payload = {key: row[key] for key in ('id', 'batch', 'mode', 'profile')}
        payload.update(url=url, results=report)
        for suffix, content in (('json', json.dumps(payload, ensure_ascii=False, indent=2)), ('txt', text)):
            path = dest / f"{row['id']}.{suffix}"
            temporary = path.with_suffix('.' + suffix + '.tmp')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as out:
                out.write(content + '\n')
            os.replace(temporary, path)
        print(f"[{row['batch']}/{row['id']}] {row['profile']}\n{text}\nОтчёты: {dest}", flush=True)
        if pending:
            with store.db:
                store.db.execute('UPDATE jobs SET sent=-1 WHERE id=?', (row['id'],))
    return len(rows)


async def run_worker(store, directory, *, batch=None, once=False):
    from site_watch import settings
    settings()
    from durable_queue import QueueWorker
    from scan_runner import scan_queued_job
    from scan_pipeline import format_results
    async def unused_send(*args):
        raise RuntimeError('CLI does not use Telegram delivery')
    worker = QueueWorker(store, scan_queued_job, unused_send, {0}, format_results)
    async def export_loop():
        while True:
            export_reports(store, directory, batch=batch, pending=True)
            await asyncio.sleep(0.25)
    work = asyncio.create_task(worker.work(batch=batch, stop_when_idle=once))
    export = asyncio.create_task(export_loop())
    loop = asyncio.get_running_loop()
    parent = asyncio.current_task()
    loop.add_signal_handler(signal.SIGTERM, parent.cancel)
    try:
        done, _ = await asyncio.wait([work, export], return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        export_reports(store, directory, batch=batch, pending=True)
    finally:
        work.cancel()
        export.cancel()
        await asyncio.gather(work, export, return_exceptions=True)
        loop.remove_signal_handler(signal.SIGTERM)


def main(argv=None):
    load_dotenv(BASE / '.env')
    args = parser().parse_args(argv)
    from durable_queue import QueueStore
    owns_worker = args.command == 'worker' or (args.command == 'scan' and not args.enqueue)
    store = None
    try:
        store = QueueStore(args.queue_dir, worker=owns_worker, expected_owner=0)
        if store.db.execute('SELECT 1 FROM jobs WHERE owner!=0 OR chat!=0 LIMIT 1').fetchone():
            raise ValueError('Это очередь Telegram. Используйте отдельный --queue-dir для CLI.')
        if args.command == 'watch':
            if args.action == 'add':
                from target_headers import parse_lines
                urls = args.targets + (parse_lines(args.file.read_text(encoding='utf-8-sig')) if args.file else [])
                print(f'Наблюдений сохранено: {store.watches.add(0, 0, urls)} (bounty)')
            elif args.action == 'list':
                for row in store.watches.rows(0, 0):
                    print(f"{row['id']} · {'on' if row['enabled'] else 'paused'} · {row['url']} · {row['last_error']}")
            else:
                if len(args.targets) != 1:
                    raise ValueError('Укажите один ID наблюдения.')
                print(f'Обновлено: {store.watches.control(args.targets[0], 0, 0, args.action)}')
            return 0
        if args.command in ('pause', 'resume', 'cancel'):
            count = store.control(args.batch, 0, 0, args.command)
            print(f'Обновлено целей: {count}')
            return 0 if count else 1
        if args.command == 'queue':
            rows = store.status(0, 0)
            print('\n'.join(f"{r['batch']} [{r['profile']}]: {r['status']} — {r['count']}" for r in rows) or 'Очередь пуста.')
            return 0
        if args.command == 'report':
            return 0 if export_reports(store, args.queue_dir, batch=args.batch) else 1
        from scan_safety import Limits, use_profile, number
        from SQLi.options import SQLiOptions
        for profile in ('fast', 'bounty'):
            with use_profile(profile):
                Limits.load()
        SQLiOptions.load()
        number('RECON_MAX_DEPTH', 3, 0, 100, int)
        batch = None
        if args.command == 'scan':
            urls = list(args.urls)
            if args.file:
                from target_headers import parse_lines
                urls += parse_lines(args.file.read_text(encoding='utf-8-sig'))
            if args.data_file:
                if args.mode != 'sqli_check' or len(urls) != 1:
                    raise ValueError('--data-file требует sqli_check и один URL.')
                urls[0] += '\0' + args.data_file.read_text()
            batch, count = store.enqueue(0, 0, urls, args.mode, credentials(args), args.profile)
            print(f'Пакет {batch}: {count} целей, профиль {args.profile}', flush=True)
            if args.mode == 'all' and args.profile == 'bounty':
                print('Цели сохранены для наблюдения. Для расписания оставьте запущенным cli.py worker.', flush=True)
            if args.enqueue:
                return 0
        asyncio.run(run_worker(store, args.queue_dir, batch=batch,
                               once=args.command == 'scan' or args.once))
        if batch:
            rows = store.db.execute('SELECT status,report FROM jobs WHERE batch=?', (batch,)).fetchall()
            if any(r['status'] != 'done' or any(v['status'] in ('error', 'incomplete') for v in json.loads(r['report']).values()) for r in rows):
                return 1
        return 0
    except (KeyboardInterrupt, asyncio.CancelledError):
        print('Остановлено. Незавершённые цели сохранены в очереди.', file=sys.stderr)
        return 130
    except (ValueError, OSError, RuntimeError) as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        return 2
    finally:
        if store:
            store.close()


if __name__ == '__main__':
    raise SystemExit(main())
