"""Telegram-бот для запуска проверок SQLi, IDOR и XSS через aiogram 3."""

from __future__ import annotations

import asyncio
import logging
import os

from aiogram import BaseMiddleware, Bot, Dispatcher, F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import Document, Message, ForceReply
from dotenv import load_dotenv

from pathlib import Path

from SQLi.sqlmap_client import SqlmapClient

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Каталог с sqlmap.py и sqlmapapi.py.
SQLMAP_DIR = os.environ.get("SQLMAP_DIR", "/usr/share/sqlmap")

DEFAULT_USER_A = os.environ.get("DEFAULT_USER_A", "")
DEFAULT_PASS_A = os.environ.get("DEFAULT_PASS_A", "")
DEFAULT_USER_B = os.environ.get("DEFAULT_USER_B", "")
DEFAULT_PASS_B = os.environ.get("DEFAULT_PASS_B", "")

router = Router()


def parse_allowed_users(value: str) -> frozenset[int]:
    parts = [part.strip() for part in value.split(',')]
    if not parts or any(not part.isascii() or not part.isdigit() or int(part) <= 0 for part in parts):
        raise ValueError('Укажите ALLOWED_TELEGRAM_USER_IDS в .env: положительные числовые ID через запятую.')
    return frozenset(map(int, parts))


class AccessMiddleware(BaseMiddleware):
    """Gate every update before routing, including future callback handlers."""
    def __init__(self, allowed_users):
        self.allowed_users = frozenset(allowed_users)

    async def __call__(self, handler, event, data):
        message = event.message
        callback = event.callback_query
        user = callback.from_user if callback else (message.from_user if message else None)
        chat = callback.message.chat if callback and callback.message else (message.chat if message else None)
        if (user is None or user.is_bot or user.id not in self.allowed_users
                or chat is None or chat.type not in ('private', 'group', 'supergroup')
                or (message is not None and message.sender_chat is not None)):
            if callback:
                await callback.answer('Доступ закрыт.', show_alert=True)
            return None
        return await handler(event, data)


class ScanStates(StatesGroup):
    waiting_for_targets = State()
    waiting_for_profile = State()
    waiting_for_creds = State()


@router.message(Command("start"))
async def start(message: Message) -> None:
    await message.answer(
        "Проверка сайтов на уязвимости.\n\n"
        "/all — начать проверку сайта или списка\n"
        "/queue — состояние проверок\n"
        "/help — остальные возможности\n\n"
        "Для старта отправь /all, затем ссылку или .txt со списком сайтов."
    )


@router.message(Command("help"))
async def help_command(message: Message) -> None:
    await message.answer(
        "Выбери раздел:\n\n"
        "/modes — виды сканирования и профили\n"
        "/quick — проверка одной страницы или запроса\n"
        "/queue_help — управление проверками\n"
        "/watch_help — наблюдение за изменениями сайтов"
    )


@router.message(Command("modes"))
async def modes(message: Message) -> None:
    await message.answer(
        "Виды сканирования:\n\n"
        "/all — все сканеры\n"
        "/sqli — SQL-инъекции\n"
        "/xss — XSS\n"
        "/idor — сравнение доступа между аккаунтами\n"
        "/exposure — открытые конфиги, Git-файлы и дампы\n\n"
        "После команды отправь URL или .txt со списком целей и выбери профиль:\n"
        "fast — разовая проверка своего стенда;\n"
        "bounty — более длинные паузы между запросами. В /all цели также "
        "сохраняются для наблюдения.\n\n"
        "Для IDOR нужны два аккаунта. Для анонимного запуска отправь - "
        "на запрос аккаунтов. /exposure работает без входа."
    )


@router.message(Command("quick"))
async def quick_help(message: Message) -> None:
    await message.answer(
        "Проверки без обхода сайта:\n\n"
        "/sqli_check <url> [тело POST] — SQLi одной точки\n"
        "/xss_check <url> — XSS одной страницы\n"
        "/idor_check <url> — доступ к одному URL под A/B и без входа\n\n"
        "Для IDOR нужны два аккаунта; одинаковый ответ не доказывает нарушение прав.\n"
        "При передаче учётных данных вход может обращаться к другим страницам.\n"
        "На запрос аккаунтов отправь - (анонимно), defaults (из настроек) "
        "или user:pass (для IDOR: user1:pass1 user2:pass2)."
    )


@router.message(Command("queue_help"))
async def queue_help(message: Message) -> None:
    await message.answer(
        "Управление проверками:\n\n"
        "/queue — состояние и номера пакетов\n"
        "/pause <пакет> — приостановить\n"
        "/resume <пакет> — продолжить\n"
        "/cancel <пакет> — отменить\n\n"
        "Эти команды управляют отдельным пакетом. "
        "Чтобы остановить будущие обходы сайта, используй /watch_help."
    )


@router.message(Command("watch_help"))
async def watch_help(message: Message) -> None:
    from site_watch import settings
    interval, full = settings()
    await message.answer(
        "Наблюдение за изменениями:\n\n"
        "После /all с профилем bounty список сохраняется автоматически. "
        "Повторно отправлять его не нужно.\n"
        f"Katana обходит сайты каждые {interval / 3600:g} ч. "
        "Изменения запускают полную проверку; без изменений работает Exposure Watch. "
        f"Полная проверка также запускается раз в {full / 86400:g} дн.\n\n"
        "/watch_list — сайты и их ID\n"
        "/watch_pause <ID> — приостановить наблюдение\n"
        "/watch_resume <ID> — возобновить\n"
        "/watch_remove <ID> — удалить из наблюдения\n\n"
        "Бот должен оставаться запущенным. Последующие проверки выполняются без входа."
    )


@router.message(Command('queue', 'pause', 'resume', 'cancel'))
async def queue_command(message: Message) -> None:
    if queue_worker is None:
        await message.answer('Очередь ещё не готова.')
        return
    parts = message.text.split()
    action = parts[0].split('@')[0].lstrip('/')
    if action == 'queue':
        rows = queue_worker.store.status(message.from_user.id, message.chat.id)
        labels = {'queued': 'ожидает', 'running': 'работает', 'paused': 'пауза',
                  'done': 'обработано', 'cancelled': 'отменено'}
        await message.answer('\n'.join(f"{r['batch']} ({r['profile']}): {labels[r['status']]} — {r['count']}" for r in rows)
                             or 'Очередь пуста.')
    elif len(parts) != 2:
        await message.answer(f'Использование: /{action} <номер пакета из /queue>')
    else:
        count = await queue_worker.control(parts[1], message.from_user.id, message.chat.id, action)
        await message.answer(f'Обновлено целей: {count}.')


@router.message(Command('watch_list', 'watch_pause', 'watch_resume', 'watch_remove'))
async def watch_control(message: Message) -> None:
    if queue_worker is None:
        await message.answer('Очередь ещё не готова.')
        return
    parts = message.text.split()
    action = parts[0].split('@')[0].removeprefix('/watch_')
    watches = queue_worker.store.watches
    if action == 'list':
        rows = watches.rows(message.from_user.id, message.chat.id)
        lines = [f"{r['id']} · {'включено' if r['enabled'] else 'пауза'} · {r['url']}" +
                 (f" · {r['last_error']}" if r['last_error'] else '') for r in rows]
        for chunk in split_msg('\n'.join(lines) or 'Наблюдений нет.'):
            await message.answer(chunk)
    elif len(parts) != 2:
        await message.answer(f'Использование: /watch_{action} <ID из /watch_list>')
    else:
        count = watches.control(parts[1], message.from_user.id, message.chat.id, action)
        await message.answer(f'Обновлено наблюдений: {count}.')


@router.message(Command("xss_check", "idor_check"))
async def handle_quick_command(message: Message, state: FSMContext) -> None:
    from shared_recon import origin
    parts = message.text.strip().split()
    mode = parts[0].lstrip('/').split('@', 1)[0]
    if len(parts) != 2:
        await message.answer(f"Использование: /{mode} <url>")
        return
    try:
        origin(parts[1])
    except ValueError:
        await message.answer("Нужен один корректный HTTP(S) URL.")
        return
    await save_urls_and_ask_creds(message, state, mode, [parts[1]])


@router.message(Command("sqli_check"))
async def handle_sqli_check_command(message: Message, state: FSMContext) -> None:
    """
    /sqli_check <url> [тело] — явный режим одной точки, без краулинга остального сайта.
    Метод определяется сам: есть текст после URL -> POST с этим телом, иначе -> GET.
    """
    parts = message.text.strip().split(maxsplit=2)
    if len(parts) < 2:
        await message.answer(
            "Использование:\n"
            "/sqli_check <url> — одна GET-цель (например с ?id=1)\n"
            "/sqli_check <url> <тело POST> — например: /sqli_check http://site.com/login.php username=test&password=test"
        )
        return
    url = parts[1]
    body = parts[2] if len(parts) > 2 else ""
    # Кодируем url и body одной строкой через разделитель, который не встретится в URL/теле запроса
    combined = f"{url}\x00{body}"
    await save_urls_and_ask_creds(message, state, "sqli_check", [combined])


@router.message(Command("sqli", "idor", "xss", "exposure", "all", "watch"))
async def handle_mode_command(message: Message, state: FSMContext) -> None:
    text = message.text.strip()
    parts = text.split(maxsplit=1)
    mode = parts[0].lstrip("/").split("@", 1)[0]

    if len(parts) > 1:
        url = parts[1].strip()
        await save_urls_and_ask_creds(message, state, mode, [url])
        return

    await state.set_state(ScanStates.waiting_for_targets)
    await state.update_data(mode=mode)
    await message.reply(f"Режим: {mode}. Ответь на это сообщение ссылкой или .txt файлом.",
                         reply_markup=ForceReply(selective=True))


async def save_urls_and_ask_creds(message: Message, state: FSMContext, mode: str, urls: list[str]) -> None:
    from target_headers import parse_lines
    try:
        urls = parse_lines('\n'.join(urls))
    except ValueError as exc:
        await message.answer(str(exc))
        return
    if mode == 'watch':
        if queue_worker is None:
            await message.answer('Очередь ещё не готова.')
            return
        try:
            count = queue_worker.store.watches.add(message.from_user.id, message.chat.id, urls)
        except ValueError as exc:
            await message.answer(str(exc))
            return
        await state.clear()
        from site_watch import settings
        hours = settings()[0] / 3600
        await message.answer(f'Наблюдение сохранено: {count} целей. Профиль bounty, обход каждые {hours:g} ч. /watch_list — список.')
        return
    await state.update_data(mode=mode, urls=urls)
    await state.set_state(ScanStates.waiting_for_profile)
    await message.reply(
        f'Целей: {len(urls)}. Выбери профиль для всего пакета:\n'
        'fast — быстрый, для своего стенда (пауза 0,1 с по умолчанию);\n'
        'bounty — для багбаунти (пауза от 1 с); /all также сохраняет цели для наблюдения.\n'
        'Набор проверок одинаковый. Ответь fast или bounty.',
        reply_markup=ForceReply(selective=True))


@router.message(ScanStates.waiting_for_profile, F.text)
async def choose_profile(message: Message, state: FSMContext) -> None:
    profile = message.text.strip().lower()
    if profile not in ('fast', 'bounty'):
        await message.reply('Выбери fast или bounty.', reply_markup=ForceReply(selective=True))
        return
    await state.update_data(profile=profile)
    data = await state.get_data()
    if data.get('mode') == 'exposure':
        await state.clear()
        await enqueue_scan(message, data, ['', '', '', ''])
        return
    await state.set_state(ScanStates.waiting_for_creds)
    await message.reply(
        f'Профиль: {profile}. Отправь - для анонимной проверки, defaults для аккаунтов из настроек,\n'
        'или user:pass (для IDOR: user1:pass1 user2:pass2).',
        reply_markup=ForceReply(selective=True))


# Обработчики текста и документов регистрируются до общего обработчика.
@router.message(ScanStates.waiting_for_targets, F.document)
async def handle_state_document(message: Message, state: FSMContext, bot: Bot) -> None:
    document: Document = message.document
    if not document.file_name or not document.file_name.endswith(".txt"):
        await message.answer("Ошибка: ожидается `.txt` файл.")
        return

    file_info = await bot.get_file(document.file_id)
    file_io = await bot.download_file(file_info.file_path)
    content = file_io.getvalue().decode("utf-8-sig", errors="replace")
    urls = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]

    if not urls:
        await message.answer("Ошибка: файл пустой.")
        return

    data = await state.get_data()
    mode = data.get("mode", "all")
    await save_urls_and_ask_creds(message, state, mode, urls)


@router.message(ScanStates.waiting_for_targets, F.text)
async def handle_state_text(message: Message, state: FSMContext) -> None:
    url = message.text.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        await message.answer("Ошибка: неверный формат URL (должен начинаться с http:// или https://).")
        return

    data = await state.get_data()
    mode = data.get("mode", "all")
    await save_urls_and_ask_creds(message, state, mode, [url])


@router.message(ScanStates.waiting_for_targets)
async def handle_unexpected_input(message: Message) -> None:
    await message.answer("Ошибка: отправь текстовую ссылку или `.txt` файл.")


@router.message(ScanStates.waiting_for_creds, F.text)
async def handle_creds_input(message: Message, state: FSMContext, bot: Bot) -> None:
    text = message.text.strip()
    data = await state.get_data()
    urls = data.get("urls", [])
    mode = data.get("mode", "all")
    await state.clear()

    user_a, pass_a = DEFAULT_USER_A, DEFAULT_PASS_A
    user_b, pass_b = DEFAULT_USER_B, DEFAULT_PASS_B

    if text == "-":
        user_a = pass_a = user_b = pass_b = ""
    elif text != "defaults":
        parts = text.split()
        if len(parts) >= 1 and ":" in parts[0]:
            user_a, pass_a = parts[0].split(":", 1)
        if len(parts) >= 2 and ":" in parts[1]:
            user_b, pass_b = parts[1].split(":", 1)

    await enqueue_scan(message, data, [user_a, pass_a, user_b, pass_b])


async def enqueue_scan(message, data, credentials):
    urls = data.get('urls', [])
    mode = data.get('mode', 'all')
    if queue_worker is None:
        await message.answer('Очередь ещё не готова.')
        return
    try:
        batch, count = queue_worker.store.enqueue(message.from_user.id, message.chat.id, urls, mode,
                                                   credentials, profile=data.get('profile', 'bounty'))
    except ValueError:
        await message.answer('В списке есть некорректный HTTP(S) URL. Исправьте файл и загрузите заново.')
        return
    note = ''
    if mode == 'all' and data.get('profile', 'bounty') == 'bounty':
        note = '\nЦели также сохранены для наблюдения: повторно отправлять список не нужно. /watch_list — управление. Последующие проверки без входа.'
    await message.answer(f'Пакет {batch} сохранён: {count} уникальных целей. /queue — состояние.' + note)


queue_worker = None


async def scan_queued_job(job):
    from scan_runner import scan_queued_job as run
    return await run(job, sqlmap_factory=SqlmapClient, sqlmap_dir=SQLMAP_DIR)


def split_msg(text: str, limit: int = 4000) -> list[str]:
    chunks = []
    while text:
        chunks.append(text[:limit])
        text = text[limit:]
    return chunks or [""]


async def main() -> None:
    try:
        from site_watch import settings
        settings()
        from scan_safety import Limits
        Limits.load()
        from scan_safety import use_profile
        with use_profile('fast'):
            Limits.load()
        from SQLi.options import SQLiOptions
        SQLiOptions.load()
        from scan_safety import number
        number("RECON_MAX_DEPTH", 3, 0, 100, int)
        allowed_users = parse_allowed_users(os.environ.get('ALLOWED_TELEGRAM_USER_IDS', ''))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("TELEGRAM_BOT_TOKEN не задан в окружении или файле .env")

    sqlmapapi_path = os.path.join(SQLMAP_DIR, "sqlmapapi.py")
    if not os.path.exists(sqlmapapi_path):
        logger.warning(
            "sqlmapapi.py не найден по пути %s — команды /sqli и /all (SQLi-часть) не будут "
            "работать, пока SQLMAP_DIR не указывает на папку с sqlmap.py и sqlmapapi.py.",
            sqlmapapi_path,
        )

    bot = Bot(token=token)
    dp = Dispatcher()
    dp.update.outer_middleware(AccessMiddleware(allowed_users))
    dp.include_router(router)
    from durable_queue import QueueStore, QueueWorker
    from scan_pipeline import format_results
    global queue_worker
    store = QueueStore(os.environ.get('QUEUE_DIR', str(BASE_DIR / 'queue_data')))
    queue_worker = QueueWorker(store, scan_queued_job, bot.send_message, allowed_users, format_results)
    worker_task = asyncio.create_task(queue_worker.work())
    delivery_task = asyncio.create_task(queue_worker.deliver())
    polling_task = asyncio.create_task(dp.start_polling(bot, close_bot_session=False))
    try:
        finished, _ = await asyncio.wait([polling_task, worker_task, delivery_task],
                                         return_when=asyncio.FIRST_COMPLETED)
        for task in finished:
            task.result()
    finally:
        polling_task.cancel()
        worker_task.cancel()
        delivery_task.cancel()
        await asyncio.gather(polling_task, worker_task, delivery_task, return_exceptions=True)
        store.close()
        queue_worker = None
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
