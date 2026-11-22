"""Асинхронный клиент REST API sqlmap. Управляет процессом sqlmapapi.py и его задачами."""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


class SqlmapAPIError(Exception):
    """Ошибка при взаимодействии с sqlmapapi."""


@dataclass
class SqlmapTarget:
    url: str
    method: str = "GET"
    data: Optional[str] = None          # тело запроса как строка (sqlmap сам это ждёт)
    cookie: Optional[str] = None        # "name1=value1; name2=value2"
    headers: dict[str, str] = field(default_factory=dict)

    # опции агрессивности/обхода WAF — заполняются модулем profile.py,
    # но можно передать и вручную
    level: int = 1
    risk: int = 1
    tamper: Optional[str] = None        # "space2comment,randomcase"
    random_agent: bool = True
    delay: float = 0
    test_parameter: Optional[str] = None  # "id" или "id,foo" — сузить тест, не трогать остальные поля
    techniques: Optional[str] = None
    time_sec: Optional[int] = None        # секунды SLEEP() для time-based техник (sqlmap default: 5)


class SqlmapClient:
    """
    Использование:

        async with SqlmapClient(sqlmap_dir="/usr/share/sqlmap") as client:
            result = await client.scan(target, timeout=180)

    sqlmap_dir — папка, где лежат sqlmap.py и sqlmapapi.py (например /usr/share/sqlmap
    для Kali/apt-установки, или путь к клонированному репозиторию).
    Можно передать и sqlmap_py_path (путь к sqlmap.py) — папка будет вычислена из него,
    для обратной совместимости.
    """

    def __init__(
        self,
        sqlmap_dir: Optional[str] = None,
        sqlmap_py_path: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 8775,
        python_bin: str = "python3",
        startup_timeout: float = 15.0,
        poll_interval: float = 2.0,
    ):
        if sqlmap_dir is None:
            if sqlmap_py_path is None:
                raise ValueError("Нужно передать либо sqlmap_dir, либо sqlmap_py_path")
            sqlmap_dir = os.path.dirname(os.path.abspath(sqlmap_py_path))

        self.sqlmap_dir = sqlmap_dir
        self.sqlmapapi_py_path = os.path.join(sqlmap_dir, "sqlmapapi.py")

        self.host = host
        self.port = port
        self.python_bin = python_bin
        self.base_url = f"http://{host}:{port}"
        self.startup_timeout = startup_timeout
        self.poll_interval = poll_interval

        self._process: Optional[asyncio.subprocess.Process] = None
        self._http: Optional[httpx.AsyncClient] = None
        self._pump_tasks: list[asyncio.Task] = []
        self._stdout_lines: list[str] = []
        self._stderr_lines: list[str] = []

    async def _pump_stream(self, stream: asyncio.StreamReader, lines_buf: list[str], prefix: str) -> None:
        """Постоянно вычитывает поток процесса, чтобы пайп не переполнился и не заблокировал sqlmapapi."""
        while True:
            line = await stream.readline()
            if not line:
                break
            text = line.decode(errors="ignore").rstrip()
            logger.debug("[sqlmapapi %s] %s", prefix, text)
            lines_buf.append(text)
            if len(lines_buf) > 200:
                lines_buf.pop(0)


    async def __aenter__(self) -> "SqlmapClient":
        await self.start_server()
        return self

    async def __aexit__(self, *exc):
        await self.stop_server()

    async def start_server(self) -> None:
        if not os.path.exists(self.sqlmapapi_py_path):
            raise SqlmapAPIError(
                f"sqlmapapi.py не найден по пути {self.sqlmapapi_py_path}. "
                f"Проверьте, что sqlmap_dir указывает на папку, где лежат и sqlmap.py, и sqlmapapi.py."
            )

        logger.info("Starting sqlmapapi.py server on %s:%s", self.host, self.port)
        self._process = await asyncio.create_subprocess_exec(
            self.python_bin, self.sqlmapapi_py_path,
            "-s", "-H", self.host, "-p", str(self.port),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._http = httpx.AsyncClient(base_url=self.base_url, timeout=30)
        self._stdout_lines = []
        self._stderr_lines = []
        self._pump_tasks = [
            asyncio.create_task(self._pump_stream(self._process.stdout, self._stdout_lines, "stdout")),
            asyncio.create_task(self._pump_stream(self._process.stderr, self._stderr_lines, "stderr")),
        ]

        deadline = asyncio.get_event_loop().time() + self.startup_timeout
        while asyncio.get_event_loop().time() < deadline:
            if self._process.returncode is not None:
                detail = "\n".join(self._stderr_lines[-20:]) or "\n".join(self._stdout_lines[-20:])
                raise SqlmapAPIError(
                    f"sqlmapapi процесс завершился раньше времени: {detail}"
                )
            try:
                resp = await self._http.get("/task/new")
                if resp.status_code == 200:
                    logger.info("sqlmapapi готов")
                    return
            except httpx.TransportError:
                pass
            await asyncio.sleep(0.5)

        await self.stop_server()
        raise SqlmapAPIError("sqlmapapi не поднялся за отведённое время")

    async def stop_server(self) -> None:
        if self._http:
            await self._http.aclose()
            self._http = None
        for task in self._pump_tasks:
            task.cancel()
        self._pump_tasks = []
        if self._process and self._process.returncode is None:
            logger.info("Останавливаю sqlmapapi процесс")
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._process.kill()
        self._process = None


    def _require_http(self) -> httpx.AsyncClient:
        if self._http is None:
            raise SqlmapAPIError("Клиент не запущен — используйте 'async with SqlmapClient(...)' или start_server()")
        return self._http

    async def new_task(self) -> str:
        resp = await self._require_http().get("/task/new")
        resp.raise_for_status()
        payload = resp.json()
        if not payload.get("success"):
            raise SqlmapAPIError(f"Не удалось создать task: {payload}")
        return payload["taskid"]

    async def delete_task(self, task_id: str) -> None:
        resp = await self._require_http().get(f"/task/{task_id}/delete")
        resp.raise_for_status()

    async def set_option(self, task_id: str, option: str, value: Any) -> None:
        resp = await self._require_http().post(
            f"/option/{task_id}/set", json={option: value}
        )
        resp.raise_for_status()

    async def start_scan(self, task_id: str, target: SqlmapTarget) -> None:
        from scan_safety import Limits, check_safety, engine_pause
        check_safety()
        await engine_pause()
        from .options import SQLiOptions, techniques
        options = SQLiOptions.load()
        if not 1 <= target.level <= 5 or not 1 <= target.risk <= 3:
            raise SqlmapAPIError('SQLi level must be 1..5 and risk 1..3')
        opts: dict[str, Any] = {
            "url": target.url,
            "method": target.method,
            "level": target.level,
            "risk": target.risk,
            "randomAgent": target.random_agent,
            "delay": max(target.delay, Limits.load().interval),
            "threads": 1,
            "retries": 0,
            "timeout": 10,
            "technique": techniques(target.techniques if target.techniques is not None else options.techniques),
            "ignoreRedirects": True,
            "skipWaf": True,
        }
        if target.data:
            opts["data"] = target.data
        if target.cookie:
            opts["cookie"] = target.cookie
        if any(k.lower() == 'user-agent' for k in target.headers):
            opts['randomAgent'] = False
            opts['agent'] = next(v for k, v in target.headers.items() if k.lower() == 'user-agent')
        if target.headers:
            # API options travel through an INI file. A single header without
            # a separator is iterated character-by-character by sqlmap.
            # Literal backslash-n survives INI trimming, including at the end.
            if any('\r' in str(x) or '\n' in str(x) for pair in target.headers.items() for x in pair):
                raise SqlmapAPIError('Недопустимый перевод строки в HTTP-заголовке')
            opts["headers"] = "\\n".join(f"{k}: {v}" for k, v in target.headers.items()) + "\\n"
        if target.tamper:
            opts["tamper"] = target.tamper
        if target.test_parameter:
            opts["testParameter"] = target.test_parameter
        opts["timeSec"] = target.time_sec if target.time_sec is not None else options.time_sec

        resp = await self._require_http().post(f"/scan/{task_id}/start", json=opts)
        resp.raise_for_status()
        payload = resp.json()
        if not payload.get("success"):
            raise SqlmapAPIError(f"Не удалось запустить скан: {payload}")

    async def get_status(self, task_id: str) -> str:
        resp = await self._require_http().get(f"/scan/{task_id}/status")
        resp.raise_for_status()
        payload = resp.json()
        if not payload.get('success', True):
            raise SqlmapAPIError('sqlmap API не смог получить статус проверки')
        if payload.get('returncode') not in (None, 0):
            raise SqlmapAPIError(f"sqlmap завершился с кодом {payload['returncode']}; проверка неполная")
        status = payload.get('status')
        if status not in ('running', 'terminated'):
            raise SqlmapAPIError('sqlmap вернул неожиданный статус; проверка неполная')
        return status

    async def get_data(self, task_id: str) -> list[dict]:
        resp = await self._require_http().get(f"/scan/{task_id}/data")
        resp.raise_for_status()
        payload = resp.json()
        if not payload.get('success', True) or payload.get('error'):
            # Engine errors can contain credentials and response bodies.
            raise SqlmapAPIError('sqlmap сообщил об ошибке выполнения; это не результат «уязвимостей нет». Подробности доступны в журнале sqlmap API.')
        return payload.get('data', [])

    async def stop_scan(self, task_id: str) -> None:
        resp = await self._require_http().get(f"/scan/{task_id}/stop")
        resp.raise_for_status()


    async def scan(self, target: SqlmapTarget, timeout: float = 300.0) -> tuple[list[dict], bool]:
        """Возвращает список находок и признак остановки по таймауту."""
        task_id = await self.new_task()
        timed_out = False
        try:
            await self.start_scan(task_id, target)

            deadline = asyncio.get_event_loop().time() + timeout
            while True:
                status = await self.get_status(task_id)
                if status != "running":
                    break
                if asyncio.get_event_loop().time() > deadline:
                    await self.stop_scan(task_id)
                    timed_out = True
                    logger.warning("Скан %s превысил таймаут %.0fs, остановлен", target.url, timeout)
                    break
                await asyncio.sleep(self.poll_interval)

            result = await self.get_data(task_id)
            from scan_safety import engine_pause
            await engine_pause()
            return result, timed_out
        finally:
            # Cancellation of the outer scan must also stop the engine task.
            try:
                await self.stop_scan(task_id)
            finally:
                await self.delete_task(task_id)
