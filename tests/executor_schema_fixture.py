"""Loopback schema adapter for disposable pinned-Executor acceptance only."""
import asyncio
from contextlib import contextmanager
import importlib.util
from pathlib import Path
import threading

from aiohttp import web


@contextmanager
def schema_adapter(upstream):
    path = Path(__file__).resolve().parents[1] / "scripts/executor_schema_proxy.py"
    spec = importlib.util.spec_from_file_location("schema_adapter_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    runner = None
    port = 0

    async def start():
        nonlocal runner, port
        runner = web.AppRunner(module.create_app(upstream), access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", port)
        await site.start()
        port = runner.addresses[0][1]

    def run(operation):
        return asyncio.run_coroutine_threadsafe(operation, loop).result(timeout=30)

    def restart():
        run(runner.cleanup())
        run(start())

    try:
        run(start())
        yield f"http://127.0.0.1:{port}", restart
    finally:
        if runner is not None:
            run(runner.cleanup())
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        loop.close()
