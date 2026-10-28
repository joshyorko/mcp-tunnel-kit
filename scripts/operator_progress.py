"""Flushed stderr progress for bounded, potentially slow operator operations."""
import sys
import threading
import time


def emit(message):
    print(message, file=sys.stderr, flush=True)


def run_phase(label, operation, *args, heartbeat_interval=15, **kwargs):
    started = time.monotonic()
    finished = threading.Event()
    emit(label + '...')

    def heartbeat():
        while not finished.wait(heartbeat_interval):
            emit(f'{label}: still working ({time.monotonic() - started:.0f}s)')

    worker = threading.Thread(target=heartbeat, daemon=True)
    worker.start()
    failed = True
    try:
        result = operation(*args, **kwargs)
        failed = False
        return result
    finally:
        finished.set()
        worker.join()
        state = 'failed' if failed else 'done'
        emit(f'{label}: {state} ({time.monotonic() - started:.1f}s)')
