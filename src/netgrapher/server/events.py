"""Event bus between the discovery engine (a plain thread) and WebSocket clients (asyncio).

Publishing is thread-safe. A client that falls too far behind gets its queue replaced by a
single "resync" event and reloads the full project.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

QUEUE_SIZE = 2000


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[asyncio.Queue[dict[str, Any]], asyncio.AbstractEventLoop] = {}
        self._lock = threading.Lock()

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        """Call from within the event loop that will consume the queue."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=QUEUE_SIZE)
        with self._lock:
            self._subscribers[queue] = asyncio.get_running_loop()
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            self._subscribers.pop(queue, None)

    def publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            targets = list(self._subscribers.items())
        for queue, loop in targets:
            try:
                loop.call_soon_threadsafe(_offer, queue, event)
            except RuntimeError:  # loop closed
                self.unsubscribe(queue)


def _offer(queue: asyncio.Queue[dict[str, Any]], event: dict[str, Any]) -> None:
    if queue.full():
        while not queue.empty():
            queue.get_nowait()
        queue.put_nowait({"type": "resync"})
        return
    queue.put_nowait(event)
