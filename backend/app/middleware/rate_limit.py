"""Small in-memory sliding-window rate limiter.

Limitation (documented in the README): counters live in memory, so they reset when the server
restarts and are not shared between several server processes. Production would use Redis.
"""
import threading
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self):
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, window: float, now: float) -> deque:
        events = self._events.setdefault(key, deque())
        while events and now - events[0] >= window:
            events.popleft()
        if not events:
            self._events.pop(key, None)
            events = self._events.setdefault(key, deque())
        return events

    def retry_after(self, key: str, limit: int, window: float) -> int:
        """Seconds to wait if `key` already used up `limit` events in `window`, else 0."""
        now = time.monotonic()
        with self._lock:
            events = self._prune(key, window, now)
            if len(events) >= limit:
                return max(1, int(window - (now - events[0])) + 1)
            return 0

    def record(self, key: str, window: float) -> None:
        now = time.monotonic()
        with self._lock:
            self._prune(key, window, now).append(now)

    def clear(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
