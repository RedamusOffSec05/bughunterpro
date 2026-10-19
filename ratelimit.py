#!/usr/bin/env python3
"""Thread-safe token bucket for BugHunterPro rate limiting."""

import threading
import time


class TokenBucket:
    """
    Thread-safe token bucket.

    rate     : tokens refilled per second
    capacity : maximum tokens (burst ceiling)
    """

    def __init__(self, rate: float, capacity: float):
        self.rate     = float(rate)
        self.capacity = float(capacity)
        self._tokens  = float(capacity)
        self._ts      = time.monotonic()
        self._lock    = threading.Lock()

    def _refill(self):
        now = time.monotonic()
        self._tokens = min(self.capacity, self._tokens + (now - self._ts) * self.rate)
        self._ts = now

    def try_acquire(self, tokens: float = 1.0) -> bool:
        """Return True and consume tokens, or return False immediately."""
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def acquire(self, tokens: float = 1.0):
        """Block until tokens are available, then consume them."""
        while not self.try_acquire(tokens):
            time.sleep(1.0 / self.rate)
