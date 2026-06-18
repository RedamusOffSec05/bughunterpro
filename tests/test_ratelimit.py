"""Tests for ratelimit.TokenBucket."""

import time

import pytest

from ratelimit import TokenBucket


class TestTokenBucket:
    def test_initial_acquire_succeeds(self):
        bucket = TokenBucket(rate=10, capacity=10)
        assert bucket.try_acquire() is True

    def test_depleted_bucket_fails(self):
        bucket = TokenBucket(rate=1, capacity=3)
        for _ in range(3):
            bucket.try_acquire()
        assert bucket.try_acquire() is False

    def test_refills_over_time(self):
        bucket = TokenBucket(rate=100, capacity=1)
        bucket.try_acquire()                   # deplete
        time.sleep(0.05)                       # wait for refill at 100/s
        assert bucket.try_acquire() is True

    def test_does_not_exceed_capacity(self):
        bucket = TokenBucket(rate=1000, capacity=5)
        time.sleep(0.1)                        # would add 100 tokens at rate=1000
        # but capacity caps at 5
        count = 0
        while bucket.try_acquire():
            count += 1
        assert count == 5

    def test_acquire_blocks_briefly(self):
        bucket = TokenBucket(rate=100, capacity=1)
        bucket.try_acquire()                   # deplete
        start = time.monotonic()
        bucket.acquire()                       # should block ~0.01s
        elapsed = time.monotonic() - start
        assert elapsed >= 0.005               # at least half the expected wait

    def test_fractional_tokens(self):
        bucket = TokenBucket(rate=10, capacity=10)
        assert bucket.try_acquire(tokens=5.0) is True
        assert bucket.try_acquire(tokens=5.0) is True
        assert bucket.try_acquire(tokens=1.0) is False

    def test_thread_safety(self):
        import threading
        bucket = TokenBucket(rate=0.01, capacity=100)
        acquired = []
        lock = threading.Lock()

        def worker():
            if bucket.try_acquire():
                with lock:
                    acquired.append(1)

        threads = [threading.Thread(target=worker) for _ in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(acquired) <= 100
