"""Circuit breaker (SPEC §12): after `failures` consecutive failures a model is skipped ("open") for
`reset_s` seconds; then ONE trial call is let through ("half_open"). Trial success closes the
breaker, trial failure re-opens it for another `reset_s`.

One breaker per model lives in `firewall/llm.py`. No awaits inside, so it is safe to share
between asyncio tasks; a lock also makes it safe across threads.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Literal

BreakerState = Literal["closed", "open", "half_open"]


class CircuitBreaker:
    def __init__(self, failures: int = 5, reset_s: float = 60.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.failure_threshold = max(1, int(failures))
        self.reset_s = float(reset_s)
        self._clock = clock
        self._lock = threading.Lock()
        self._state: BreakerState = "closed"
        self._consecutive = 0
        self._opened_at: float | None = None
        self._trial_started: float | None = None   # half-open trial in flight since

    # ---- queries ----
    @property
    def state(self) -> BreakerState:
        with self._lock:
            return self._current(self._clock())

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive

    def retry_in(self) -> float:
        """Seconds until an open breaker half-opens (0 when not open)."""
        with self._lock:
            if self._state != "open" or self._opened_at is None:
                return 0.0
            return max(0.0, self._opened_at + self.reset_s - self._clock())

    def snapshot(self) -> dict:
        return {"state": self.state, "consecutive_failures": self._consecutive,
                "retry_in_s": round(self.retry_in(), 1)}

    # ---- transitions ----
    def allow(self) -> bool:
        """May a call go through now? In half_open only one trial call is allowed at a time."""
        with self._lock:
            now = self._clock()
            state = self._current(now)
            if state == "closed":
                return True
            if state == "open":
                return False
            self._state = "half_open"
            # A trial that never reported back (crash/cancel without release) goes stale after reset_s.
            if self._trial_started is not None and now - self._trial_started < self.reset_s:
                return False
            self._trial_started = now
            return True

    def release(self) -> None:
        """Give back a half-open trial slot claimed by allow() when no call was actually made."""
        with self._lock:
            self._trial_started = None

    def record_success(self) -> None:
        with self._lock:
            self._state = "closed"
            self._consecutive = 0
            self._opened_at = None
            self._trial_started = None

    def record_failure(self) -> None:
        with self._lock:
            now = self._clock()
            state = self._current(now)
            self._consecutive += 1
            if state == "half_open":            # the trial failed: open again for reset_s
                self._open(now)
            elif state == "closed" and self._consecutive >= self.failure_threshold:
                self._open(now)
            # already open: a straggler that started before opening; don't extend the open period

    # ---- internals ----
    def _current(self, now: float) -> BreakerState:
        if self._state == "open" and self._opened_at is not None and now - self._opened_at >= self.reset_s:
            return "half_open"
        return self._state

    def _open(self, now: float) -> None:
        self._state = "open"
        self._opened_at = now
        self._trial_started = None


__all__ = ["CircuitBreaker", "BreakerState"]
