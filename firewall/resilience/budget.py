"""Per-model quota guards (SPEC §12): an RPM limiter and a daily request budget.

Free-tier Gemini quotas are per project and per model; requests-per-day reset at midnight Pacific.
Set RPM_LIMITS / DAILY_BUDGETS to ~80% of the numbers in the AI Studio dashboard.

RateLimiter = token bucket (capacity = rpm, refill rpm/60 per second) plus, by default, a rolling
60 s window that never admits more than `rpm` requests in any minute. A pure bucket admits a full
burst and then keeps refilling, i.e. up to 2 x rpm in the first minute, which is exactly the kind
of overshoot that earns a 429 (and a pinned eval run would then pause).
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import secrets
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, time as dtime, timedelta, timezone
from pathlib import Path
from typing import Literal
from zoneinfo import ZoneInfo

log = logging.getLogger(__name__)

PACIFIC = ZoneInfo("America/Los_Angeles")
WINDOW_S = 60.0
QuotaKind = Literal["rpm", "daily"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def next_reset_utc(now: datetime | None = None) -> datetime:
    """Next midnight America/Los_Angeles (when free-tier RPD resets), as an aware UTC datetime.
    A naive `now` is taken to be UTC."""
    now = now or _utcnow()
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    local = now.astimezone(PACIFIC)
    midnight = datetime.combine(local.date() + timedelta(days=1), dtime(0, 0), tzinfo=PACIFIC)
    return midnight.astimezone(timezone.utc)


def pacific_day(now: datetime | None = None) -> str:
    """The quota day (YYYY-MM-DD in America/Los_Angeles) that `now` falls in."""
    now = now or _utcnow()
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(PACIFIC).date().isoformat()


class QuotaExceeded(Exception):
    """A pinned call can't proceed because the model's quota is used up. Batch runs pause on it."""

    def __init__(self, model: str, kind: QuotaKind, resume_after: datetime | None = None) -> None:
        super().__init__(model, kind, resume_after)
        self.model = model
        self.kind = kind
        self.resume_after = resume_after

    def __str__(self) -> str:
        when = self.resume_after.isoformat() if self.resume_after else "unknown"
        return f"{self.kind} quota exhausted for {self.model}; resume after {when}"


# ---------------- RPM limiter ----------------

@dataclass
class _Bucket:
    tokens: float
    last: float
    cooldown_until: float = -math.inf
    probe_after_cooldown: bool = False
    stamps: deque[float] = field(default_factory=deque)   # admission times inside the window


class RateLimiter:
    """Per-model token bucket (+ rolling-window guard). `clock` / `sleep` are injectable for tests."""

    def __init__(self, rpm_for: Callable[[str], int], clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], Awaitable[object]] = asyncio.sleep, *,
                 strict_window: bool = True) -> None:
        self._rpm_for = rpm_for
        self._clock = clock
        self._sleep = sleep
        self.strict_window = strict_window
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def try_acquire(self, model: str) -> bool:
        with self._lock:
            now = self._clock()
            b, cap = self._refill(model, now)
            if now < b.cooldown_until or b.tokens < 1.0:
                return False
            if self.strict_window and len(b.stamps) >= cap:
                return False
            b.tokens -= 1.0
            if self.strict_window:
                b.stamps.append(now)
            return True

    async def acquire(self, model: str, timeout: float) -> bool:
        """Wait up to `timeout` seconds for a token. Returns False at once if none can arrive in time."""
        deadline = self._clock() + max(0.0, timeout)
        for _ in range(10_000):   # guard against a clock that never advances
            if self.try_acquire(model):
                return True
            wait = self.next_available_in(model)
            remaining = deadline - self._clock()
            if math.isinf(wait) or wait > remaining:
                return False
            await self._sleep(wait + 1e-6)   # tiny epsilon so float rounding can't make us spin
        return False

    def cooldown(self, model: str, seconds: float) -> None:
        """After a 429: no tokens for `seconds`; then one probe token and a normal refill."""
        with self._lock:
            now = self._clock()
            b, _ = self._refill(model, now)
            b.tokens = 0.0
            b.cooldown_until = max(b.cooldown_until, now + max(0.0, seconds))
            b.probe_after_cooldown = True

    def next_available_in(self, model: str) -> float:
        """Seconds until try_acquire could succeed (0 = now, inf = never, e.g. rpm 0)."""
        with self._lock:
            now = self._clock()
            b, cap = self._refill(model, now)
            if cap <= 0:
                return math.inf
            rate = cap / 60.0
            if now < b.cooldown_until:
                token_wait = b.cooldown_until - now      # a probe token is granted when it ends
            elif b.tokens >= 1.0:
                token_wait = 0.0
            else:
                token_wait = (1.0 - b.tokens) / rate
            window_wait = 0.0
            if self.strict_window and len(b.stamps) >= cap:
                window_wait = b.stamps[len(b.stamps) - cap] + WINDOW_S - now
            return max(0.0, token_wait, window_wait)

    def available(self, model: str) -> float:
        """Tokens available right now (for stats)."""
        with self._lock:
            now = self._clock()
            b, cap = self._refill(model, now)
            if now < b.cooldown_until:
                return 0.0
            if self.strict_window:
                return float(max(0.0, min(b.tokens, cap - len(b.stamps))))
            return float(b.tokens)

    def _refill(self, model: str, now: float) -> tuple[_Bucket, int]:
        cap = max(0, int(self._rpm_for(model)))
        b = self._buckets.get(model)
        if b is None:
            b = self._buckets[model] = _Bucket(tokens=float(cap), last=now)
        rate = cap / 60.0
        if now >= b.cooldown_until:
            if b.probe_after_cooldown:
                b.probe_after_cooldown = False
                b.tokens = min(float(cap), 1.0 + (now - b.cooldown_until) * rate) if cap else 0.0
                b.last = now
            elif now > b.last:
                b.tokens = min(float(cap), b.tokens + (now - b.last) * rate)
                b.last = now
        while b.stamps and b.stamps[0] <= now - WINDOW_S:
            b.stamps.popleft()
        return b, cap


# ---------------- daily budget ----------------

class DailyBudget:
    """Requests per model per Pacific day, persisted to `path_dir/budget-<YYYY-MM-DD>.json`.

    Each consume() re-reads the file (so an eval CLI and the API process see each other's usage,
    roughly) and writes it back atomically (temp file + os.replace).
    """

    def __init__(self, budget_for: Callable[[str], int], path_dir: Path | str,
                 now: Callable[[], datetime] = _utcnow) -> None:
        self._budget_for = budget_for
        self._dir = Path(path_dir)
        self._now = now
        self._lock = threading.Lock()
        self._day: str | None = None
        self._used: dict[str, int] = {}

    def path_for(self, day: str) -> Path:
        return self._dir / f"budget-{day}.json"

    def day(self) -> str:
        return pacific_day(self._now())

    def remaining(self, model: str) -> int:
        with self._lock:
            self._sync()
            return max(0, int(self._budget_for(model)) - self._used.get(model, 0))

    def consume(self, model: str) -> bool:
        """Count one request against today's budget; False (and no increment) when exhausted."""
        with self._lock:
            day = self._sync()
            self._merge_disk(day)
            if int(self._budget_for(model)) - self._used.get(model, 0) <= 0:
                return False
            self._used[model] = self._used.get(model, 0) + 1
            self._save(day)
            return True

    def exhaust(self, model: str) -> None:
        """Mark a model's budget as used up for today (e.g. Google returned a per-day 429)."""
        with self._lock:
            day = self._sync()
            self._merge_disk(day)
            self._used[model] = max(self._used.get(model, 0), int(self._budget_for(model)))
            self._save(day)

    def snapshot(self) -> dict[str, dict]:
        with self._lock:
            self._sync()
            out = {}
            for model, used in sorted(self._used.items()):
                budget = int(self._budget_for(model))
                out[model] = {"used": used, "budget": budget, "remaining": max(0, budget - used)}
            return out

    # ---- internals ----
    def _sync(self) -> str:
        day = self.day()
        if day != self._day:        # new Pacific day (or first use): start from what's on disk
            self._day = day
            self._used = self._load(day)
        return day

    def _merge_disk(self, day: str) -> None:
        for model, used in self._load(day).items():
            if used > self._used.get(model, 0):
                self._used[model] = used

    def _load(self, day: str) -> dict[str, int]:
        path = self.path_for(day)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            log.warning("unreadable budget file %s (%s); counting from memory", path, e)
            return {}
        used = data.get("used", {}) if isinstance(data, dict) else {}
        if not isinstance(used, dict):
            return {}
        return {str(k): v for k, v in used.items() if isinstance(v, int) and not isinstance(v, bool) and v >= 0}

    def _save(self, day: str) -> None:
        path = self.path_for(day)
        payload = {"day": day, "tz": "America/Los_Angeles", "used": self._used,
                   "updated_at": _utcnow().isoformat()}
        try:
            atomic_write_text(path, json.dumps(payload, indent=1, sort_keys=True))
        except OSError as e:   # never fail an LLM call because the counter couldn't be persisted
            log.warning("could not persist budget file %s: %s", path, e)


def atomic_write_text(path: Path, text: str) -> None:
    """Write via a temp file in the same directory + fsync + os.replace (no torn files)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


__all__ = ["QuotaExceeded", "RateLimiter", "DailyBudget", "next_reset_utc", "pacific_day",
           "atomic_write_text", "PACIFIC"]
