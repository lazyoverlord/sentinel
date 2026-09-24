"""Disk caches (SPEC §12), both on diskcache (SQLite):

- DevCache: memoizes structured LLM results during development so re-running a test, the demo or
  an eval doesn't spend free-tier quota. Key = sha256(model, prompt_version, system, prompt, schema).
  Turned off for reliability runs (DEV_CACHE=false) and never used when temperature > 0.
- VerdictCache: final firewall verdicts for session-less requests, key = sha256(content hash +
  source + policy version), TTL 24 h. Also the demo safety net (pre-warm it with the demo inputs).

Values are stored as JSON text, never pickled, so a tampered cache directory can't execute code.
Both are no-ops when disabled (get -> None, set does nothing, no files are created).
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEV_CACHE_SIZE_LIMIT = 512 * 1024 * 1024
VERDICT_CACHE_SIZE_LIMIT = 256 * 1024 * 1024


def content_hash(data: bytes | str) -> str:
    """sha256 hex of the content (str is UTF-8 encoded first)."""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(data).hexdigest()


def _key(*parts: Any) -> str:
    blob = json.dumps([str(p) for p in parts], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8", errors="surrogatepass")).hexdigest()


class _JsonDiskCache:
    """Shared plumbing: lazily-imported diskcache, JSON values, safe no-op when disabled."""

    def __init__(self, directory: Path | str, *, enabled: bool, size_limit: int) -> None:
        self.directory = Path(directory)
        self.enabled = bool(enabled)
        self._cache = None
        if self.enabled:
            import diskcache
            self.directory.mkdir(parents=True, exist_ok=True)
            self._cache = diskcache.Cache(str(self.directory), size_limit=size_limit)

    def _raw_get(self, key: str) -> Any:
        if self._cache is None:
            return None
        try:
            raw = self._cache.get(key)
        except Exception as e:   # corrupted/locked DB: behave like a miss
            log.warning("cache read failed in %s: %s", self.directory, e)
            return None
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return None

    def _raw_set(self, key: str, value: Any, expire: float | None = None) -> None:
        if self._cache is None:
            return
        try:
            self._cache.set(key, json.dumps(value, ensure_ascii=False, default=str), expire=expire)
        except Exception as e:   # a cache must never break the request
            log.warning("cache write failed in %s: %s", self.directory, e)

    def delete(self, key: str) -> None:
        if self._cache is not None:
            try:
                self._cache.delete(key)
            except Exception:
                pass

    def clear(self) -> None:
        if self._cache is not None:
            self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache) if self._cache is not None else 0

    def close(self) -> None:
        if self._cache is not None:
            self._cache.close()
            self._cache = None

    def __enter__(self):
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class DevCache(_JsonDiskCache):
    def __init__(self, directory: Path | str, *, enabled: bool = True,
                 size_limit: int = DEV_CACHE_SIZE_LIMIT) -> None:
        super().__init__(directory, enabled=enabled, size_limit=size_limit)

    @staticmethod
    def make_key(model: str, prompt_version: str, system: str, prompt: str, schema_name: str) -> str:
        return _key("dev", model, prompt_version, system, prompt, schema_name)

    def get(self, key: str) -> dict | None:
        value = self._raw_get(key)
        return value if isinstance(value, dict) else None

    def set(self, key: str, value: dict) -> None:
        self._raw_set(key, value)


class VerdictCache(_JsonDiskCache):
    """TTL enforced twice: diskcache `expire` (culls old rows) and a stored timestamp checked
    against `clock` (injectable, so tests don't have to sleep)."""

    def __init__(self, directory: Path | str, *, ttl_s: float = 86400, enabled: bool = True,
                 clock: Callable[[], float] = time.time,
                 size_limit: int = VERDICT_CACHE_SIZE_LIMIT) -> None:
        super().__init__(directory, enabled=enabled, size_limit=size_limit)
        self.ttl_s = float(ttl_s)
        self._clock = clock
        self.hits = 0
        self.misses = 0

    @staticmethod
    def make_key(content_hash: str, source: str, policy_version: str) -> str:
        return _key("verdict", content_hash, source, policy_version)

    def get(self, key: str) -> dict | None:
        if self._cache is None:
            return None
        entry = self._raw_get(key)
        value = entry.get("value") if isinstance(entry, dict) else None
        stored_at = entry.get("stored_at") if isinstance(entry, dict) else None
        if (not isinstance(value, dict) or not isinstance(stored_at, (int, float))
                or self._clock() - stored_at > self.ttl_s):
            if entry is not None:
                self.delete(key)
            self.misses += 1
            return None
        self.hits += 1
        return value

    def set(self, key: str, value: dict) -> None:
        if self._cache is None:
            return
        self._raw_set(key, {"stored_at": self._clock(), "value": value},
                      expire=self.ttl_s if self.ttl_s > 0 else None)

    def clear(self) -> None:
        super().clear()
        self.hits = 0
        self.misses = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

    def stats(self) -> dict:
        return {"enabled": self.enabled, "entries": len(self), "hits": self.hits,
                "misses": self.misses, "hit_rate": round(self.hit_rate, 4), "ttl_s": self.ttl_s}


__all__ = ["DevCache", "VerdictCache", "content_hash"]
