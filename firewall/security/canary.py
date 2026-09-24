"""Canary tokens (SPEC §14): random markers planted in a (victim) system prompt. If one shows up in a
tool argument or a reply, exfiltration is proven. Format: CNRY-<16 hex>. DLP detects both registered
canaries and anything in the canonical format.
"""
from __future__ import annotations

import re
import secrets
import threading

CANARY_RE = re.compile(r"\bCNRY-[0-9a-f]{16}\b")


class CanaryRegistry:
    def __init__(self) -> None:
        self._tokens: set[str] = set()
        self._lock = threading.Lock()

    def new(self) -> str:
        token = "CNRY-" + secrets.token_hex(8)
        with self._lock:
            self._tokens.add(token)
        return token

    def add(self, token: str) -> None:
        with self._lock:
            self._tokens.add(token)

    def all(self) -> set[str]:
        with self._lock:
            return set(self._tokens)

    def found_in(self, text: str) -> list[str]:
        hits = {m.group(0) for m in CANARY_RE.finditer(text)}
        hits |= {t for t in self.all() if t in text}
        return sorted(hits)


REGISTRY = CanaryRegistry()
