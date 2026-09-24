"""Data-loss-prevention scan (SPEC §7.2 DLP).

This is **not** an injection signal. It reports whether recognizable secrets / PII are *present*
(``sensitive_data_present``), used by the gate's SDE floor, the log redactor and the egress guard.
Detectors are linear-time and case-sensitive where the token format is (keys, PAN).

    KINDS
    find(text, canaries=()) -> [{"kind", "start", "end"}]   # sorted by start, non-overlapping
    scan(text, canaries=()) -> [str]                        # sorted unique kinds
    verhoeff_valid(number) -> bool
"""
from __future__ import annotations

from typing import Iterable

import regex

from firewall.security.canary import CANARY_RE, REGISTRY

KINDS = (
    "openai_key",
    "aws_access_key",
    "github_token",
    "google_api_key",
    "jwt",
    "private_key",
    "aadhaar",
    "pan",
    "upi_id",
    "canary",
)

MAX_DLP_CHARS = 1_000_000

# Real UPI PSP handles (SPEC §7.2). Longest-first so the alternation prefers the full handle
# (e.g. "okicici" before "icici") since it is anchored right after '@'.
_UPI_PSPS = [
    "okhdfcbank", "unionbankofindia", "jupiteraxis", "barodampay", "wahdfcbank",
    "timecosmos", "freecharge", "abfspay", "waicici", "yesbank", "idfcbank",
    "axisbank", "pingpay", "okaxis", "okicici", "hdfcbank", "waaxis", "indus",
    "kotak", "oksbi", "paytm", "cnrb", "ikwik", "wasbi", "barodampay",
    "ybl", "ibl", "axl", "apl", "upi", "sbi", "pnb", "boi", "fbl", "rbl",
    "icici",
]
# Deduplicate while preserving longest-first order.
_UPI_PSPS = sorted(dict.fromkeys(_UPI_PSPS), key=len, reverse=True)

# --- format detectors (case-sensitive; no IGNORECASE) ---
_DETECTORS: list[tuple[str, "regex.Pattern"]] = [
    ("openai_key", regex.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("aws_access_key", regex.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", regex.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("google_api_key", regex.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", regex.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")),
    ("private_key", regex.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    # PAN: 5 letters (4th = holder type), 4 digits, 1 letter. Word-bounded, uppercase only.
    ("pan", regex.compile(r"\b[A-Z]{3}[ABCFGHLJPTKE][A-Z][0-9]{4}[A-Z]\b")),
    ("upi_id", regex.compile(r"\b[A-Za-z0-9][A-Za-z0-9.\-_]{1,}@(?:" + "|".join(_UPI_PSPS) + r")(?![\w.])")),
]
# Aadhaar candidate: 12 digits (first 2-9), optionally grouped 4-4-4. Verhoeff-validated below.
_AADHAAR_RE = regex.compile(r"\b[2-9][0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}\b")


# ---- Verhoeff checksum (standard d / p / inv tables) ----
_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_valid(number: str) -> bool:
    """True iff ``number`` (digits, optional spaces/hyphens) passes the Verhoeff checksum."""
    digits = [c for c in number if c.isdigit()]
    if not digits:
        return False
    c = 0
    for i, d in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(d)]]
    return c == 0


def _find_all(text: str, token: str) -> list[tuple[int, int]]:
    """Every non-overlapping literal occurrence of ``token`` in ``text``."""
    spans: list[tuple[int, int]] = []
    if not token:
        return spans
    start = 0
    while True:
        idx = text.find(token, start)
        if idx == -1:
            break
        spans.append((idx, idx + len(token)))
        start = idx + len(token)
    return spans


def find(text: str, canaries: Iterable[str] = ()) -> list[dict]:
    """All DLP hits as ``[{"kind", "start", "end"}]`` sorted by start, non-overlapping
    (longest wins on overlap)."""
    text = text[:MAX_DLP_CHARS]
    raw: list[tuple[int, int, str]] = []

    for kind, rx in _DETECTORS:
        for m in rx.finditer(text):
            raw.append((m.start(), m.end(), kind))

    for m in _AADHAAR_RE.finditer(text):
        if verhoeff_valid(m.group(0)):
            raw.append((m.start(), m.end(), "aadhaar"))

    # canaries: canonical format + registered tokens + caller-supplied tokens
    for m in CANARY_RE.finditer(text):
        raw.append((m.start(), m.end(), "canary"))
    tokens = set(canaries) | REGISTRY.all()
    for token in tokens:
        for s, e in _find_all(text, token):
            raw.append((s, e, "canary"))

    # resolve overlaps: longest wins (then earliest, then by KINDS order for stability)
    kind_rank = {k: i for i, k in enumerate(KINDS)}
    raw.sort(key=lambda r: (-(r[1] - r[0]), r[0], kind_rank.get(r[2], 99)))
    kept: list[tuple[int, int, str]] = []
    for s, e, kind in raw:
        if any(s < ke and ks < e for ks, ke, _ in kept):
            continue
        kept.append((s, e, kind))

    kept.sort(key=lambda r: (r[0], r[1]))
    return [{"kind": k, "start": s, "end": e} for s, e, k in kept]


def scan(text: str, canaries: Iterable[str] = ()) -> list[str]:
    """Sorted unique DLP kinds present in ``text``."""
    return sorted({hit["kind"] for hit in find(text, canaries)})


__all__ = ["KINDS", "find", "scan", "verhoeff_valid"]
