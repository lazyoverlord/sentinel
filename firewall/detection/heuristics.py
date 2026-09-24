"""Rules engine (SPEC §7.2): regex patterns over (obfuscation-expanded) text.

Patterns live in ``data/patterns.json`` and are compiled once with the ``regex`` module
(flags ``IGNORECASE | V1``) with a per-match ``timeout=`` (ReDoS guard). Each match is tagged
``quoted`` per the use--mention rule so a security article that *quotes* an attack is reviewed but
not fast-blocked (SPEC §8, §22 row 9).

Public surface:
    CATEGORIES, CATEGORY_FLAGS
    Pattern (pydantic model, one per patterns.json entry)
    HeuristicEngine(patterns_path=None, *, timeout_s=0.05)
        .version .patterns .timeouts
        .scan(text, segment_id, variant_kind="original") -> list[HeuristicMatch]
        .reload()
        HeuristicEngine.H(matches) / .flags(matches) / .all_high_quoted(matches)
    quoted_regions(text) -> list[(start, end)]   # half-open, use--mention regions
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import regex
from pydantic import BaseModel

from firewall.config import ROOT
from firewall.schemas import HeuristicMatch

log = logging.getLogger(__name__)

# The 13 rule categories (SPEC §7.2). Order is stable for reporting.
CATEGORIES: tuple[str, ...] = (
    "instruction_override",
    "role_change",
    "secret_extraction",
    "tool_abuse",
    "credential_request",
    "exfiltration_channel",
    "role_marker_spoof",
    "fake_authority",
    "ai_manipulation_intent",
    "classifier_manipulation",
    "ai_addressed_imperative",
    "hindi_hinglish",
    "low_signal",
)

# Which categories raise which ensemble flag (SPEC §7.5). Only UNQUOTED matches set a flag
# (see flags()); quoted matches still count toward H.
CATEGORY_FLAGS: dict[str, str] = {
    "ai_manipulation_intent": "manip",
    "classifier_manipulation": "manip",
    "role_marker_spoof": "rolespoof",
    "exfiltration_channel": "exfil",
    "ai_addressed_imperative": "ai_imperative",
}

# Resource limits (SPEC §7.3 spirit): cap the scanned text and matches per pattern.
MAX_SCAN_CHARS = 200_000
MAX_MATCHES_PER_PATTERN = 20

# Use--mention: an unbalanced opener never runs past its paragraph (blank line) or this many chars.
_MAX_UNBALANCED = 2_000
_OPEN_BEFORE = {"(", "["}                       # straight ' opens only after these / whitespace / start
_CLOSE_AFTER = set(".,!?;:)]}\"'`»") | {"’"}  # straight ' closes only before these / whitespace / end
_PARA_BREAK = regex.compile(r"\n[ \t]*\n")
_COMPILE_FLAGS = regex.IGNORECASE | regex.V1


class Pattern(BaseModel):
    id: str
    category: str
    types: list[int]
    weight: float
    regex: str
    description: str
    example_positive: str
    example_negative: str


def _paragraph_bound(text: str, start: int) -> int:
    """End index for an unbalanced opener at ``start``: the earlier of the next blank line and a
    2,000-char cap (never past the end of the text)."""
    limit = min(start + _MAX_UNBALANCED, len(text))
    m = _PARA_BREAK.search(text, start, limit)
    return m.start() if m else limit


def quoted_regions(text: str) -> list[tuple[int, int]]:
    """Half-open [start, end) spans that count as *quoted* for the use--mention rule (SPEC §7.2):
    "double", curly double, 'curly single', «guillemets», `inline code`, ```fenced blocks```, and
    lines beginning with ``>`` (markdown blockquote). Straight single quotes open only at
    start / after whitespace / after ``(`` ``[`` and close only before whitespace / punctuation /
    end, so apostrophes in words like ``don't`` never open a region. A single left-to-right scan
    means regions never nest or overlap; an unbalanced opener is bounded by its paragraph."""
    n = len(text)
    regions: list[tuple[int, int]] = []
    i = 0
    while i < n:
        ch = text[i]

        # markdown blockquote: line start, up to 3 leading spaces, then '>' -> whole line.
        if i == 0 or text[i - 1] == "\n":
            j, spaces = i, 0
            while j < n and text[j] in " \t" and spaces < 3:
                j += 1
                spaces += 1
            if j < n and text[j] == ">":
                eol = text.find("\n", j)
                eol = n if eol == -1 else eol
                regions.append((i, eol))
                i = eol
                continue

        # fenced code block ```...```
        if text.startswith("```", i):
            close = text.find("```", i + 3)
            if close == -1:
                regions.append((i, _paragraph_bound(text, i)))
                break
            regions.append((i, close + 3))
            i = close + 3
            continue

        # inline backtick `...`
        if ch == "`":
            close = text.find("`", i + 1)
            if close == -1:
                regions.append((i, _paragraph_bound(text, i)))
                i += 1
                continue
            regions.append((i, close + 1))
            i = close + 1
            continue

        # paired quotes: straight double, curly double, curly single, guillemets
        closer = {'"': '"', "“": "”", "‘": "’", "«": "»"}.get(ch)
        if closer is not None:
            close = text.find(closer, i + 1)
            if close == -1:
                regions.append((i, _paragraph_bound(text, i)))
                i += 1
                continue
            regions.append((i, close + 1))
            i = close + 1
            continue

        # straight single quote: only a real opener (not an apostrophe)
        if ch == "'":
            prev = text[i - 1] if i > 0 else ""
            if i == 0 or prev.isspace() or prev in _OPEN_BEFORE:
                j = i + 1
                found = -1
                while True:
                    b = text.find("'", j)
                    if b == -1:
                        break
                    nxt = text[b + 1] if b + 1 < n else ""
                    if nxt == "" or nxt.isspace() or nxt in _CLOSE_AFTER:
                        found = b
                        break
                    j = b + 1
                if found != -1:
                    regions.append((i, found + 1))
                    i = found + 1
                    continue
                regions.append((i, _paragraph_bound(text, i)))
                i += 1
                continue

        i += 1

    return regions


def _is_quoted(span: tuple[int, int], regions: list[tuple[int, int]]) -> bool:
    s, e = span
    return any(rs <= s and e <= re for rs, re in regions)


class HeuristicEngine:
    """Loads and compiles patterns once; scans text into HeuristicMatch objects."""

    def __init__(self, patterns_path: Path | None = None, *, timeout_s: float = 0.05) -> None:
        self.patterns_path = Path(patterns_path) if patterns_path else (ROOT / "data" / "patterns.json")
        self.timeout_s = timeout_s
        self.timeouts = 0
        self.version: str = ""
        self.patterns: list[Pattern] = []
        self._compiled: list[tuple[Pattern, "regex.Pattern"]] = []
        self._load()

    def _load(self) -> None:
        raw = json.loads(self.patterns_path.read_text(encoding="utf-8"))
        version = raw.get("version", "")
        patterns: list[Pattern] = []
        compiled: list[tuple[Pattern, "regex.Pattern"]] = []
        seen: set[str] = set()
        for entry in raw.get("patterns", []):
            pat = Pattern(**entry)
            if pat.id in seen:
                raise ValueError(f"duplicate pattern id: {pat.id}")
            seen.add(pat.id)
            if pat.category not in CATEGORIES:
                raise ValueError(f"pattern {pat.id}: unknown category {pat.category!r}")
            for t in pat.types:
                if not 1 <= t <= 9:
                    raise ValueError(f"pattern {pat.id}: type {t} out of range 1-9")
            try:
                rx = regex.compile(pat.regex, _COMPILE_FLAGS)
            except regex.error as exc:
                raise ValueError(f"pattern {pat.id}: invalid regex: {exc}") from exc
            patterns.append(pat)
            compiled.append((pat, rx))
        self.version = version
        self.patterns = patterns
        self._compiled = compiled

    def reload(self) -> None:
        self._load()

    def scan(self, text: str, segment_id: str, variant_kind: str = "original") -> list[HeuristicMatch]:
        text = text[:MAX_SCAN_CHARS]
        regions = quoted_regions(text)
        out: list[HeuristicMatch] = []
        for pat, rx in self._compiled:
            try:
                count = 0
                for m in rx.finditer(text, timeout=self.timeout_s):
                    start, end = m.span()
                    if end == start:  # skip zero-width matches
                        continue
                    out.append(
                        HeuristicMatch(
                            pattern_id=pat.id,
                            category=pat.category,
                            types=list(pat.types),
                            weight=pat.weight,
                            segment_id=segment_id,
                            variant_kind=variant_kind,
                            span=(start, end),
                            text=m.group(0)[:200],
                            quoted=_is_quoted((start, end), regions),
                        )
                    )
                    count += 1
                    if count >= MAX_MATCHES_PER_PATTERN:
                        break
            except TimeoutError:
                self.timeouts += 1
                log.warning("regex timeout: pattern=%s (skipped for this text)", pat.id)
                continue
        return out

    # ---- aggregation helpers (SPEC §7.2 / §7.5) ----
    @staticmethod
    def H(matches: list[HeuristicMatch]) -> float:
        """Heuristic score = max weight over matches (0.0 if none). Quoted matches count."""
        return max((m.weight for m in matches), default=0.0)

    @staticmethod
    def flags(matches: list[HeuristicMatch]) -> set[str]:
        """manip / rolespoof / exfil / ai_imperative from UNQUOTED matches only (SPEC §7.2 decision:
        a quoted attack is reviewed but not fast-blocked by R3 or held by the floor)."""
        out: set[str] = set()
        for m in matches:
            if m.quoted:
                continue
            flag = CATEGORY_FLAGS.get(m.category)
            if flag:
                out.add(flag)
        return out

    @staticmethod
    def all_high_quoted(matches: list[HeuristicMatch]) -> bool:
        """True iff every match with weight >= 0.7 is quoted. False when there are no high matches
        (feeds gate R4: ``NOT all_high_matches_quoted``)."""
        highs = [m for m in matches if m.weight >= 0.7]
        if not highs:
            return False
        return all(m.quoted for m in highs)


__all__ = ["CATEGORIES", "CATEGORY_FLAGS", "Pattern", "HeuristicEngine", "quoted_regions"]
