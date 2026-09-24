"""Evidence grounding (SPEC §8 after-review step 1).

The judge must quote its evidence verbatim from the DATA blocks. A quote that isn't really in the
segment it cites (hallucinated, or planted by an injection aimed at the judge) doesn't count:
"injection with no grounded evidence and not multi-step => suspicious".

Normalization, applied to both sides before comparing: datamarks -> spaces, neutralized
delimiters (‹ ›) -> < >, curly quotes/dashes -> ASCII, lowercase, invisible format characters
dropped, whitespace runs collapsed to one space. A quote is grounded iff its segment id exists,
it has >= 8 non-space characters, and rapidfuzz partial_ratio(quote, segment) >= min_score.
Quotes with an ellipsis ("…" / "...") are checked fragment by fragment.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from rapidfuzz import fuzz

from firewall.schemas import Evidence
from firewall.security.spotlight import CLOSE_LOOKALIKE, DATAMARK, OPEN_LOOKALIKE, strip_datamarks

MIN_QUOTE_CHARS = 8

_INVISIBLE = "­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f"
_GAP = re.compile(rf"[\s{_INVISIBLE}]+")
_ELLIPSIS = re.compile(r"…|\.{3,}")
# length-preserving 1:1 character mappings (keeps the index map for locate() trivial)
_STATIC_MAP = {
    ord(DATAMARK): " ", ord(OPEN_LOOKALIKE): "<", ord(CLOSE_LOOKALIKE): ">",
    0xFF1C: "<", 0xFF1E: ">",
    0x2018: "'", 0x2019: "'", 0x201A: "'", 0x201B: "'", 0x2032: "'",
    0x201C: '"', 0x201D: '"', 0x201E: '"', 0x201F: '"', 0x2033: '"', 0x00AB: '"', 0x00BB: '"',
    0x2010: "-", 0x2011: "-", 0x2012: "-", 0x2013: "-", 0x2014: "-", 0x2015: "-", 0x2212: "-",
}


def ground(evidence: Iterable[Any], segments: Mapping[str, str], *,
           min_score: int = 90) -> list[Evidence]:
    """Mark each judge quote grounded / not grounded against the segment it cites.

    `evidence` items may be JudgeEvidence / Evidence models or plain dicts with segment_id + quote.
    An unknown segment id is never grounded (other segments are not searched).
    """
    out: list[Evidence] = []
    normalized: dict[str, str] = {}
    for item in evidence or []:
        sid = _field(item, "segment_id")
        sid = "" if sid is None else str(sid)
        quote = str(_field(item, "quote") or "")
        grounded = False
        seg_text = segments.get(sid) if sid else None
        if seg_text is not None:
            if sid not in normalized:
                normalized[sid] = _normalize(seg_text)[0]
            grounded = _is_grounded(quote, normalized[sid], min_score)
        out.append(Evidence(segment_id=sid, quote=strip_datamarks(quote).strip(), grounded=grounded))
    return out


def grounded_count(evidence: Iterable[Evidence]) -> int:
    return sum(1 for e in evidence or [] if _field(e, "grounded") is True)


def locate(quote: str, segment_text: str, *, min_score: int = 90) -> tuple[int, int] | None:
    """Best-matching (start, end) span of `quote` in the ORIGINAL segment_text, or None.

    Uses rapidfuzz partial_ratio_alignment on normalized text, then maps the window back to
    original offsets. For an ellipsis quote, returns the span covering all located fragments.
    """
    seg_n, index = _normalize(segment_text or "")
    frags = _fragments(quote)
    if not seg_n or not frags or sum(_nonspace(f) for f in frags) < MIN_QUOTE_CHARS:
        return None
    spans: list[tuple[int, int]] = []
    for frag in frags:
        if _nonspace(frag) < MIN_QUOTE_CHARS:
            continue  # too short to place reliably; the long fragments define the span
        span = _align(frag, seg_n, min_score)
        if span is None:
            return None
        spans.append(span)
    if not spans:
        return None
    start = min(a for a, _ in spans)
    end = max(b for _, b in spans)
    while start < end and seg_n[start] == " ":
        start += 1
    while end > start and seg_n[end - 1] == " ":
        end -= 1
    if start >= end:
        return None
    return index[start], index[end - 1] + 1


# ---------------- internals ----------------

def _field(item: Any, name: str) -> Any:
    if isinstance(item, Mapping):
        return item.get(name)
    return getattr(item, name, None)


def _char_table(s: str) -> dict[int, str]:
    table = dict(_STATIC_MAP)
    for ch in set(s):
        code = ord(ch)
        if code in table:
            continue
        low = ch.lower()
        if low != ch and len(low) == 1:  # skip 'İ' -> 'i̇' etc. to stay 1:1
            table[code] = low
    return table


def _normalize(s: str) -> tuple[str, list[int]]:
    """Return (normalized text, index map normalized-position -> original-position)."""
    t = s.translate(_char_table(s))
    out: list[str] = []
    index: list[int] = []
    pos = 0
    n = len(t)
    for m in _GAP.finditer(t):
        a, b = m.span()
        if a > pos:
            out.append(t[pos:a])
            index.extend(range(pos, a))
        # a gap of invisible characters only is dropped; a gap with real whitespace becomes one space
        if index and b < n and any(c.isspace() for c in m.group()):
            out.append(" ")
            index.append(a)
        pos = b
    if pos < n:
        out.append(t[pos:])
        index.extend(range(pos, n))
    return "".join(out), index


def _fragments(quote: str) -> list[str]:
    frags = (_normalize(part)[0] for part in _ELLIPSIS.split(quote or ""))
    return [f for f in frags if f]


def _nonspace(s: str) -> int:
    return len(s) - s.count(" ")


def _score(frag: str, seg: str) -> float:
    if not frag or not seg:
        return 0.0
    if len(frag) <= len(seg):
        return fuzz.partial_ratio(frag, seg)
    # A quote longer than its segment can't be "inside" it; partial_ratio would swap the arguments
    # and score a short segment contained in a long hallucinated quote as 100.
    return fuzz.ratio(frag, seg)


def _is_grounded(quote: str, seg_n: str, min_score: int) -> bool:
    frags = _fragments(quote)
    if not frags or sum(_nonspace(f) for f in frags) < MIN_QUOTE_CHARS:
        return False
    if len(frags) == 1:
        return _score(frags[0], seg_n) >= min_score
    # Ellipsis quote: every fragment must be in the segment (short ones exactly), and at least one
    # fragment must be long enough for the fuzzy match to mean something.
    has_long = False
    for frag in frags:
        if _nonspace(frag) < MIN_QUOTE_CHARS:
            if frag not in seg_n:
                return False
        elif _score(frag, seg_n) >= min_score:
            has_long = True
        else:
            return False
    return has_long


def _align(frag: str, seg_n: str, min_score: int) -> tuple[int, int] | None:
    if len(frag) <= len(seg_n):
        al = fuzz.partial_ratio_alignment(frag, seg_n)
        if al is None or al.score < min_score:
            return None
        return al.dest_start, al.dest_end
    if fuzz.ratio(frag, seg_n) < min_score:
        return None
    return 0, len(seg_n)


__all__ = ["ground", "grounded_count", "locate", "MIN_QUOTE_CHARS"]
