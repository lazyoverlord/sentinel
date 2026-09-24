"""Obfuscation expander (SPEC §7.3): produce decoded / normalized variants of each segment so the
classifiers and rules see what an attacker hid. Never executes anything; bounded work everywhere.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

from firewall.schemas import Segment, Variant

DECODED_KINDS = frozenset({"base64", "base32", "hex", "url", "html_entities", "unicode_escape",
                           "rot13", "reversed", "zero_width", "unicode_tags"})
CONDITIONAL_KINDS = frozenset({"rot13", "reversed"})
INVISIBLE_KINDS = frozenset({"zero_width", "unicode_tags"})

ZW_CHARS = "​‌‍⁠﻿"
_INVISIBLE_RE = re.compile(r"[​-‏‪-‮⁠-⁤⁦-⁩﻿­᠎"
                           r"\U000e0000-\U000e007f]")
_TAG_RUN = re.compile(r"[\U000e0000-\U000e007f]+")

_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "Α": "A", "Β": "B", "Ε": "E",
    "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y",
    "Χ": "X",
}
_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s",
         "!": "i", "|": "l"}
_STOP = set("""the and to of a in is you that it for all your are this be with on not as or now from
previous instructions ignore i me my we our they have has do does can will would should must please
what how who when where which tell say reveal system prompt rules secret password send email any
above before new give show print forget disregard just only an at by if but so then than there
their them these those was were been being into about""".split())

_B64 = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
_B32 = re.compile(r"[A-Z2-7]{16,}={0,6}")
_HEX_PLAIN = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_HEX_ESC = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
_HEX_SPACED = re.compile(r"(?:(?:0x)?[0-9a-fA-F]{2}[ ,:]){7,}(?:0x)?[0-9a-fA-F]{2}")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_ENT = re.compile(r"&(?:#\d{1,7}|#x[0-9A-Fa-f]{1,6}|[A-Za-z]{2,10});")
_UESC = re.compile(r"\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\x[0-9a-fA-F]{2}")
_SPACED = re.compile(r"(?<![^\s])(?:[A-Za-z0-9@$!|][ .\-_*]){2,}[A-Za-z0-9@$!|](?![^\s.,!?;:])")

MAX_CANDIDATES = 64
MAX_CANDIDATE_LEN = 100_000
MAX_DECODED_TOTAL = 400_000


# ---------------------------------------------------------------- helpers
def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return ok / len(s)


def _good_text(b: bytes, min_len: int = 8) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(s.strip()) < min_len or _printable_ratio(s) < 0.85:
        return None
    letters = sum(c.isalpha() for c in s)
    if letters < max(4, len(s) * 0.4):        # decoded binary-ish junk is not a hidden instruction
        return None
    if " " not in s.strip() and len(s) > 12:  # a single token is almost never an instruction
        return None
    return s


def _stop_ratio(s: str) -> float:
    words = re.findall(r"[a-z']+", s.lower())
    if len(words) < 3:
        return 0.0
    return sum(w in _STOP for w in words) / len(words)


def strip_invisible(text: str) -> tuple[str, list[tuple[int, int]]]:
    spans, out, last = [], [], 0
    for m in _INVISIBLE_RE.finditer(text):
        if spans and spans[-1][1] == m.start():
            spans[-1] = (spans[-1][0], m.end())
        else:
            spans.append((m.start(), m.end()))
    for a, b in spans:
        out.append(text[last:a])
        last = b
    out.append(text[last:])
    return "".join(out), spans


# ---------------------------------------------------------------- normalization
@dataclass
class Normalized:
    text: str
    index_map: list[int]


def normalize(text: str) -> Normalized:
    letters = [c for c in text if c.isalpha()]
    latin = sum(1 for c in letters if c.isascii())
    latin_majority = bool(letters) and latin / len(letters) >= 0.5
    chars: list[str] = []
    idx: list[int] = []
    # 1) NFKC per char, drop invisibles
    for i, ch in enumerate(text):
        if _INVISIBLE_RE.match(ch):
            continue
        n = unicodedata.normalize("NFKC", ch)
        for c in n:
            chars.append(c)
            idx.append(i)
    # 2) per-token confusables + leetspeak
    s = "".join(chars)
    for m in re.finditer(r"\S+", s):
        tok = m.group(0)
        has_ascii = any(c.isascii() and c.isalpha() for c in tok)
        if has_ascii or latin_majority:
            for j in range(m.start(), m.end()):
                if chars[j] in _CONFUSABLES:
                    chars[j] = _CONFUSABLES[chars[j]]
        tok = "".join(chars[m.start():m.end()])
        core = tok.strip(".,;:?\"'()[]")
        if any(c.isalpha() for c in core) and any(c in _LEET for c in core) and not re.fullmatch(r"[\d.,$₹%]+", core):
            off = m.start() + tok.find(core)
            for j in range(off, off + len(core)):
                if chars[j] in _LEET:
                    # keep a trailing '!' as punctuation
                    if chars[j] == "!" and j == off + len(core) - 1:
                        continue
                    chars[j] = _LEET[chars[j]]
    # 3) collapse spaced letters
    s = "".join(chars)
    keep = [True] * len(s)
    for m in _SPACED.finditer(s):
        for j in range(m.start(), m.end()):
            if s[j] in " .-_*":
                keep[j] = False
    out_chars = [c for c, k in zip(s, keep) if k]
    out_idx = [i for i, k in zip(idx, keep) if k]
    # re-collapse: spaced runs separated by 2+ spaces leave one space between words
    text_out = "".join(out_chars)
    return Normalized(text_out, out_idx)


# ---------------------------------------------------------------- decoders (text -> [(kind, decoded, span)])
def _decode_candidates(text: str) -> list[tuple[str, str, tuple[int, int]]]:
    found: list[tuple[str, str, tuple[int, int]]] = []
    n = 0
    for m in _B64.finditer(text):
        if n >= MAX_CANDIDATES:
            break
        cand = m.group(0)
        if len(cand) > MAX_CANDIDATE_LEN or not re.search(r"[0-9+/=_\-]|[a-z][A-Z]", cand):
            continue
        n += 1
        raw = cand.rstrip("=")
        try:
            b = base64.b64decode(raw.replace("-", "+").replace("_", "/") + "=" * (-len(raw) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        s = _good_text(b)
        if s:
            found.append(("base64", s, m.span()))
    for m in _B32.finditer(text):
        cand = m.group(0)
        if len(cand) > MAX_CANDIDATE_LEN:
            continue
        raw = cand.rstrip("=")
        try:
            b = base64.b32decode(raw + "=" * (-len(raw) % 8))
        except (binascii.Error, ValueError):
            continue
        s = _good_text(b)
        if s:
            found.append(("base32", s, m.span()))
    for rx in (_HEX_ESC, _HEX_SPACED, _HEX_PLAIN):
        for m in rx.finditer(text):
            digits = re.sub(r"\\x|0x|[ ,:]", "", m.group(0))
            try:
                s = _good_text(bytes.fromhex(digits))
            except ValueError:
                continue
            if s and not any(k == "hex" and sp[0] <= m.start() < sp[1] for k, _, sp in found):
                found.append(("hex", s, m.span()))
    if len(_PCT.findall(text)) >= 3:
        d = unquote(text)
        if d != text:
            found.append(("url", d, (0, len(text))))
    if len(_ENT.findall(text)) >= 3:
        d = html.unescape(text)
        if d != text:
            found.append(("html_entities", d, (0, len(text))))
    if len(_UESC.findall(text)) >= 3:
        def rep(m):
            g = m.group(0)
            try:
                return chr(int(g[2:], 16))
            except ValueError:
                return g
        d = _UESC.sub(rep, text)
        if d != text:
            found.append(("unicode_escape", d, (0, len(text))))
    # unicode tags
    for m in _TAG_RUN.finditer(text):
        dec = "".join(chr(ord(c) - 0xE0000) for c in m.group(0) if 0xE0020 <= ord(c) <= 0xE007E)
        if len(dec) >= 4:
            found.append(("unicode_tags", dec, m.span()))
    # zero-width stego
    zw = [(i, c) for i, c in enumerate(text) if c in ZW_CHARS]
    if len(zw) >= 16:
        seq = "".join(c for _, c in zw)
        counts = sorted({c: seq.count(c) for c in set(seq)}.items(), key=lambda kv: -kv[1])
        syms = [c for c, _ in counts]
        if len(syms) >= 2:
            a, b = syms[0], syms[1]
            sep = syms[2] if len(syms) > 2 else None
            for zero, one in ((a, b), (b, a)):
                bits = "".join("0" if c == zero else "1" if c == one else "" for c in seq if c != sep)
                bs = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
                try:
                    s = bs.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if len(s) >= 4 and _printable_ratio(s) >= 0.85:
                    found.append(("zero_width", s, (zw[0][0], zw[-1][0] + 1)))
                    break
    # rot13 / reversed (conditional, only when the text looks encoded)
    base_ratio = _stop_ratio(text)
    if base_ratio < 0.05 and len(re.findall(r"[A-Za-z]", text)) >= 12:
        r = codecs.decode(text, "rot13")
        if _stop_ratio(r) >= 0.15:
            found.append(("rot13", r, (0, len(text))))
        rv = text[::-1]
        if _stop_ratio(rv) >= 0.15:
            found.append(("reversed", rv, (0, len(text))))
    return found


# ---------------------------------------------------------------- expansion
class VariantBudget:
    def __init__(self, limit: int = 256):
        self.limit = limit
        self.used = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def take(self) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return True


@dataclass
class ExpandResult:
    variants: list[Variant] = field(default_factory=list)
    truncated: bool = False
    normalized: dict[str, Normalized] = field(default_factory=dict)


_PRIORITY = {"unicode_tags": 0, "zero_width": 1, "base64": 2, "base32": 3, "hex": 4, "url": 5,
             "html_entities": 6, "unicode_escape": 7, "rot13": 8, "reversed": 9}


def expand_segment(segment: Segment, *, max_per_segment: int = 32, max_depth: int = 3,
                   budget: VariantBudget | None = None) -> ExpandResult:
    res = ExpandResult()
    budget = budget or VariantBudget(10 ** 9)
    seen: set[str] = set()
    text = segment.text

    def emit(kind: str, t: str, depth: int, span) -> bool:
        if t in seen:
            return True
        if len(res.variants) >= max_per_segment or not budget.take():
            res.truncated = True
            return False
        seen.add(t)
        res.variants.append(Variant(segment_id=segment.id, kind=kind, text=t, depth=depth, span=span))
        return True

    emit("original", text, 0, (0, len(text)))
    norm = normalize(text)
    if norm.text != text and norm.text.strip():
        if emit("normalized", norm.text, 0, None):
            res.normalized[segment.id] = norm

    decoded_total = 0
    queue: list[tuple[str, int, tuple[int, int] | None]] = [(text, 0, None)]
    if norm.text != text:
        queue.append((norm.text, 0, "norm"))  # type: ignore[arg-type]
    while queue:
        src, depth, parent_span = queue.pop(0)
        if depth >= max_depth:
            continue
        cands = sorted(_decode_candidates(src), key=lambda k: (_PRIORITY.get(k[0], 99), k[2][0]))
        for kind, dec, span in cands:
            decoded_total += len(dec)
            if decoded_total > MAX_DECODED_TOTAL:
                res.truncated = True
                return res
            if parent_span == "norm":
                nm = norm.index_map
                top = (nm[span[0]] if span[0] < len(nm) else 0,
                       (nm[span[1] - 1] + 1) if 0 < span[1] <= len(nm) else len(text))
            else:
                top = parent_span or span
            if dec in seen:
                continue
            if not emit(kind, dec, depth + 1, top):
                return res
            queue.append((dec, depth + 1, top))
    return res


def expand_all(segments: list[Segment], *, max_per_segment: int = 32, max_per_request: int = 256,
               max_depth: int = 3) -> ExpandResult:
    budget = VariantBudget(max_per_request)
    out = ExpandResult()
    for seg in segments:
        r = expand_segment(seg, max_per_segment=max_per_segment, max_depth=max_depth, budget=budget)
        out.variants += r.variants
        out.truncated |= r.truncated
        out.normalized.update(r.normalized)
    return out
