"""Shared building blocks for the format parsers (SPEC §6).

Format parsers produce `RawSeg`s (no ids yet) in document order. `finalize()` turns them into a
`ParsedContent`: ids S1.., parent links, empty segments dropped, MAX_TEXT_CHARS cap applied.
"""
from __future__ import annotations

import codecs
import io
import re
import threading
import time
import zipfile
from dataclasses import dataclass

from lxml import etree

from firewall.config import Settings
from firewall.schemas import Channel, ParsedContent, Segment, Source

# Channels the pipeline joins into the released ("clean") document.
VISIBLE_CHANNELS: frozenset[str] = frozenset({"visible", "ocr", "ocr_layer"})
MAX_ZIP_ENTRIES = 5000
LOW_CONTRAST_MAX = 1.2        # WCAG contrast ratio below which text counts as invisible
WHITE_LUMINANCE = 0.95        # SPEC §6: fill luminance > 0.95 => white text
_WARNING_DETAIL_MAX = 200


class ParseLimitError(Exception):
    """A hard size limit was hit (file too large, zip bomb). The caller must reject the input."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class UnsupportedFormatError(ValueError):
    """No parser for this data (unknown binary). Triggers the text fallback."""


class ParseCancelled(BaseException):
    """Raised at a checkpoint once the caller has stopped waiting (timeout).

    A BaseException so that parsers' broad `except Exception` blocks don't swallow it.
    """


@dataclass(eq=False)
class RawSeg:
    """A segment before ids are assigned; `parent` points at another RawSeg."""

    text: str
    channel: Channel
    location: str
    hidden_reason: str | None = None
    parent: RawSeg | None = None


@dataclass
class _Shared:
    """State shared by a top-level parse and all of its nested (attachment) parses."""

    settings: Settings
    deadline: float
    cancel: threading.Event
    chars: int = 0          # characters emitted so far (for early stop at MAX_TEXT_CHARS)
    stopped_early: bool = False   # a parser skipped content because the text budget was spent


class ParseContext:
    """Per-parse state: settings, deadline/cancel flag, recursion depth, warnings."""

    def __init__(self, settings: Settings, *, deadline: float | None = None) -> None:
        if deadline is None:
            deadline = time.monotonic() + settings.PARSE_TIMEOUT_S
        self.shared = _Shared(settings, deadline, threading.Event())
        self.depth = 0
        self.warnings: list[str] = []

    @property
    def settings(self) -> Settings:
        return self.shared.settings

    def child(self) -> ParseContext:
        """Context for a nested document (attachment): one level deeper, own warning list."""
        c = ParseContext.__new__(ParseContext)
        c.shared, c.depth, c.warnings = self.shared, self.depth + 1, []
        return c

    def checkpoint(self) -> None:
        """Call inside long loops: stops work once the caller gave up or the deadline passed."""
        if self.shared.cancel.is_set() or time.monotonic() > self.shared.deadline:
            raise ParseCancelled()

    def remaining(self) -> float:
        return self.shared.deadline - time.monotonic()

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    @property
    def full(self) -> bool:
        """True once more text was extracted than MAX_TEXT_CHARS. Parsers check it to stop
        early, so a True answer is remembered and the result is marked truncated."""
        if self.shared.chars > self.settings.MAX_TEXT_CHARS:
            self.shared.stopped_early = True
            return True
        return False


class Out:
    """Ordered collector of RawSegs that keeps the shared character count up to date."""

    def __init__(self, ctx: ParseContext) -> None:
        self.ctx = ctx
        self.segs: list[RawSeg] = []

    def add(self, text: str | None, channel: Channel, location: str,
            hidden_reason: str | None = None, parent: RawSeg | None = None) -> RawSeg | None:
        if not text or not text.strip():
            return None
        seg = RawSeg(text, channel, location, hidden_reason, parent)
        self.segs.append(seg)
        self.ctx.shared.chars += len(text)
        return seg

    def reserve(self, channel: Channel, location: str, hidden_reason: str | None = None) -> RawSeg:
        """Placeholder that keeps its place in document order; its text is set later by fill()."""
        seg = RawSeg("", channel, location, hidden_reason)
        self.segs.append(seg)
        return seg

    def fill(self, seg: RawSeg, text: str) -> None:
        seg.text = text
        self.ctx.shared.chars += len(text)

    def append_raw(self, seg: RawSeg) -> None:
        """Adopt a segment produced by a nested parse (already counted)."""
        self.segs.append(seg)

    @property
    def full(self) -> bool:
        return self.ctx.full


# ---------------------------------------------------------------- finalize / fallback

def finalize(fmt: str, source_type: Source, raw: list[RawSeg], warnings: list[str],
             settings: Settings, *, truncated: bool = False) -> ParsedContent:
    """Assign ids, resolve parents, drop empty segments, apply the MAX_TEXT_CHARS cap."""
    cap = settings.MAX_TEXT_CHARS
    kept: list[tuple[RawSeg, str]] = []
    total = 0
    cut_note = ""
    live = [(seg, seg.text.strip()) for seg in raw]
    live = [(seg, text) for seg, text in live if text]
    for i, (seg, text) in enumerate(live):
        if total + len(text) > cap:
            text = text[: cap - total].rstrip()
            if text:
                kept.append((seg, text))
                total += len(text)
            truncated = True
            dropped = len(live) - i - (1 if text else 0)
            cut_note = f"; last kept segment cut, {dropped} later segment(s) dropped"
            break
        kept.append((seg, text))
        total += len(text)

    ids = {id(seg): f"S{n}" for n, (seg, _) in enumerate(kept, 1)}
    segments = [
        Segment(id=ids[id(seg)], text=text, channel=seg.channel, location=seg.location,
                hidden_reason=seg.hidden_reason,
                parent=ids.get(id(seg.parent)) if seg.parent is not None else None)
        for seg, text in kept
    ]
    out_warnings = list(dict.fromkeys(warnings))          # dedupe, keep order
    if truncated and not any(w.startswith("truncated:") for w in out_warnings):
        out_warnings.append(f"truncated: extracted text capped at MAX_TEXT_CHARS={cap}{cut_note}")
    return ParsedContent(format=fmt, source_type=source_type, segments=segments,
                         warnings=out_warnings, truncated=truncated)


def fallback_segments(data: bytes, settings: Settings) -> tuple[list[RawSeg], bool]:
    """SPEC §6 parse-failure fallback: one visible UTF-8 (errors=replace) segment."""
    cap = settings.MAX_TEXT_CHARS
    # a character takes at most 4 UTF-8 bytes, so this prefix always yields >= cap characters
    text = data[: cap * 4 + 4].decode("utf-8", errors="replace")
    truncated = len(text) > cap
    return [RawSeg(text[:cap], "visible", "text")], truncated


def describe_error(exc: BaseException) -> str:
    """'<ExceptionType>: <message>' for parse_error warnings (message shortened)."""
    msg = " ".join(str(exc).split())[:_WARNING_DETAIL_MAX] or "no message"
    return f"{type(exc).__name__}: {msg}"


def prefix_warning(warning: str, label: str) -> str:
    """'parse_error: X' -> 'parse_error: attachment:a.pdf > X' (keeps the warning-kind prefix)."""
    kind, sep, rest = warning.partition(": ")
    if not sep:
        return f"{label}: {warning}"
    return f"{kind}: {label} > {rest}"


# ---------------------------------------------------------------- limits

def check_zip_limits(data: bytes, settings: Settings) -> None:
    """Reject zip bombs BEFORE any member is decompressed (declared sizes; zipfile enforces them)."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise ParseLimitError(f"zip archive has {len(infos)} entries (limit {MAX_ZIP_ENTRIES})")
    total = sum(info.file_size for info in infos)
    if total > settings.MAX_UNCOMPRESSED_BYTES:
        raise ParseLimitError(f"zip uncompressed size {total} bytes exceeds "
                              f"MAX_UNCOMPRESSED_BYTES={settings.MAX_UNCOMPRESSED_BYTES}")


# ---------------------------------------------------------------- text helpers

_REPLACEMENT_CHAR = chr(0xFFFD)        # what errors="replace" inserts for undecodable bytes
_BOMS = ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
         (codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"))


def decode_text(data: bytes) -> str:
    """Bytes -> str: BOM-aware, UTF-8 first, cp1252 for clearly non-UTF-8 legacy text.

    Only character-set decoding: never base64/entities/etc. (that is the obfuscation layer's job).
    """
    for bom, encoding in _BOMS:              # UTF-32-LE BOM starts with the UTF-16-LE one: check 32 first
        if data.startswith(bom):
            return data.decode(encoding, errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
        if text.count(_REPLACEMENT_CHAR) <= max(3, len(text) // 200):   # mostly UTF-8 with a few bad bytes
            return text
        return data.decode("cp1252", errors="replace")


def collapse_ws(text: str) -> str:
    return " ".join(text.split())


_NON_ALNUM = re.compile(r"[\W_]+")


def alnum_key(text: str) -> str:
    """Case/punctuation/whitespace-insensitive key used to spot duplicated text."""
    return _NON_ALNUM.sub("", text.casefold())


# ---------------------------------------------------------------- colour helpers

RGB = tuple[float, float, float]            # components in 0..1
WHITE: RGB = (1.0, 1.0, 1.0)
BLACK: RGB = (0.0, 0.0, 0.0)


def _linear(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def luminance(rgb: RGB) -> float:
    """sRGB relative luminance (WCAG): 0 = black, 1 = white."""
    r, g, b = rgb
    return 0.2126 * _linear(r) + 0.7152 * _linear(g) + 0.0722 * _linear(b)


def contrast_ratio(a: RGB, b: RGB) -> float:
    """WCAG contrast ratio, 1.0 (identical) .. 21.0 (black on white)."""
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def rgb_from_hex(value: str | None) -> RGB | None:
    """'FFF' / 'FFFFFF' / '#ffffff' / 'FFFFFF80' -> (1,1,1); None when not a hex colour."""
    if not value:
        return None
    v = value.strip().lstrip("#")
    if len(v) in (3, 4) and all(ch in "0123456789abcdefABCDEF" for ch in v):
        v = "".join(ch * 2 for ch in v[:3])
    if len(v) in (6, 8) and all(ch in "0123456789abcdefABCDEF" for ch in v):
        return (int(v[0:2], 16) / 255, int(v[2:4], 16) / 255, int(v[4:6], 16) / 255)
    return None


def rgb_from_int(value: int) -> RGB:
    """PyMuPDF span colour (0xRRGGBB int) -> RGB."""
    return (((value >> 16) & 255) / 255, ((value >> 8) & 255) / 255, (value & 255) / 255)


# ---------------------------------------------------------------- safe XML

def safe_xml_parser(*, recover: bool = False) -> etree.XMLParser:
    """lxml parser that never expands entities, loads DTDs or touches the network (XXE/billion laughs)."""
    return etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False,
                           dtd_validation=False, huge_tree=False, recover=recover)


def xml_text_items(xml: bytes | str, *, min_letters: int = 1) -> list[tuple[str, str]]:
    """(prefixed-name, text) for element text and attribute values of a small XML packet (XMP)."""
    if isinstance(xml, str):
        xml = xml.encode("utf-8", errors="replace")
    root = etree.fromstring(xml, parser=safe_xml_parser(recover=True))
    if root is None:
        return []
    items: list[tuple[str, str]] = []
    rdf_ns = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"

    def name_of(node: etree._Element, qname: str) -> str:
        q = etree.QName(qname)
        prefix = next((p for p, ns in (node.nsmap or {}).items() if ns == q.namespace and p), None)
        return f"{prefix}:{q.localname}" if prefix else q.localname

    def property_name(el: etree._Element) -> str:
        # rdf:li / rdf:Alt hold the value of the nearest non-RDF ancestor (e.g. dc:description)
        node = el
        while node is not None and isinstance(node.tag, str) and etree.QName(node).namespace == rdf_ns:
            node = node.getparent()
        node = el if node is None else node
        return name_of(node, node.tag)

    skip_ns = (rdf_ns, "http://www.w3.org/XML/1998/namespace")     # rdf:about, xml:lang, ...
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue                                    # comments / PIs / entities
        for attr, value in el.attrib.items():
            if etree.QName(attr).namespace in skip_ns:
                continue
            if (sum(ch.isalpha() for ch in value) >= max(3, min_letters)
                    and not value.startswith(("http:", "https:", "uuid:", "xmp.", "adobe:"))):
                items.append((name_of(el, attr), value))
        text = (el.text or "").strip()
        if text and sum(ch.isalpha() for ch in text) >= min_letters:
            items.append((property_name(el), text))
    return items
