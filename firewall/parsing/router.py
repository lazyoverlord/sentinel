"""Format detection and dispatch (SPEC §6): content_type -> extension -> magic bytes.

Also hosts `embed_attachment`, the depth-limited recursion used by email and PDF attachments.
"""
from __future__ import annotations

import codecs
import io
import json
import os
import re
import zipfile
from collections.abc import Callable

from .base import (
    VISIBLE_CHANNELS,
    Out,
    ParseContext,
    ParseLimitError,
    RawSeg,
    UnsupportedFormatError,
    describe_error,
    fallback_segments,
    prefix_warning,
)
from . import code_parser, docx_parser, email_parser, html_parser, image, markdown_parser, pdf, structured, text

ParserFn = Callable[..., list[RawSeg]]

# format -> parser(data, ctx, *, filename, content_type). Tests may swap entries (monkeypatch.setitem).
PARSERS: dict[str, ParserFn] = {
    "text": text.parse,
    "pdf": pdf.parse,
    "docx": docx_parser.parse,
    "html": html_parser.parse,
    "markdown": markdown_parser.parse,
    "email": email_parser.parse,
    "json": structured.parse_json,
    "xml": structured.parse_xml,
    "code": code_parser.parse,
    "image": image.parse,
}

BINARY_FORMATS = frozenset({"pdf", "docx", "image"})

# Content types that say nothing useful: fall through to the extension / magic bytes.
_GENERIC_TYPES = frozenset({
    "", "application/octet-stream", "binary/octet-stream", "application/unknown", "application/binary",
    "application/x-download", "application/download", "application/force-download", "text/plain",
})

_TYPE_MAP: dict[str, str] = {
    "application/pdf": "pdf", "application/x-pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "text/html": "html", "application/xhtml+xml": "html",
    "text/markdown": "markdown", "text/x-markdown": "markdown",
    "message/rfc822": "email",
    "application/json": "json", "text/json": "json", "application/x-ndjson": "json", "application/jsonl": "json",
    "application/xml": "xml", "text/xml": "xml", "image/svg+xml": "xml",
}
_TYPE_MAP.update({ct: "code" for ct in code_parser.LANG_BY_TYPE})

_EXT_MAP: dict[str, str] = {
    **{ext: "text" for ext in (".txt", ".text", ".log", ".csv", ".tsv", ".ini", ".cfg", ".conf",
                               ".toml", ".yaml", ".yml", ".rst", ".tex")},
    ".pdf": "pdf",
    ".docx": "docx",
    **{ext: "html" for ext in (".html", ".htm", ".xhtml", ".shtml")},
    **{ext: "markdown" for ext in (".md", ".markdown", ".mdown", ".mkd", ".mkdn")},
    ".eml": "email",
    **{ext: "json" for ext in (".json", ".jsonl", ".ndjson", ".geojson")},
    **{ext: "xml" for ext in (".xml", ".rss", ".atom", ".svg", ".xsd", ".xsl", ".xslt")},
    **{ext: "code" for ext in code_parser.LANG_BY_EXT},
    **{ext: "image" for ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp")},
}

_EMAIL_HEADERS = frozenset({"from", "to", "subject", "date", "message-id", "mime-version", "received",
                            "return-path", "delivered-to", "reply-to", "cc", "x-mailer"})
_HEADER_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]")
_HTML_TAG = re.compile(r"<(?:html|head|body)[\s>]")
_BOM = chr(0xFEFF)                   # byte-order mark left at the start of decoded text


def _normalize_type(content_type: str | None) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def _type_to_format(ct: str) -> str | None:
    if ct in _TYPE_MAP:
        return _TYPE_MAP[ct]
    if ct.startswith("image/"):
        return "image"
    if ct.endswith("+json"):
        return "json"
    if ct.endswith("+xml"):
        return "xml"
    return None


def _ext_to_format(filename: str | None) -> str | None:
    if not filename:
        return None
    return _EXT_MAP.get(os.path.splitext(filename.strip().lower())[1])


def _head_text(data: bytes) -> str | None:
    """Decode the first 4 KB as text (BOM-aware); None if it looks binary."""
    head = data[:4096]
    boms = ((codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be"))
    for bom, enc in boms:
        if head.startswith(bom):
            return codecs.getincrementaldecoder(enc)(errors="replace").decode(head[len(bom):])
    if head.count(b"\x00") > len(head) // 100:
        return None
    try:
        return codecs.getincrementaldecoder("utf-8")().decode(head)   # tolerates a cut multibyte char
    except UnicodeDecodeError:
        text = head.decode("cp1252", errors="replace")
        controls = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\r\n\f")
        return None if controls > len(text) // 50 else text


def _looks_like_email(text: str) -> bool:
    seen: set[str] = set()
    for line in text.splitlines()[:60]:
        if not line.strip():
            break                                   # end of the header block
        m = _HEADER_LINE.match(line)
        if m:
            seen.add(m.group(1).lower())
        elif not line[:1].isspace() and not line.startswith("From "):
            return False                            # neither a header nor a folded continuation
    return len(seen & _EMAIL_HEADERS) >= 2


def _is_docx_zip(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return "word/document.xml" in zf.namelist()
    except (zipfile.BadZipFile, ValueError, OSError):
        return False


def _binary_magic(data: bytes) -> str | None:
    """pdf / docx / image / 'binary' (other zip) from unmistakable signatures, else None."""
    head = data[:16]
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        return "docx" if _is_docx_zip(data) else "binary"
    if (head.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"II*\x00", b"MM\x00*"))
            or (head[:4] == b"RIFF" and head[8:12] == b"WEBP")
            or (head[:2] == b"BM" and data[6:10] == b"\x00\x00\x00\x00" and len(data) > 26)):
        return "image"
    return None


def sniff(data: bytes) -> str:
    """Format from magic bytes / content; 'binary' when unrecognized and not text."""
    magic = _binary_magic(data)
    if magic:
        return magic
    text = _head_text(data)
    if text is None:
        return "binary"
    t = text.lstrip(_BOM + " \t\r\n").lower()
    if t.startswith("<?xml"):
        return "html" if "<html" in t[:2000] else "xml"
    if t.startswith(("<!doctype html", "<html")) or _HTML_TAG.search(t[:2000]):
        return "html"
    if t[:1] in ("{", "["):
        try:
            json.loads(data)
            return "json"
        except ValueError:
            pass
    if _looks_like_email(text.lstrip(_BOM)):
        return "email"
    return "text"


def detect_format(data: bytes, filename: str | None, content_type: str | None) -> str:
    """Router: content_type -> extension -> magic bytes.

    Returns one of text/pdf/docx/html/markdown/email/json/xml/code/image, or 'binary' for
    unrecognized binary data (parse() then uses the text fallback with a parse_error warning).
    A declared text-like format loses to unmistakable binary magic (e.g. a PDF labelled text/html).
    """
    ct = _normalize_type(content_type)
    fmt = None if ct in _GENERIC_TYPES else _type_to_format(ct)
    fmt = fmt or _ext_to_format(filename)
    if fmt is None:
        return sniff(data)
    if fmt not in BINARY_FORMATS:
        magic = _binary_magic(data)
        if magic in BINARY_FORMATS:
            return magic
    return fmt


def run_parser(fmt: str, data: bytes, filename: str | None, content_type: str | None,
               ctx: ParseContext) -> list[RawSeg]:
    """Run one format parser (no fallback; exceptions propagate)."""
    parser = PARSERS.get(fmt)
    if parser is None:
        declared = _normalize_type(content_type) or "unknown type"
        raise UnsupportedFormatError(f"no parser for {fmt} data ({declared})")
    return parser(data, ctx, filename=filename, content_type=content_type)


def parse_nested(data: bytes, filename: str | None, content_type: str | None,
                 ctx: ParseContext) -> tuple[str, list[RawSeg]]:
    """Parse an embedded document with the same fallback rules as a top-level one.

    ParseLimitError propagates (the caller decides); cancellation propagates (BaseException).
    """
    fmt = detect_format(data, filename, content_type)
    try:
        return fmt, run_parser(fmt, data, filename, content_type, ctx)
    except ParseLimitError:
        raise
    except Exception as exc:  # noqa: BLE001 - any parser failure => text fallback
        ctx.warnings.clear()
        ctx.warn(f"parse_error: {describe_error(exc)}")
        segs, truncated = fallback_segments(data, ctx.settings)
        if truncated:
            ctx.warn(f"truncated: fallback text capped at MAX_TEXT_CHARS={ctx.settings.MAX_TEXT_CHARS}")
        ctx.shared.chars += sum(len(s.text) for s in segs)
        return "text", segs


def embed_attachment(ctx: ParseContext, out: Out, data: bytes | None, *, name: str | None,
                     content_type: str | None, fallback_name: str = "attachment") -> RawSeg | None:
    """Add an attachment: a metadata segment naming it, then its parsed segments.

    Visible channels of the attachment become `attachment`; hidden/comment/metadata keep theirs.
    Locations get the prefix "attachment:<name> > "; parent = the naming segment.
    Beyond MAX_RECURSION_DEPTH the content is skipped with a recursion_limit warning.
    """
    shown = (name or "").strip() or fallback_name
    # the name is attacker-controlled: tidy it for the location label, keep it raw in the text
    label = f"attachment:{' '.join(shown.split())[:120]}"
    ctype = _normalize_type(content_type)
    meta = out.add(shown if name else f"{shown} ({ctype or 'unknown type'})", "metadata", label, "attachment_name")
    settings = ctx.settings
    if data is None:
        return meta
    if ctx.depth + 1 > settings.MAX_RECURSION_DEPTH:
        ctx.warn(f"recursion_limit: {label} not parsed (nesting depth {ctx.depth + 1} > "
                 f"MAX_RECURSION_DEPTH={settings.MAX_RECURSION_DEPTH})")
        return meta
    if len(data) > settings.MAX_FILE_BYTES:
        ctx.warn(f"limit: {label} is {len(data)} bytes (> MAX_FILE_BYTES={settings.MAX_FILE_BYTES}); not parsed")
        return meta
    if out.full:
        return meta
    child = ctx.child()
    try:
        _, segs = parse_nested(data, shown, content_type, child)
    except ParseLimitError as exc:
        ctx.warn(f"limit: {label}: {exc.reason}; not parsed")
        return meta
    for w in child.warnings:
        ctx.warn(prefix_warning(w, label))
    for seg in segs:
        seg.channel = "attachment" if seg.channel in VISIBLE_CHANNELS else seg.channel
        seg.location = f"{label} > {seg.location}"
        if seg.parent is None:
            seg.parent = meta
        out.append_raw(seg)
    return meta
