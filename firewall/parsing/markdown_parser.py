"""Markdown (SPEC §6, Should): markdown-it-py tokens re-serialized as lightweight markdown.

Visible text keeps the syntax detectors rely on: `code` backticks, ``` fences, "> " quote
markers and raw link/image URLs (exfiltration rules look for ![](https://...?q=...)).
Non-visible parts become their own segments: HTML comments and link reference definitions
(`[//]: # (...)`, never rendered) -> `comment`; image alt text and link titles -> `metadata`;
raw HTML goes through the HTML rules (so a hidden <span>/<div> is `hidden`).
"""
from __future__ import annotations

import html
import re
from dataclasses import dataclass, field

from markdown_it import MarkdownIt
from markdown_it.token import Token

from .base import Out, ParseContext, RawSeg, decode_text
from .html_parser import element_hidden_reason, parse_html_raw

_TAG = re.compile(                      # one inline HTML tag: </?name attrs /?>
    r"^<\s*(/?)\s*([A-Za-z][\w:-]*)"
    r"((?:\s+[^\s=>/]+(?:\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+))?)*)\s*(/?)\s*>$", re.S)
_ATTR = re.compile(r"([^\s=>/]+)(?:\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+)))?")
_IMG_SRC = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.I)
_REF_COMMENT = re.compile(r"^\s{0,3}\[(?://|#|comment|_)\]:", re.I)
_VOID = frozenset({"br", "img", "hr", "input", "wbr", "meta", "link", "source", "area", "col", "embed"})
# tokens whose line map covers the source lines they render
_LEAF_BLOCKS = frozenset({"paragraph_open", "heading_open", "fence", "code_block", "html_block",
                          "table_open", "hr"})
_CONTAINER_MARKERS = re.compile(r"^(?:\s*(?:>|[-+*]|\d{1,9}[.)])(?=\s|$))*\s*$")


@dataclass
class _Piece:
    """A non-visible segment found while rendering an inline token."""
    line: int
    channel: str
    reason: str | None
    text: str


@dataclass
class _Inline:
    text: str
    pieces: list[_Piece] = field(default_factory=list)


def _attrs(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _ATTR.finditer(raw):
        value = next((g for g in m.groups()[1:] if g is not None), "")
        out[m.group(1).lower()] = html.unescape(value)
    return out


def _render_inline(tok: Token, first_line: int) -> _Inline:
    """Inline children -> markdown-ish text; hidden inline HTML, comments, alt/titles -> pieces."""
    parts: list[str] = []
    pieces: list[_Piece] = []
    line = first_line
    hidden_stack: list[tuple[str, str | None]] = []     # open inline HTML tags and their hidden reason
    hidden_buf: list[str] = []
    hidden_start = line
    hrefs: list[tuple[str, bool]] = []

    def hidden_reason() -> str | None:
        return next((r for _, r in hidden_stack if r), None)

    def emit(text: str) -> None:
        nonlocal hidden_start
        if hidden_reason():
            if not hidden_buf:
                hidden_start = line
            hidden_buf.append(text)
        else:
            parts.append(text)

    def flush_hidden(reason: str | None) -> None:
        if hidden_buf:
            pieces.append(_Piece(hidden_start, "hidden", reason, "".join(hidden_buf)))
            hidden_buf.clear()

    for child in tok.children or []:
        kind = child.type
        if kind in ("softbreak", "hardbreak"):
            emit("\n")
            line += 1
        elif kind == "text":
            emit(child.content)
        elif kind == "code_inline":
            emit(f"{child.markup}{child.content}{child.markup}")
        elif kind == "link_open":
            href = str(child.attrs.get("href", ""))
            auto = child.markup in ("autolink", "linkify")
            hrefs.append((href, auto))
            if child.attrs.get("title"):
                pieces.append(_Piece(line, "metadata", "link_title", str(child.attrs["title"])))
            if not auto:
                emit("[")
        elif kind == "link_close":
            href, auto = hrefs.pop() if hrefs else ("", True)
            if not auto:
                emit(f"]({href})")
        elif kind == "image":
            emit(f"![]({child.attrs.get('src', '')})")           # URL stays visible, alt does not
            if child.content:
                pieces.append(_Piece(line, "metadata", "img_alt", child.content))
            if child.attrs.get("title"):
                pieces.append(_Piece(line, "metadata", "link_title", str(child.attrs["title"])))
        elif kind == "html_inline":
            raw = child.content.strip()
            if raw.startswith("<!--"):
                body = raw.removeprefix("<!--").removesuffix("-->")
                pieces.append(_Piece(line, "comment", "html_comment", body))
                continue
            m = _TAG.match(raw)
            if not m:
                emit(child.content)
                continue
            closing, name, attr_src, self_closing = m.group(1), m.group(2).lower(), m.group(3), m.group(4)
            attrs = _attrs(attr_src)
            if closing:
                for i in range(len(hidden_stack) - 1, -1, -1):
                    if hidden_stack[i][0] == name:
                        before = hidden_reason()
                        del hidden_stack[i:]
                        if before and not hidden_reason():
                            flush_hidden(before)
                        break
            elif name == "br":
                emit("\n")
            elif name == "img":
                emit(f"![]({attrs.get('src', '')})")
                if attrs.get("alt"):
                    pieces.append(_Piece(line, "metadata", "img_alt", attrs["alt"]))
            elif name == "input" and attrs.get("type", "").lower() == "hidden" and attrs.get("value"):
                pieces.append(_Piece(line, "hidden", "hidden_input", attrs["value"]))
            elif not self_closing and name not in _VOID:
                hidden_stack.append((name, element_hidden_reason(name, attrs)))
        elif child.content:                                   # emphasis markers etc. carry no text
            emit(child.content)
    flush_hidden(hidden_reason())           # an unclosed hidden tag ends with its paragraph
    return _Inline("".join(parts), pieces)


def _quote(text: str, depth: int) -> str:
    if not depth:
        return text
    prefix = "> " * depth
    return "\n".join(prefix + line for line in text.split("\n"))


def parse(data: bytes, ctx: ParseContext, *, filename: str | None = None,
          content_type: str | None = None) -> list[RawSeg]:
    src = decode_text(data)
    md = MarkdownIt("commonmark").enable("table").enable("strikethrough")
    env: dict = {}
    tokens = md.parse(src, env)
    lines = src.splitlines()
    ctx.checkpoint()

    found: list[tuple[int, int, RawSeg]] = []           # (line, order, segment) -> sorted at the end
    order = 0

    def add(line: int, text: str, channel: str, reason: str | None = None) -> None:
        nonlocal order
        if text and text.strip():
            order += 1
            found.append((line, order, RawSeg(text, channel, f"line {line}", reason)))  # type: ignore[arg-type]

    def add_inline(line: int, rendered: _Inline, prefix: str = "", quote_depth: int = 0) -> None:
        add(line, _quote(prefix + rendered.text, quote_depth), "visible")
        for p in rendered.pieces:
            add(p.line, p.text, p.channel, p.reason)

    # Link reference definitions never render: comment channel (covers the `[//]: # (...)` idiom).
    for ref in env.get("references", {}).values():
        start, end = ref.get("map") or (None, None)
        if start is None:
            continue
        raw = "\n".join(lines[start:end])
        add(start + 1, raw, "comment", "md_comment" if _REF_COMMENT.match(raw) else "md_reference")

    quote_depth = 0
    lists: list[list[int | str]] = []        # [kind, next number]
    item_marker = ""
    i = 0
    while i < len(tokens):
        if i % 500 == 0:
            ctx.checkpoint()
        tok = tokens[i]
        line = (tok.map[0] + 1) if tok.map else 1
        kind = tok.type
        if kind == "blockquote_open":
            quote_depth += 1
        elif kind == "blockquote_close":
            quote_depth -= 1
        elif kind in ("bullet_list_open", "ordered_list_open"):
            lists.append([kind, int(tok.attrs.get("start", 1) or 1)])
        elif kind in ("bullet_list_close", "ordered_list_close"):
            if lists:
                lists.pop()
        elif kind == "list_item_open" and lists:
            top = lists[-1]
            if top[0] == "ordered_list_open":
                item_marker = f"{top[1]}. "
                top[1] = int(top[1]) + 1
            else:
                item_marker = "- "
        elif kind in ("paragraph_open", "heading_open") and i + 1 < len(tokens):
            prefix = "#" * int(tok.tag[1]) + " " if kind == "heading_open" else item_marker
            item_marker = ""
            add_inline(line, _render_inline(tokens[i + 1], line), prefix, quote_depth)
            i += 3
            continue
        elif kind in ("fence", "code_block"):
            fence = tok.markup if kind == "fence" and tok.markup else "```"
            add(line, _quote(f"{fence}{tok.info}\n{tok.content}{fence}", quote_depth), "visible")
            item_marker = ""
        elif kind == "html_block":
            html_segs = parse_html_raw(tok.content, ctx)
            ctx.shared.chars -= sum(len(s.text) for s in html_segs)    # re-counted by `out` below
            for seg in html_segs:
                add(line, seg.text, seg.channel, seg.hidden_reason)
            for m in _IMG_SRC.finditer(tok.content):         # keep raw <img> URLs visible for exfil rules
                add(line, f"![]({next(g for g in m.groups() if g is not None)})", "visible")
        elif kind == "table_open":
            rows: list[str] = []
            j = i + 1
            cells: list[_Inline] = []
            while j < len(tokens) and tokens[j].type != "table_close":
                t = tokens[j]
                if t.type == "inline":
                    cells.append(_render_inline(t, (t.map[0] + 1) if t.map else line))
                elif t.type == "tr_close":
                    rows.append("| " + " | ".join(c.text for c in cells) + " |")
                    for c in cells:
                        for p in c.pieces:
                            add(p.line, p.text, p.channel, p.reason)
                    cells = []
                j += 1
            add(line, _quote("\n".join(rows), quote_depth), "visible")
            i = j + 1
            continue
        i += 1

    # Safety net: markdown-it stops tokenizing past its nesting limit (20 levels) and drops that
    # text. Keep any non-blank line no token accounts for as plain visible text.
    covered: set[int] = set()
    for tok in tokens:
        if tok.type in _LEAF_BLOCKS and tok.map:
            covered.update(range(tok.map[0], tok.map[1]))
    for ref in env.get("references", {}).values():
        if ref.get("map"):
            covered.update(range(ref["map"][0], ref["map"][1]))
    run_start: int | None = None
    for n, text_line in enumerate(lines + [""]):
        lost = n < len(lines) and n not in covered and not _CONTAINER_MARKERS.match(text_line)
        if lost and run_start is None:
            run_start = n
        elif not lost and run_start is not None:
            add(run_start + 1, "\n".join(lines[run_start:n]), "visible")
            ctx.warn("limit: markdown nested beyond the parser's depth limit; those lines were kept as plain text")
            run_start = None

    out = Out(ctx)
    for _, _, seg in sorted(found, key=lambda t: (t[0], t[1])):
        out.add(seg.text, seg.channel, seg.location, seg.hidden_reason)
    return out.segs
