"""JSON and XML (SPEC §6): every string leaf is a visible segment located by JSONPath / XPath.

JSON keys, numbers, booleans and nulls are not segments. XML: element text and attribute values
are visible; comments / processing instructions go to the `comment` channel. The XML parser never
expands entities or loads DTDs (no XXE, no billion laughs).
"""
from __future__ import annotations

import json
import re
from typing import Any

from lxml import etree

from .base import Out, ParseContext, RawSeg, decode_text, safe_xml_parser

MAX_JSON_DEPTH = 64
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CHECK_EVERY = 2000                     # nodes between cancellation checkpoints


# ---------------------------------------------------------------- JSON

def _key_path(path: str, key: str) -> str:
    if _IDENT.match(key):
        return f"{path}.{key}"
    escaped = key.replace("\\", "\\\\").replace("'", "\\'")
    return f"{path}['{escaped}']"


def walk_json(value: Any, out: Out, ctx: ParseContext, *, root: str = "$", loc_prefix: str = "",
              channel: str = "visible", reason: str | None = None, skip_at_keys: bool = False) -> None:
    """Emit one segment per string leaf in document order (iterative: deep input can't overflow)."""
    stack: list[tuple[Any, str, int]] = [(value, root, 0)]
    seen = 0
    while stack:
        node, path, depth = stack.pop()
        seen += 1
        if seen % _CHECK_EVERY == 0:
            ctx.checkpoint()
            if out.full:
                return
        if isinstance(node, str):
            out.add(node, channel, f"{loc_prefix}{path}", reason)
        elif isinstance(node, (dict, list)):
            if depth >= MAX_JSON_DEPTH:
                ctx.warn(f"limit: JSON nesting deeper than {MAX_JSON_DEPTH} flattened at {loc_prefix}{path}")
                out.add(json.dumps(node, ensure_ascii=False), channel, f"{loc_prefix}{path}", reason)
                continue
            if isinstance(node, dict):
                # JSON-LD: skip keyword strings like "@type": "Article", but walk "@graph": [...]
                items = [(k, v) for k, v in node.items()
                         if not (skip_at_keys and str(k).startswith("@") and isinstance(v, str))]
                children = [(v, _key_path(path, str(k)), depth + 1) for k, v in items]
            else:
                children = [(v, f"{path}[{i}]", depth + 1) for i, v in enumerate(node)]
            stack.extend(reversed(children))          # reversed => popped in document order
        # numbers / booleans / null are not text


def parse_json(data: bytes, ctx: ParseContext, *, filename: str | None = None,
               content_type: str | None = None) -> list[RawSeg]:
    text = decode_text(data)
    out = Out(ctx)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        if "Extra data" not in exc.msg:
            raise
        # JSON Lines / NDJSON: one document per line
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip():
                walk_json(json.loads(line), out, ctx, loc_prefix=f"line {n} · ")
        return out.segs
    walk_json(value, out, ctx)
    return out.segs


# ---------------------------------------------------------------- XML

def _local(tag: str) -> str:
    return etree.QName(tag).localname if tag.startswith("{") else tag


def parse_xml(data: bytes, ctx: ParseContext, *, filename: str | None = None,
              content_type: str | None = None) -> list[RawSeg]:
    root = etree.fromstring(data, parser=safe_xml_parser())
    out = Out(ctx)
    entity_seen = False

    def attr_worthy(value: str) -> bool:
        # skip ids/numbers/coordinates; keep anything with a real word in it
        return re.search(r"[^\W\d_]{3}", value) is not None

    def children_with_paths(parent_path: str, parent: etree._Element) -> list[tuple[etree._Element, str]]:
        # (lxml element proxies are recycled, so paths travel with the elements, never via id())
        children = list(parent)
        counts: dict[str, int] = {}
        for ch in children:
            if isinstance(ch.tag, str):
                counts[ch.tag] = counts.get(ch.tag, 0) + 1
        seen: dict[str, int] = {}
        result: list[tuple[etree._Element, str]] = []
        for ch in children:
            if isinstance(ch.tag, str):
                seen[ch.tag] = seen.get(ch.tag, 0) + 1
                idx = f"[{seen[ch.tag]}]" if counts[ch.tag] > 1 else ""
                result.append((ch, f"{parent_path}/{_local(ch.tag)}{idx}"))
            else:
                result.append((ch, parent_path))
        return result

    def emit_misc(node: etree._Element, parent_path: str) -> None:
        nonlocal entity_seen
        if isinstance(node, etree._Comment):
            out.add(node.text, "comment", f"{parent_path}/comment()", "xml_comment")
        elif isinstance(node, etree._ProcessingInstruction):
            out.add(node.text, "comment", f"{parent_path}/processing-instruction()", "xml_pi")
        elif isinstance(node, etree._Entity):
            entity_seen = True                           # never expanded

    # prolog/epilog comments and PIs around the root element
    for sib in reversed(list(root.itersiblings(preceding=True))):
        emit_misc(sib, "")
    root_path = f"/{_local(root.tag)}"
    # iterative DFS with enter/exit events so tails come out in document order
    stack: list[tuple[str, etree._Element, str, str]] = [("enter", root, root_path, "")]
    visited = 0
    while stack:
        event, el, path, parent_path = stack.pop()
        if event == "exit":
            if parent_path:                              # text after the element, inside its parent
                out.add(el.tail, "visible", f"{parent_path}/text()")
            continue
        visited += 1
        if visited % _CHECK_EVERY == 0:
            ctx.checkpoint()
            if out.full:
                break
        if not isinstance(el.tag, str):                  # comment / PI / entity inside an element
            emit_misc(el, parent_path)
            if el.tail and el.tail.strip():
                out.add(el.tail, "visible", f"{parent_path}/text()")
            continue
        for name, value in el.attrib.items():
            if attr_worthy(value):
                out.add(value, "visible", f"{path}/@{_local(name)}")
        out.add(el.text, "visible", path)
        stack.append(("exit", el, path, parent_path))
        for ch, ch_path in reversed(children_with_paths(path, el)):
            stack.append(("enter", ch, ch_path, path))
    for sib in root.itersiblings():
        emit_misc(sib, "")
    if entity_seen:
        ctx.warn("limit: XML entity references were not expanded")
    return out.segs
