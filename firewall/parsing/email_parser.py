"""Email / .eml (SPEC §6): headers -> metadata, text/plain -> visible, text/html -> HTML rules,
attachments recurse through the router (depth-limited).

multipart/alternative: the plain part is the visible text; from the HTML alternative we keep all
non-visible segments (hidden, comment, metadata) plus any visible text the plain part does NOT
contain - otherwise an attacker could show one text in HTML and a harmless one in plain.
"""
from __future__ import annotations

import email
import email.policy
import mimetypes
from email.message import Message

from .base import Out, ParseContext, RawSeg, alnum_key, decode_text
from .html_parser import parse_html_raw

HEADERS = ("Subject", "From", "Reply-To", "To", "Cc")
_BODY_TYPES = ("text/plain", "text/html")


def _is_attachment(part: Message) -> bool:
    ctype = part.get_content_type()
    if ctype == "message/rfc822":
        return True
    if part.is_multipart():
        return False
    return (part.get_content_disposition() == "attachment" or bool(part.get_filename())
            or ctype not in _BODY_TYPES)


def _text_content(part: Message) -> str:
    try:
        content = part.get_content()                     # type: ignore[attr-defined]
        if isinstance(content, str):
            return content
    except Exception:  # noqa: BLE001 - unknown charset / broken encoding: decode the bytes ourselves
        pass
    payload = part.get_payload(decode=True)
    return decode_text(payload if isinstance(payload, bytes) else b"")


class _Walker:
    def __init__(self, ctx: ParseContext, out: Out) -> None:
        self.ctx, self.out = ctx, out
        self.n = 0                                       # leaf part counter ("part N")

    def walk(self, part: Message, alt_plain: str | None = None) -> None:
        self.ctx.checkpoint()
        if _is_attachment(part):
            self.n += 1
            self._attachment(part)
            return
        if part.is_multipart():
            subparts = list(part.iter_parts())            # type: ignore[attr-defined]
            if part.get_content_subtype() == "alternative":
                plain = "\n".join(_text_content(p) for p in subparts
                                  if p.get_content_type() == "text/plain" and not _is_attachment(p))
                alt_plain = alnum_key(plain) if plain.strip() else None
            for sub in subparts:
                self.walk(sub, alt_plain)
            return
        self.n += 1
        ctype = part.get_content_type()
        text = _text_content(part)
        if ctype == "text/plain":
            self.out.add(text, "visible", f"part {self.n} text/plain")
            return
        prefix = f"part {self.n} text/html > "
        for seg in parse_html_raw(text, self.ctx):
            if seg.channel == "visible" and alt_plain is not None and alnum_key(seg.text) in alt_plain:
                self.ctx.shared.chars -= len(seg.text)    # duplicate of the plain alternative
                continue
            seg.location = prefix + seg.location
            self.out.append_raw(seg)

    def _attachment(self, part: Message) -> None:
        from .router import embed_attachment              # lazy: router imports this module

        ctype = part.get_content_type()
        data: bytes | None
        if ctype == "message/rfc822":
            try:
                if part.is_multipart():
                    inner = part.get_payload(0)
                else:
                    inner = part.get_content()           # type: ignore[attr-defined]
                data = inner.as_bytes()
            except Exception:  # noqa: BLE001
                data = None
                self.ctx.warn(f"parse_error: part {self.n} message/rfc822 could not be read")
        else:
            payload = part.get_payload(decode=True)
            data = payload if isinstance(payload, bytes) else None
        extension = ".eml" if ctype == "message/rfc822" else (mimetypes.guess_extension(ctype) or ".bin")
        embed_attachment(self.ctx, self.out, data, name=part.get_filename(), content_type=ctype,
                         fallback_name=f"part{self.n}{extension}")


def parse(data: bytes, ctx: ParseContext, *, filename: str | None = None,
          content_type: str | None = None) -> list[RawSeg]:
    msg = email.message_from_bytes(data, policy=email.policy.default)
    out = Out(ctx)
    for name in HEADERS:
        try:
            values = msg.get_all(name) or []
            for value in values:
                out.add(str(value), "metadata", f"header:{name}", "email_header")
        except Exception:  # noqa: BLE001 - malformed header: skip it, keep parsing
            ctx.warn(f"parse_error: header:{name} could not be decoded")
    _Walker(ctx, out).walk(msg)
    return out.segs
