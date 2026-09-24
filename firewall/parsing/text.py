"""Plain text (SPEC §6): the whole file is one visible segment."""
from __future__ import annotations

from .base import ParseContext, RawSeg, decode_text


def parse(data: bytes, ctx: ParseContext, *, filename: str | None = None,
          content_type: str | None = None) -> list[RawSeg]:
    return [RawSeg(decode_text(data), "visible", "text")]
