"""Document parsing (SPEC §6): untrusted bytes -> ParsedContent (segments tagged by channel).

Public API (the pipeline and API code against exactly this):
    parse(data, *, filename, content_type, source_type, settings) -> ParsedContent
    parse_text(text, *, source_type, settings) -> ParsedContent
    detect_format(data, filename, content_type) -> str
    ParseLimitError  (.reason) - raised only for hard size limits; the input must be rejected

Warning prefixes: "parse_error: ", "truncated: ", "recursion_limit: ", "ocr: ", "limit: ".
"""
from __future__ import annotations

import concurrent.futures
import threading
import time

from firewall.config import Settings
from firewall.schemas import ParsedContent, Source

from .base import (
    ParseCancelled,
    ParseContext,
    ParseLimitError,
    RawSeg,
    describe_error,
    fallback_segments,
    finalize,
)
from .router import detect_format, run_parser

__all__ = ["ParseLimitError", "parse", "parse_text", "detect_format"]

# The worker's own deadline is a little later than the caller's wait, so the caller always
# times out first and the worker's cancellation can't race it.
_WORKER_GRACE_S = 0.5


def parse_text(text: str, *, source_type: Source, settings: Settings) -> ParsedContent:
    """Plain text input: one visible segment at location "text" (MAX_TEXT_CHARS applies)."""
    return finalize("text", source_type, [RawSeg(text, "visible", "text")], [], settings)


def parse(data: bytes, *, filename: str | None, content_type: str | None, source_type: Source,
          settings: Settings) -> ParsedContent:
    """Parse an uploaded/retrieved file into segments.

    Raises ParseLimitError for size limits (file > MAX_FILE_BYTES, zip bombs). Any other parser
    failure or a timeout returns the UTF-8 text fallback with a "parse_error: ..." warning.
    """
    if len(data) > settings.MAX_FILE_BYTES:
        raise ParseLimitError(f"file is {len(data)} bytes (limit MAX_FILE_BYTES={settings.MAX_FILE_BYTES})")
    fmt = detect_format(data, filename, content_type)
    timeout = settings.PARSE_TIMEOUT_S
    ctx = ParseContext(settings, deadline=time.monotonic() + timeout + _WORKER_GRACE_S)
    future: concurrent.futures.Future[list[RawSeg]] = concurrent.futures.Future()

    def work() -> None:
        try:
            future.set_result(run_parser(fmt, data, filename, content_type, ctx))
        except BaseException as exc:  # noqa: BLE001 - handed to the waiting caller
            future.set_exception(exc)

    # A daemon thread rather than a ThreadPoolExecutor: Python can't kill threads, and a stuck
    # executor worker would block interpreter exit. On timeout we stop waiting, set the cancel
    # flag (parsers stop at their next checkpoint) and discard whatever the thread returns later.
    threading.Thread(target=work, name=f"sentinel-parse-{fmt}", daemon=True).start()
    try:
        raw = future.result(timeout=timeout)
    except ParseLimitError:
        raise
    except (concurrent.futures.TimeoutError, ParseCancelled) as exc:
        if isinstance(exc, ParseCancelled) or not future.done():
            ctx.shared.cancel.set()
            return _fallback(data, source_type, settings, "TimeoutError: timeout")
        return _fallback(data, source_type, settings, describe_error(exc))
    except Exception as exc:  # noqa: BLE001 - any parser failure => text fallback
        return _fallback(data, source_type, settings, describe_error(exc))
    return finalize(fmt, source_type, raw, ctx.warnings, settings, truncated=ctx.shared.stopped_early)


def _fallback(data: bytes, source_type: Source, settings: Settings, reason: str) -> ParsedContent:
    segs, truncated = fallback_segments(data, settings)
    return finalize("text", source_type, segs, [f"parse_error: {reason}"], settings, truncated=truncated)
