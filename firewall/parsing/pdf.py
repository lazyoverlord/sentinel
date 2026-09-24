"""PDF (SPEC §6): per-block visible text + hidden-text forensics via PyMuPDF.

Per span (a run of text with one style) the first matching reason wins:
hidden_layer (optional content switched off by default) > render_invisible (render mode 3/7) >
opacity_0 > off_page > white_text / low_contrast (near-white fill; confirmed against the rendered
page, so white text on a dark banner or photo stays visible) > font_lt_2pt.
Consecutive hidden spans with the same reason on a page merge into one segment.
OCR-layer exception: a page with no visible text, an image and invisible text is a scanned page,
so that text is `ocr_layer` (treated as visible).
Also: document metadata / XMP / outline -> metadata, annotations -> comment, form fields ->
metadata, embedded files -> attachment (recursive, depth-limited).
"""
from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field

import pymupdf
from PIL import Image, ImageChops

from .base import (
    LOW_CONTRAST_MAX,
    RGB,
    WHITE,
    WHITE_LUMINANCE,
    Out,
    ParseContext,
    RawSeg,
    alnum_key,
    contrast_ratio,
    luminance,
    rgb_from_int,
    xml_text_items,
)

# MuPDF writes recoverable errors to stderr by default; we surface failures ourselves.
pymupdf.TOOLS.mupdf_display_errors(False)
pymupdf.TOOLS.mupdf_display_warnings(False)

# MuPDF is not thread-safe and parses run in worker threads, so PDF work is serialized.
# Re-entrant because an embedded PDF is parsed while the outer document is still open.
_ENGINE_LOCK = threading.RLock()

# No MEDIABOX_CLIP (we want off-page text) and no image blocks (we don't need pixel data).
_TEXT_FLAGS = pymupdf.TEXTFLAGS_DICT & ~pymupdf.TEXT_MEDIABOX_CLIP & ~pymupdf.TEXT_PRESERVE_IMAGES
_FILLED, _STROKED, _CLIP = 16, 32, 64          # span["char_flags"] bits (FZ_STEXT_FILLED/STROKED/CLIPPED)
FONT_MIN_PT = 2.0
OPACITY_MAX = 0.05
OFF_PAGE_FRACTION = 0.5                        # >= half of the span's box outside the page
MAX_BACKGROUND_RENDERS = 50                    # page renders per document for the white-text check
_RENDER_ZOOM = 2.0
_PIXEL_DIFF = 24                               # 0..255 channel difference that a reader can see
_CONTRAST_PIXELS = 0.03                        # share of differing pixels => text is visible
META_FIELDS = (("title", "Title"), ("author", "Author"), ("subject", "Subject"),
               ("keywords", "Keywords"), ("creator", "Creator"), ("producer", "Producer"))
_ANNOT_SKIP = {pymupdf.PDF_ANNOT_POPUP, pymupdf.PDF_ANNOT_WIDGET}
_SpanKey = tuple[str, tuple[int, ...]]   # (text, rounded bbox): identifies a span across extractions


@dataclass
class _Span:
    idx: int                 # 1-based span number on the page (reading order)
    block: int
    line: int
    text: str
    size: float
    rgb: RGB
    alpha: float
    flags: int
    bbox: pymupdf.Rect
    reason: str | None = None
    channel: str = "visible"


class _Background:
    """Is there visible contrast under a span? Renders the page once, lazily."""

    def __init__(self, page: pymupdf.Page, budget: list[int]) -> None:
        self.page, self.budget = page, budget
        self.image: Image.Image | None = None
        self.tried = False

    def _render(self) -> Image.Image | None:
        if not self.tried:
            self.tried = True
            if self.budget[0] > 0:
                self.budget[0] -= 1
                pix = self.page.get_pixmap(matrix=pymupdf.Matrix(_RENDER_ZOOM, _RENDER_ZOOM),
                                           colorspace=pymupdf.csRGB, alpha=False)
                self.image = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
        return self.image

    def text_visible(self, span: _Span) -> bool:
        """True if pixels under the span differ from the text colour (so the glyphs show)."""
        image = self._render()
        if image is None:
            return False                                 # can't tell: assume a white page (SPEC)
        r = pymupdf.Rect(span.bbox) * self.page.rotation_matrix * _RENDER_ZOOM
        box = (max(0, math.floor(r.x0)), max(0, math.floor(r.y0)),
               min(image.width, math.ceil(r.x1)), min(image.height, math.ceil(r.y1)))
        if box[2] <= box[0] or box[3] <= box[1]:
            return False
        region = image.crop(box)
        solid = Image.new("RGB", region.size, tuple(round(c * 255) for c in span.rgb))
        red, green, blue = ImageChops.difference(region, solid).split()
        diff = ImageChops.lighter(ImageChops.lighter(red, green), blue)
        hist = diff.histogram()
        differing = sum(hist[_PIXEL_DIFF + 1:])
        return differing >= _CONTRAST_PIXELS * region.width * region.height


def _outside_fraction(bbox: pymupdf.Rect, page_rect: pymupdf.Rect) -> float:
    area = bbox.width * bbox.height
    if area <= 0:
        cx, cy = (bbox.x0 + bbox.x1) / 2, (bbox.y0 + bbox.y1) / 2
        return 0.0 if page_rect.contains(pymupdf.Point(cx, cy)) else 1.0
    inside = pymupdf.Rect(bbox) & page_rect
    inside_area = 0.0 if inside.is_empty else inside.width * inside.height
    return 1.0 - inside_area / area


def _span_key(sp: _Span) -> _SpanKey:
    return sp.text, tuple(round(v) for v in sp.bbox)


def _page_spans(page: pymupdf.Page) -> list[_Span]:
    data = page.get_text("dict", flags=_TEXT_FLAGS, clip=pymupdf.INFINITE_RECT())
    spans: list[_Span] = []
    idx = line_no = 0
    for b_i, block in enumerate(data.get("blocks", [])):
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            line_no += 1
            for s in line.get("spans", []):
                idx += 1
                spans.append(_Span(idx, b_i, line_no, s.get("text", ""), float(s.get("size", 0)),
                                   rgb_from_int(int(s.get("color", 0))), s.get("alpha", 255) / 255,
                                   int(s.get("char_flags", _FILLED)), pymupdf.Rect(s["bbox"])))
    # Render modes 4-6 (fill/stroke + clip) emit each glyph twice; drop the clip-only twin.
    painted = {_span_key(sp) for sp in spans if not sp.flags & _CLIP}
    return [sp for sp in spans if not (sp.flags & _CLIP and sp.alpha == 0 and _span_key(sp) in painted)]


def _hidden_layer_baseline(doc: pymupdf.Document, ctx: ParseContext) -> dict[int, set[_SpanKey]] | None:
    """Optional content switched off by default is not extracted at all. If the document has
    such layers: record each page's default-visible spans, then switch every layer on, so the
    extra spans can be reported as `hidden_layer`. None when there is nothing to do."""
    try:
        off = [cfg for cfg in doc.layer_ui_configs() if not cfg.get("on")]
        ocgs_off = any(not info.get("on") for info in (doc.get_ocgs() or {}).values())
    except Exception:  # noqa: BLE001 - broken optional-content dictionary
        return None
    if not off:
        if ocgs_off:
            ctx.warn("limit: PDF has hidden optional-content layers that could not be enabled")
        return None
    baseline: dict[int, set[_SpanKey]] = {}
    for page_no, page in enumerate(doc, 1):
        ctx.checkpoint()
        baseline[page_no] = {_span_key(sp) for sp in _page_spans(page)}
    for cfg in off:
        doc.set_layer_ui_config(cfg["number"], 0)        # action 0 = switch on
    return baseline


def _classify(span: _Span, page_rect: pymupdf.Rect, background: _Background) -> str | None:
    if not span.flags & (_FILLED | _STROKED) or (span.flags & _CLIP and span.alpha == 0):
        return "render_invisible"                        # text render mode 3 (or 7: clip only)
    if span.alpha <= OPACITY_MAX:
        return "opacity_0"
    if _outside_fraction(span.bbox, page_rect) >= OFF_PAGE_FRACTION:
        return "off_page"
    if contrast_ratio(span.rgb, WHITE) < LOW_CONTRAST_MAX and not background.text_visible(span):
        return "white_text" if luminance(span.rgb) > WHITE_LUMINANCE else "low_contrast"
    if span.size < FONT_MIN_PT:
        return "font_lt_2pt"
    return None


@dataclass
class _Pending:
    """A segment being assembled from consecutive spans (new line => newline)."""

    key: object              # block number (visible run) or hidden reason (hidden run)
    seg: RawSeg
    parts: list[str] = field(default_factory=list)
    line: int = -1

    def add(self, sp: _Span) -> None:
        if self.parts and sp.line != self.line:
            self.parts.append("\n")
        self.parts.append(sp.text)
        self.line = sp.line


def _emit_page(spans: list[_Span], page_no: int, out: Out) -> str:
    """Block-grouped visible segments + merged hidden segments; returns the page's visible text."""
    vis: _Pending | None = None
    hid: _Pending | None = None
    page_text: list[str] = []

    def close(pending: _Pending | None) -> None:
        if pending is not None:
            text = "".join(pending.parts)
            out.fill(pending.seg, text)
            if pending.seg.channel != "hidden":
                page_text.append(text)

    for sp in spans:
        if not sp.text:
            continue
        if not sp.text.strip():                          # whitespace joins whatever is open
            if hid is not None or vis is not None:
                (hid or vis).parts.append(sp.text)      # type: ignore[union-attr]
            continue
        location = f"page {page_no} · span {sp.idx}"
        if sp.reason is None:                            # visible (or ocr_layer): grouped per block
            close(hid)
            hid = None
            if vis is None or vis.key != sp.block:
                close(vis)
                vis = _Pending(sp.block, out.reserve(sp.channel, location))  # type: ignore[arg-type]
            vis.add(sp)
        else:                                            # hidden: merged while the reason repeats
            if hid is None or hid.key != sp.reason:
                close(hid)
                hid = _Pending(sp.reason, out.reserve("hidden", location, sp.reason))
            hid.add(sp)
    close(vis)
    close(hid)
    return "\n".join(page_text)


def _page(page: pymupdf.Page, page_no: int, out: Out, ctx: ParseContext, render_budget: list[int],
          default_visible: set[_SpanKey] | None) -> None:
    spans = _page_spans(page)
    # text coordinates are unrotated; compare with the unrotated visible area (CropBox)
    page_rect = pymupdf.Rect(0, 0, page.cropbox.width, page.cropbox.height)
    background = _Background(page, render_budget)
    for sp in spans:
        if not sp.text.strip():
            continue
        if default_visible is not None and _span_key(sp) not in default_visible:
            sp.reason = "hidden_layer"                   # only shows once hidden layers are switched on
        else:
            sp.reason = _classify(sp, page_rect, background)
    # OCR-layer exception: scanned page = image + invisible text and nothing else visible
    has_visible = any(sp.reason is None and sp.text.strip() for sp in spans)
    if not has_visible and any(sp.reason == "render_invisible" for sp in spans) and page.get_image_info():
        for sp in spans:
            if sp.reason == "render_invisible":
                sp.reason, sp.channel = None, "ocr_layer"
    visible_key = alnum_key(_emit_page(spans, page_no, out))

    from .router import embed_attachment                 # lazy: router imports this module

    for n, annot in enumerate(page.annots() or [], 1):
        kind = annot.type[0]
        if kind in _ANNOT_SKIP:
            continue
        if kind == pymupdf.PDF_ANNOT_FILE_ATTACHMENT:
            try:
                info = annot.file_info
                embed_attachment(ctx, out, annot.get_file(), name=info.get("filename"), content_type=None,
                                 fallback_name=f"page{page_no}-annotation{n}.bin")
            except Exception as exc:  # noqa: BLE001
                ctx.warn(f"parse_error: page {page_no} file annotation {n}: {type(exc).__name__}")
            continue
        info = annot.info or {}
        text = "\n".join(v.strip() for v in (info.get("subject"), info.get("content")) if v and v.strip())
        if text and alnum_key(text) not in visible_key:  # FreeText annotations are already page text
            out.add(text, "comment", f"page {page_no} · annotation {n}", "pdf_annotation")
    for widget in page.widgets() or []:
        values = [v for v in (widget.field_value, widget.field_label) if isinstance(v, str) and v.strip()]
        text = "\n".join(v for v in values if alnum_key(v) not in visible_key)
        out.add(text, "metadata", f"page {page_no} · field {widget.field_name or '?'}", "pdf_form_field")


def _metadata(doc: pymupdf.Document, out: Out) -> None:
    meta = doc.metadata or {}
    seen: set[str] = set()
    for key, label in META_FIELDS:
        value = meta.get(key) or ""
        if value.strip():
            out.add(value, "metadata", f"PDF:metadata:{label}", "pdf_metadata")
            seen.add(alnum_key(value))
    try:
        xmp = doc.get_xml_metadata()
        items = xml_text_items(xmp) if xmp and xmp.strip() else []
    except Exception:  # noqa: BLE001 - broken XMP packet: skip it
        items = []
    for name, value in items:
        if alnum_key(value) not in seen:
            seen.add(alnum_key(value))
            out.add(value, "metadata", f"PDF:xmp:{name}", "pdf_xmp")
    for n, entry in enumerate(doc.get_toc(simple=True) or [], 1):
        out.add(str(entry[1]), "metadata", f"PDF:outline:{n}", "pdf_outline")


def _embedded_files(doc: pymupdf.Document, out: Out, ctx: ParseContext) -> None:
    from .router import embed_attachment

    for i in range(doc.embfile_count()):
        info = doc.embfile_info(i)
        name = info.get("filename") or info.get("name") or f"embedded-{i + 1}"
        if info.get("description") and info["description"] != name:
            out.add(info["description"], "metadata", f"attachment:{name} · description",
                    "pdf_embedded_description")
        size = int(info.get("size") or info.get("length") or 0)
        if size > ctx.settings.MAX_FILE_BYTES:
            ctx.warn(f"limit: attachment:{name} is {size} bytes (> MAX_FILE_BYTES); not parsed")
            embed_attachment(ctx, out, None, name=name, content_type=None)
            continue
        embed_attachment(ctx, out, doc.embfile_get(i), name=name, content_type=None)


def parse(data: bytes, ctx: ParseContext, *, filename: str | None = None,
          content_type: str | None = None) -> list[RawSeg]:
    if not _ENGINE_LOCK.acquire(timeout=max(0.1, ctx.remaining())):
        raise TimeoutError("PDF engine busy")
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
        try:
            if doc.needs_pass and not doc.authenticate(""):
                raise ValueError("encrypted PDF (password required)")
            if doc.page_count == 0:
                raise ValueError("PDF has no pages")
            out = Out(ctx)
            _metadata(doc, out)
            render_budget = [MAX_BACKGROUND_RENDERS]
            baseline = _hidden_layer_baseline(doc, ctx)
            for page_no, page in enumerate(doc, 1):
                ctx.checkpoint()
                if out.full:
                    break
                _page(page, page_no, out, ctx, render_budget,
                      baseline.get(page_no, set()) if baseline is not None else None)
            if not out.full:
                _embedded_files(doc, out, ctx)
            return out.segs
        finally:
            doc.close()
    finally:
        _ENGINE_LOCK.release()
