"""Images (SPEC §6): two OCR passes + image metadata.

Pass 1 reads the image as a person would see it -> `ocr` (one segment per OCR line).
Pass 2 enhances contrast (grayscale -> autocontrast(cutoff=1) -> equalize -> binarize at 128,
plus the inverted image) to reveal near-invisible text; lines missing from pass 1 are
`ocr_enhanced` / `low_contrast`.

Two additions (see the owner report): tesseract binarizes adaptively, so on an image that holds
ONLY faint text it reads #F8F8F8-on-white in pass 1 - every pass-1 line is therefore contrast-
checked and demoted to `ocr_enhanced` when a reader could not see it. And when faint text shares
the image with dark text, equalization maps the faint text above the 128 threshold, so pass 2
also runs a "background deviation" binarization (ink = any pixel off the dominant background).
EXIF / XMP / PNG text chunks / comments -> `metadata`. Deterministic OCR only (no LLM here).
"""
from __future__ import annotations

import functools
import io
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import pytesseract
from PIL import Image, ImageOps
from rapidfuzz import fuzz

from .base import LOW_CONTRAST_MAX, Out, ParseContext, RawSeg, contrast_ratio, xml_text_items

UPSCALE_BELOW = 1000              # upscale x2 when the smaller side is below this
MAX_OCR_PIXELS = 36_000_000       # never upscale beyond / downscale above this many pixels
OCR_CALL_TIMEOUT_S = 8.0
FUZZ_SAME_LINE = 80               # partial_ratio >= this: the same line
PASS2_MIN_CONF = 50.0             # pass-2 lines below this mean confidence are noise
BACKGROUND_DELTA = 6              # grey levels off the background that count as ink
_INK_SHARE = 0.05                 # the most-deviating 5% of a line's pixels are its ink

_EXIF_TAGS = {0x010E: "ImageDescription", 0x013B: "Artist", 0x8298: "Copyright",
              0x9C9B: "XPTitle", 0x9C9C: "XPComment", 0x9C9D: "XPAuthor", 0x9C9E: "XPKeywords",
              0x9C9F: "XPSubject"}
_EXIF_IFD = 0x8769
_EXIF_IFD_TAGS = {0x9286: "UserComment"}


@dataclass
class OcrLine:
    text: str
    conf: float
    box: tuple[int, int, int, int]     # left, top, right, bottom


@functools.lru_cache(maxsize=1)
def tesseract_available() -> bool:
    try:
        pytesseract.get_tesseract_version()
        return True
    except Exception:  # noqa: BLE001 - binary missing or broken
        return False


# ---------------------------------------------------------------- metadata

def _decode_exif(tag: int, value: object) -> str:
    if isinstance(value, tuple) and all(isinstance(v, int) for v in value):
        value = bytes(value)
    if isinstance(value, bytes):
        if tag in (0x9C9B, 0x9C9C, 0x9C9D, 0x9C9E, 0x9C9F):         # Windows XP* tags: UTF-16LE
            return value.decode("utf-16-le", errors="replace").rstrip("\x00")
        if tag == 0x9286:                                             # UserComment: 8-byte charset code
            code, body = value[:8], value[8:]
            if code.startswith(b"UNICODE"):
                encoding = "utf-16-be" if body[:1] == b"\x00" else "utf-16-le"
                return body.decode(encoding, errors="replace").rstrip("\x00")
            return body.decode("utf-8", errors="replace").rstrip("\x00")
        return value.decode("utf-8", errors="replace").rstrip("\x00")
    return str(value).rstrip("\x00")


def _metadata(img: Image.Image, out: Out) -> None:
    try:
        exif = img.getexif()
    except Exception:  # noqa: BLE001 - corrupt EXIF block
        exif = None
    if exif:
        for tag, name in _EXIF_TAGS.items():
            if tag in exif:
                out.add(_decode_exif(tag, exif[tag]), "metadata", f"EXIF:{name}", "exif")
        try:
            ifd = exif.get_ifd(_EXIF_IFD)
        except Exception:  # noqa: BLE001
            ifd = {}
        for tag, name in _EXIF_IFD_TAGS.items():
            if tag in ifd:
                out.add(_decode_exif(tag, ifd[tag]), "metadata", f"EXIF:{name}", "exif")
    xmp = img.info.get("xmp") or img.info.get("XML:com.adobe.xmp")
    if xmp:
        try:
            seen: set[str] = set()
            for name, value in xml_text_items(xmp):
                if value not in seen:
                    seen.add(value)
                    out.add(value, "metadata", f"XMP:{name}", "xmp")
        except Exception:  # noqa: BLE001 - unparsable packet: keep the raw text
            raw = xmp.decode("utf-8", "replace") if isinstance(xmp, bytes) else str(xmp)
            out.add(raw, "metadata", "XMP:packet", "xmp")
    for key, value in (getattr(img, "text", None) or {}).items():     # PNG tEXt / zTXt / iTXt
        if key != "XML:com.adobe.xmp":
            out.add(str(value), "metadata", f"PNG:text:{key}", "png_text")
    comment = img.info.get("comment")
    if comment:
        text = comment.decode("utf-8", "replace") if isinstance(comment, bytes) else str(comment)
        out.add(text, "metadata", f"{img.format or 'IMG'}:comment", "img_comment")


# ---------------------------------------------------------------- OCR helpers

def _prepare(img: Image.Image, ctx: ParseContext) -> Image.Image:
    """First frame, alpha composited on white (what a viewer shows), sized for OCR."""
    frames = getattr(img, "n_frames", 1)
    if frames > 1:
        img.seek(0)
        ctx.warn(f"ocr: only the first of {frames} frames was read")
    if img.mode in ("RGBA", "LA", "PA") or (img.mode == "P" and "transparency" in img.info):
        rgba = img.convert("RGBA")
        canvas = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        img = Image.alpha_composite(canvas, rgba)
    rgb = img.convert("RGB")
    w, h = rgb.size
    if min(w, h) < UPSCALE_BELOW and w * h * 4 <= MAX_OCR_PIXELS:
        rgb = rgb.resize((w * 2, h * 2), Image.Resampling.LANCZOS)
    elif w * h > MAX_OCR_PIXELS:
        scale = (MAX_OCR_PIXELS / (w * h)) ** 0.5
        rgb = rgb.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.Resampling.LANCZOS)
        ctx.warn(f"ocr: image downscaled from {w}x{h} for OCR")
    return rgb


def _binarize(gray: Image.Image) -> Image.Image:
    """SPEC pass 2: autocontrast(cutoff=1) -> equalize -> threshold 128."""
    enhanced = ImageOps.equalize(ImageOps.autocontrast(gray, cutoff=1))
    return enhanced.point(lambda v: 255 if v >= 128 else 0)


def _background_deviation(gray: Image.Image) -> Image.Image:
    """Black ink wherever a pixel differs from the dominant (background) grey level."""
    hist = gray.histogram()
    background = max(range(256), key=hist.__getitem__)
    lut = [0 if abs(v - background) > BACKGROUND_DELTA else 255 for v in range(256)]
    return gray.point(lut)


def _ocr_lines(image: Image.Image, lang: str, timeout: float) -> list[OcrLine]:
    data = pytesseract.image_to_data(image, lang=lang, output_type=pytesseract.Output.DICT, timeout=timeout)
    lines: dict[tuple[int, int, int], list[int]] = {}
    for i, word in enumerate(data["text"]):
        try:
            conf = float(data["conf"][i])
        except (TypeError, ValueError):
            conf = -1.0
        if word and word.strip() and conf >= 0:
            lines.setdefault((data["block_num"][i], data["par_num"][i], data["line_num"][i]), []).append(i)
    result: list[OcrLine] = []
    for idxs in lines.values():                  # dicts keep insertion (reading) order
        text = " ".join(data["text"][i].strip() for i in idxs)
        if sum(ch.isalnum() for ch in text) < 2:
            continue
        conf = sum(float(data["conf"][i]) for i in idxs) / len(idxs)
        box = (min(data["left"][i] for i in idxs), min(data["top"][i] for i in idxs),
               max(data["left"][i] + data["width"][i] for i in idxs),
               max(data["top"][i] + data["height"][i] for i in idxs))
        result.append(OcrLine(text, conf, box))
    return result


def _gray_rgb(level: float) -> tuple[float, float, float]:
    return (level / 255, level / 255, level / 255)


def line_contrast(gray: Image.Image, box: tuple[int, int, int, int]) -> float:
    """WCAG contrast between a line's background (most common grey) and its ink."""
    region = gray.crop(box)
    hist = region.histogram()
    total = sum(hist)
    if total == 0:
        return 21.0
    background = max(range(256), key=hist.__getitem__)
    darker = sum(hist[:background])
    lighter = sum(hist[background + 1:])
    # ink lies on the side of the background with more pixels; take its extreme 5% level
    need = max(1, int(total * _INK_SHARE))
    count, ink = 0, background
    levels = range(0, background) if darker >= lighter else range(255, background, -1)
    for level in levels:
        count += hist[level]
        if count >= need:
            ink = level
            break
    return contrast_ratio(_gray_rgb(background), _gray_rgb(ink))


def _matches(text: str, others: list[str]) -> bool:
    low = text.lower()
    return any(fuzz.partial_ratio(low, other.lower()) >= FUZZ_SAME_LINE for other in others)


# ---------------------------------------------------------------- entry point

def parse(data: bytes, ctx: ParseContext, *, filename: str | None = None,
          content_type: str | None = None) -> list[RawSeg]:
    img = Image.open(io.BytesIO(data))          # MAX_IMAGE_PIXELS stays at Pillow's default (bomb guard)
    img.load()
    out = Out(ctx)
    _metadata(img, out)
    if not tesseract_available():
        ctx.warn("ocr: tesseract unavailable; only image metadata was extracted")
        return out.segs
    rgb = _prepare(img, ctx)
    gray = rgb.convert("L")
    binary = _binarize(gray)
    passes = {                                   # label -> image; pass 1 first
        "OCR pass 1": rgb,
        "OCR pass 2": binary,
        "OCR pass 2 inverted": ImageOps.invert(binary),
        "OCR pass 2 background": _background_deviation(gray),
    }
    ctx.checkpoint()
    timeout = max(1.0, min(OCR_CALL_TIMEOUT_S, ctx.remaining() - 0.5))
    lang = ctx.settings.OCR_LANGS or "eng"
    results: dict[str, list[OcrLine]] = {}
    # tesseract runs as a subprocess, so the passes can run in parallel threads
    with ThreadPoolExecutor(max_workers=len(passes), thread_name_prefix="sentinel-ocr") as pool:
        futures = {label: pool.submit(_ocr_lines, image, lang, timeout) for label, image in passes.items()}
        for label, future in futures.items():
            try:
                results[label] = future.result()
            except Exception as exc:  # noqa: BLE001 - timeout / tesseract error: keep the other passes
                ctx.warn(f"ocr: {label} failed ({type(exc).__name__}: {' '.join(str(exc).split())[:80]})")
                results[label] = []
    ctx.checkpoint()

    pass1 = results.pop("OCR pass 1")
    for n, line in enumerate(pass1, 1):
        location = f"OCR pass 1 · line {n} · conf {round(line.conf)}"
        if line_contrast(gray, line.box) < LOW_CONTRAST_MAX:
            out.add(line.text, "ocr_enhanced", location, "low_contrast")    # tesseract saw it; a reader wouldn't
        else:
            out.add(line.text, "ocr", location)
    known = [line.text for line in pass1]
    for label, lines in results.items():
        for n, line in enumerate(lines, 1):
            if line.conf < PASS2_MIN_CONF or _matches(line.text, known):
                continue
            known.append(line.text)
            out.add(line.text, "ocr_enhanced", f"{label} · line {n} · conf {round(line.conf)}", "low_contrast")
    return out.segs
