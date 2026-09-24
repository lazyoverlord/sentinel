"""HTML (SPEC §6): visible text per block element + hidden-content forensics.

Hidden status is inherited: the outermost hidden element is reported once, as one `hidden`
segment holding all of its text, with its reason. Understood: inline styles, the `hidden` and
aria-hidden attributes, common "visually hidden" classes, <template>, <noscript>, hidden inputs,
and simple <style> rules (any selector soupsieve can match). Comments -> `comment`; <title>,
<meta>, alt/title/aria-label/placeholder attributes and JSON-LD -> `metadata`. Scripts and
styles are never executed; their text is ignored (except JSON-LD). URLs are never fetched.
"""
from __future__ import annotations

import colorsys
import json
import re
from collections import Counter
from collections.abc import Iterator, Mapping
from typing import Any

from bs4 import BeautifulSoup, Comment, NavigableString, Tag
from bs4.element import Declaration, Doctype, ProcessingInstruction

from .base import (
    BLACK,
    LOW_CONTRAST_MAX,
    RGB,
    WHITE,
    Out,
    ParseContext,
    RawSeg,
    contrast_ratio,
    decode_text,
)
from .structured import walk_json

BLOCK_TAGS = frozenset("""
    p div li td th h1 h2 h3 h4 h5 h6 section article blockquote pre header footer main body
    ul ol dl dt dd table tr thead tbody tfoot caption nav aside figure figcaption form fieldset
    legend address details summary dialog hr center menu
""".split())
_PRE_TAGS = frozenset({"pre", "textarea", "listing", "plaintext", "xmp"})
HIDDEN_CLASSES = frozenset({"sr-only", "visually-hidden", "visuallyhidden", "screen-reader-text",
                            "hidden", "d-none", "invisible"})
_META_SKIP = frozenset({"viewport", "theme-color", "color-scheme", "format-detection", "referrer",
                        "content-type", "x-ua-compatible", "refresh"})
_NEWLINE = object()                     # marker used by _text_of
_WS = re.compile(r"[ \t\n\r\f]+")
_CHECK_EVERY = 2000

# ---------------------------------------------------------------- CSS helpers

_NAMED_COLORS: dict[str, tuple[int, int, int]] = {
    "white": (255, 255, 255), "black": (0, 0, 0), "red": (255, 0, 0), "green": (0, 128, 0),
    "blue": (0, 0, 255), "yellow": (255, 255, 0), "orange": (255, 165, 0), "purple": (128, 0, 128),
    "gray": (128, 128, 128), "grey": (128, 128, 128), "silver": (192, 192, 192),
    "lightgray": (211, 211, 211), "lightgrey": (211, 211, 211), "gainsboro": (220, 220, 220),
    "whitesmoke": (245, 245, 245), "snow": (255, 250, 250), "ivory": (255, 255, 240),
    "ghostwhite": (248, 248, 255), "floralwhite": (255, 250, 240), "azure": (240, 255, 255),
    "mintcream": (245, 255, 250), "honeydew": (240, 255, 240), "aliceblue": (240, 248, 255),
    "seashell": (255, 245, 238), "linen": (250, 240, 230), "oldlace": (253, 245, 230),
    "beige": (245, 245, 220), "cornsilk": (255, 248, 220), "lavenderblush": (255, 240, 245),
    "darkgray": (169, 169, 169), "darkgrey": (169, 169, 169), "dimgray": (105, 105, 105),
    "dimgrey": (105, 105, 105), "navy": (0, 0, 128), "maroon": (128, 0, 0), "olive": (128, 128, 0),
    "teal": (0, 128, 128), "lime": (0, 255, 0), "aqua": (0, 255, 255), "cyan": (0, 255, 255),
    "fuchsia": (255, 0, 255), "magenta": (255, 0, 255), "pink": (255, 192, 203),
}
_FONT_KEYWORDS = {"xx-small": 9.0, "x-small": 10.0, "small": 13.0, "medium": 16.0, "large": 18.0,
                  "x-large": 24.0, "xx-large": 32.0, "xxx-large": 48.0}
_UNIT_PX = {"px": 1.0, "pt": 4 / 3, "pc": 16.0, "in": 96.0, "cm": 37.8, "mm": 3.78, "q": 0.945,
            "em": 16.0, "rem": 16.0, "ex": 8.0, "ch": 8.0, "%": 0.16,
            "vw": 10.0, "vh": 10.0, "vmin": 10.0, "vmax": 10.0}
_LENGTH = re.compile(r"(-?\d*\.?\d+)\s*(px|pt|pc|in|cm|mm|q|em|rem|ex|ch|%|vw|vh|vmin|vmax)?")
_COLOR_TOKEN = re.compile(r"#[0-9a-f]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)|\b[a-z]+\b")


def parse_style(style: Any) -> dict[str, str]:
    """Inline style string -> {property: value} (lower-case, !important removed)."""
    if not style:
        return {}
    text = re.sub(r"/\*.*?\*/", "", str(style), flags=re.S)
    out: dict[str, str] = {}
    for decl in text.split(";"):
        prop, sep, value = decl.partition(":")
        if sep and prop.strip():
            out[prop.strip().lower()] = value.lower().replace("!important", "").strip()
    return out


def css_px(value: str | None) -> float | None:
    """CSS length -> px (em/rem/% relative to 16px; viewport units assume ~1000px)."""
    if value is None:
        return None
    v = value.strip().lower()
    if v in _FONT_KEYWORDS:
        return _FONT_KEYWORDS[v]
    m = _LENGTH.fullmatch(v)
    if not m:
        return None
    return float(m.group(1)) * _UNIT_PX[m.group(2) or "px"]


def _font_size_px(style: Mapping[str, str]) -> float | None:
    if "font-size" in style:
        return css_px(style["font-size"])
    tokens = style.get("font", "").split()
    for i, tok in enumerate(tokens[:-1]):               # the size comes before the family name
        size = tok.split("/", 1)[0]
        unitless = size.replace(".", "").isdigit()              # e.g. a font-weight like 700
        if size in _FONT_KEYWORDS or (_LENGTH.fullmatch(size) and (size == "0" or not unitless)):
            return css_px(size)
    return None


def _number(value: str | None) -> float | None:
    if not value:
        return None
    m = re.fullmatch(r"\s*(-?\d*\.?\d+)\s*(%?)\s*", value)
    if not m:
        return None
    return float(m.group(1)) / (100 if m.group(2) else 1)


def parse_css_color(value: str | None) -> tuple[RGB, float] | None:
    """CSS colour -> (rgb 0..1, alpha 0..1); None if unknown."""
    if not value:
        return None
    v = value.strip().lower()
    if v == "transparent":
        return (BLACK, 0.0)
    if v in _NAMED_COLORS:
        r, g, b = _NAMED_COLORS[v]
        return ((r / 255, g / 255, b / 255), 1.0)
    if v.startswith("#"):
        h = v[1:]
        if len(h) in (3, 4):
            h = "".join(ch * 2 for ch in h)
        if len(h) in (6, 8) and all(ch in "0123456789abcdef" for ch in h):
            alpha = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
            return ((int(h[0:2], 16) / 255, int(h[2:4], 16) / 255, int(h[4:6], 16) / 255), alpha)
        return None
    m = re.fullmatch(r"(rgba?|hsla?)\(\s*([^)]*)\)", v)
    if not m:
        return None
    parts = [p for p in re.split(r"[\s,/]+", m.group(2).strip()) if p]
    if len(parts) < 3:
        return None
    try:
        alpha = 1.0
        if len(parts) >= 4:
            alpha = float(parts[3].rstrip("%")) / (100 if parts[3].endswith("%") else 1)
        if m.group(1).startswith("rgb"):
            rgb = tuple(min(1.0, max(0.0, float(p.rstrip("%")) / (100 if p.endswith("%") else 255)))
                        for p in parts[:3])
        else:
            hue = float(parts[0].rstrip("deg")) / 360
            sat, light = float(parts[1].rstrip("%")) / 100, float(parts[2].rstrip("%")) / 100
            rgb = colorsys.hls_to_rgb(hue % 1.0, light, sat)
    except ValueError:
        return None
    return ((rgb[0], rgb[1], rgb[2]), alpha)


def _background_color(style: Mapping[str, str]) -> RGB | None:
    if "background-color" in style:
        parsed = parse_css_color(style["background-color"])
        return parsed[0] if parsed and parsed[1] > 0.5 else None
    bg = style.get("background", "")
    if not bg or "url(" in bg or "gradient(" in bg:
        return None                                     # an image background: colour unknown
    for tok in _COLOR_TOKEN.findall(bg):
        parsed = parse_css_color(tok)
        if parsed:
            return parsed[0] if parsed[1] > 0.5 else None
    return None


def _nearly_same(a: RGB, b: RGB) -> bool:
    """Colours a reader can't tell apart (low luminance contrast and similar channels)."""
    return contrast_ratio(a, b) < LOW_CONTRAST_MAX and max(abs(x - y) for x, y in zip(a, b)) <= 40 / 255


def style_reason(style: Mapping[str, str]) -> str | None:
    """Hiding technique expressed by a set of CSS declarations, or None."""
    if style.get("display", "").split()[:1] == ["none"]:
        return "display_none"
    if style.get("visibility") in ("hidden", "collapse"):
        return "visibility_hidden"
    opacity = _number(style.get("opacity"))
    filter_zero = re.search(r"opacity\(\s*0*\.?0*%?\s*\)", style.get("filter", ""))
    if (opacity is not None and opacity <= 0.05) or filter_zero:
        return "opacity_0"
    size = _font_size_px(style)
    if size is not None and size <= 1:
        return "font_size_0"
    color = parse_css_color(style.get("color"))
    if color is not None and color[1] <= 0.05:
        return "opacity_0"                              # transparent text
    if color is not None and (bg := _background_color(style)) is not None and _nearly_same(color[0], bg):
        return "same_color"
    if _offscreen(style):
        return "offscreen"
    if _clipped(style):
        return "clipped"
    if _zero_size(style):
        return "zero_size"
    return None


def _offscreen(style: Mapping[str, str]) -> bool:
    if style.get("position") in ("absolute", "fixed"):
        for side in ("left", "top", "right", "bottom"):
            px = css_px(style.get(side))
            if px is not None and px <= -1000:
                return True
    indent = css_px(style.get("text-indent"))
    if indent is not None and indent <= -999:
        return True
    for margin in ("margin-left", "margin-top"):
        px = css_px(style.get(margin))
        if px is not None and px <= -1000:
            return True
    m = re.search(r"translate(?:x|y|3d)?\(\s*(-\d+(?:\.\d+)?)\s*(px)?", style.get("transform", ""))
    return bool(m and float(m.group(1)) <= -1000)


def _clipped(style: Mapping[str, str]) -> bool:
    clip = style.get("clip", "")
    if clip.startswith("rect("):
        nums = re.findall(r"-?\d*\.?\d+", clip)
        if nums and all(abs(float(n)) <= 1 for n in nums):
            return True
    return bool(re.match(r"(inset\(\s*(50|100)%|circle\(\s*0)", style.get("clip-path", "")))


def _zero_size(style: Mapping[str, str]) -> bool:
    overflow = " ".join(style.get(k, "") for k in ("overflow", "overflow-x", "overflow-y"))
    if "hidden" in overflow or "clip" in overflow:
        for dim in ("width", "height", "max-width", "max-height"):
            px = css_px(style.get(dim))
            if px is not None and px <= 1:
                return True
    return bool(re.search(r"scale\(\s*0(?:\.0+)?\s*[,)]", style.get("transform", "")))


def _class_tokens(value: Any) -> set[str]:
    if not value:
        return set()
    tokens = value if isinstance(value, (list, tuple)) else str(value).split()
    return {str(t).lower() for t in tokens}


def element_hidden_reason(name: str, attrs: Mapping[str, Any],
                          style: Mapping[str, str] | None = None) -> str | None:
    """Reason from an element's own markup (inline style, attributes, classes); no cascade."""
    name = name.lower()
    if name == "template":
        return "template"
    style = dict(style if style is not None else parse_style(attrs.get("style")))
    for key in ("display", "visibility", "opacity", "font-size"):   # SVG presentation attributes
        if key in attrs and key not in style:
            style[key] = str(attrs[key]).strip().lower()
    reason = style_reason(style)
    if reason:
        return reason
    if "hidden" in attrs:
        return "hidden_attr"
    if str(attrs.get("aria-hidden", "")).strip().lower() == "true":
        return "aria_hidden"
    if _class_tokens(attrs.get("class")) & HIDDEN_CLASSES:
        return "class_hidden"
    if name == "noscript":
        return "noscript"
    return None


def iter_css_rules(css: str, _depth: int = 0) -> Iterator[tuple[str, str]]:
    """(selector list, declarations) for top-level rules and rules inside @media/@supports."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    pos, n = 0, len(css)
    while pos < n:
        brace = css.find("{", pos)
        if brace == -1:
            return
        depth, j = 1, brace + 1
        while j < n and depth:
            if css[j] == "{":
                depth += 1
            elif css[j] == "}":
                depth -= 1
            j += 1
        prelude = css[pos:brace].rsplit(";", 1)[-1].strip()   # drop '@import ...;' before a rule
        body = css[brace + 1:j - 1]
        pos = j
        if prelude.startswith("@"):
            at = prelude.split()[0].lower()
            screen = "print" not in prelude.lower() or "screen" in prelude.lower()
            if at in ("@media", "@supports", "@layer", "@container", "@scope") and screen and _depth < 5:
                yield from iter_css_rules(body, _depth + 1)
        elif prelude:
            yield prelude, body


_SIMPLE_SELECTOR = re.compile(r"^(?P<tag>[A-Za-z][\w-]*|\*)?(?P<rest>(?:[.#][\w-]+)*)$")
MAX_COMPLEX_SELECTORS = 100           # soupsieve walks the whole tree per selector: keep it bounded


class _ElementIndex:
    """tag / class / id -> elements, so simple selectors (p, .x, #y, div.x) need no tree walk."""

    def __init__(self, soup: BeautifulSoup) -> None:
        self.all: list[Tag] = soup.find_all(True)
        self.by_tag: dict[str, list[Tag]] = {}
        self.by_class: dict[str, list[Tag]] = {}
        self.by_id: dict[str, list[Tag]] = {}
        for el in self.all:
            self.by_tag.setdefault((el.name or "").lower(), []).append(el)
            for cls in _class_tokens_raw(el.get("class")):
                self.by_class.setdefault(cls, []).append(el)
            if el.get("id"):
                self.by_id.setdefault(str(el.get("id")), []).append(el)

    def select_simple(self, selector: str) -> list[Tag] | None:
        """Matches for a simple selector; None if the selector is not simple."""
        m = _SIMPLE_SELECTOR.match(selector)
        if not m or not (m.group("tag") or m.group("rest")):
            return None
        tag = (m.group("tag") or "*").lower()
        ids = re.findall(r"#([\w-]+)", m.group("rest"))
        classes = re.findall(r"\.([\w-]+)", m.group("rest"))
        if len(ids) > 1:
            return []
        if ids:
            candidates = self.by_id.get(ids[0], [])
        elif classes:
            candidates = self.by_class.get(classes[0], [])
        else:
            candidates = self.all if tag == "*" else self.by_tag.get(tag, [])
        return [el for el in candidates
                if (tag == "*" or (el.name or "").lower() == tag)
                and set(classes) <= _class_tokens_raw(el.get("class"))]


def _class_tokens_raw(value: Any) -> set[str]:
    """Class names as written (CSS class selectors are case-sensitive)."""
    if not value:
        return set()
    return {str(t) for t in (value if isinstance(value, (list, tuple)) else str(value).split())}


def _stylesheet_hidden(soup: BeautifulSoup, style_tags: list[Tag], ctx: ParseContext) -> dict[int, str]:
    """id(element) -> reason for elements hidden by <style> rules."""
    hidden: dict[int, str] = {}
    index: _ElementIndex | None = None
    complex_left = MAX_COMPLEX_SELECTORS
    for style_tag in style_tags:
        for selectors, decls in iter_css_rules(style_tag.get_text()):
            reason = style_reason(parse_style(decls))
            if reason is None:
                continue
            index = index or _ElementIndex(soup)
            for selector in selectors.split(","):
                selector = selector.strip()
                if not selector:
                    continue
                matches = index.select_simple(selector)
                if matches is None:
                    if complex_left <= 0:
                        ctx.warn(f"limit: more than {MAX_COMPLEX_SELECTORS} complex CSS selectors; "
                                 "the rest were ignored")
                        continue
                    complex_left -= 1
                    try:
                        matches = soup.select(selector)
                    except Exception:  # noqa: BLE001 - unsupported/invalid selector: ignore the rule
                        continue
                for el in matches:
                    hidden.setdefault(id(el), reason)
    return hidden


# ---------------------------------------------------------------- walker

class _Walker:
    """Single pass over the tree (iterative, so deep documents can't blow the stack)."""

    def __init__(self, ctx: ParseContext, out: Out, soup: BeautifulSoup) -> None:
        self.ctx, self.out, self.soup = ctx, out, soup
        styling = soup.find_all(["style", "link"])
        style_tags = [t for t in styling if t.name == "style"]
        self.css_hidden = _stylesheet_hidden(soup, style_tags, ctx)
        # any stylesheet may set backgrounds we can't see, so colour checks get conservative
        self.has_css = bool(style_tags) or any(
            "stylesheet" in _class_tokens(t.get("rel")) for t in styling if t.name == "link")
        self.paths: dict[int, str] = {}
        self.blocks: list[str] = []          # locations of the open block elements
        self.cur: RawSeg | None = None       # visible segment being filled
        self.buf: list[str] = []
        self.cur_has_pre = False
        self.pre = 0
        self.n_comment = self.n_img = self.n_jsonld = 0
        self._style_cache: dict[int, dict[str, str]] = {}

    # ----- traversal
    def run(self) -> None:
        self._child_paths(self.soup, "")
        stack: list[tuple[Any, ...]] = [("node", ch, False) for ch in reversed(list(self.soup.children))]
        visited = 0
        while stack:
            item = stack.pop()
            if item[0] == "exit":
                _, is_block, is_pre = item
                if is_pre:
                    self.pre -= 1
                if is_block:
                    self._finish()
                    self.blocks.pop()
                continue
            _, node, hidden = item
            visited += 1
            if visited % _CHECK_EVERY == 0:
                self.ctx.checkpoint()
                if self.out.full:
                    break
            if isinstance(node, Comment):
                self.n_comment += 1
                self.out.add(str(node), "comment", f"html comment {self.n_comment}", "html_comment")
                continue
            if isinstance(node, (Doctype, Declaration, ProcessingInstruction)):
                continue
            if isinstance(node, NavigableString):
                if not hidden:
                    self._text(str(node))
                continue
            if not isinstance(node, Tag):
                continue
            stack.extend(self._enter(node, hidden))
        self._finish()

    def _enter(self, tag: Tag, hidden: bool) -> list[tuple[Any, ...]]:
        name = (tag.name or "").lower()
        path = self.paths.get(id(tag), name)
        if name == "script":
            self._script(tag)
            return []
        if name == "style":
            return []
        self._attribute_metadata(tag, name, path)
        if name == "meta":
            self._meta(tag)
            return []
        if name in ("title", "desc"):
            self.out.add(tag.get_text(" "), "metadata", path, "html_title" if name == "title" else "svg_desc")
            return []
        if name == "input":
            self._input(tag, path, hidden)
            return []
        if not hidden:
            reason = self._reason(tag, name)
            if reason:
                self.out.add(self._text_of(tag), "hidden", path, reason)
                hidden = True
        is_block = name in BLOCK_TAGS and not hidden
        is_pre = name in _PRE_TAGS
        if is_block:
            self._finish()
            self.blocks.append(path)
        if name == "br" and not hidden:
            self._text("\n", raw=True)
        if is_pre:
            self.pre += 1
        self._child_paths(tag, path)
        todo: list[tuple[Any, ...]] = [("exit", is_block, is_pre)]
        todo.extend(("node", ch, hidden) for ch in reversed(list(tag.children)))
        return todo

    def _child_paths(self, parent: Tag | BeautifulSoup, parent_path: str) -> None:
        children = [ch for ch in parent.children if isinstance(ch, Tag)]
        seen: Counter[str] = Counter()
        for ch in children:
            name = (ch.name or "").lower()
            seen[name] += 1
            if name == "html":
                path = ""
            elif name in ("body", "head") and not parent_path:
                path = name
            else:
                step = f"{name}[{seen[name]}]"
                path = f"{parent_path} > {step}" if parent_path else step
            self.paths[id(ch)] = path

    # ----- visible text accumulation
    def _text(self, text: str, *, raw: bool = False) -> None:
        if not raw and not self.pre:
            text = _WS.sub(" ", text)
        if not text:
            return
        if self.cur is None:
            if not text.strip():
                return
            self.cur = self.out.reserve("visible", self.blocks[-1] if self.blocks and self.blocks[-1] else "body")
        if self.pre:
            self.cur_has_pre = True
        self.buf.append(text)

    def _finish(self) -> None:
        if self.cur is None:
            return
        text = "".join(self.buf)
        if not self.cur_has_pre:
            text = re.sub(r" *\n *", "\n", re.sub(r" {2,}", " ", text))
        self.out.fill(self.cur, text.strip())
        self.cur, self.buf, self.cur_has_pre = None, [], False

    # ----- hidden detection
    def _style(self, tag: Tag) -> dict[str, str]:
        key = id(tag)
        if key not in self._style_cache:
            self._style_cache[key] = parse_style(tag.get("style"))
        return self._style_cache[key]

    def _reason(self, tag: Tag, name: str) -> str | None:
        style = self._style(tag)
        reason = element_hidden_reason(name, tag.attrs, style)
        if reason in ("font_size_0", "visibility_hidden") and self._descendant_overrides(tag, reason):
            reason = None           # e.g. the inline-block trick: font-size:0 parent, sized children
        if reason is None and self._same_color(tag, name, style):
            reason = "same_color"
        return reason or self.css_hidden.get(id(tag))

    def _descendant_overrides(self, tag: Tag, reason: str) -> bool:
        for d in tag.find_all(True, style=True):
            s = parse_style(d.get("style"))
            if reason == "visibility_hidden" and s.get("visibility") == "visible":
                return True
            if reason == "font_size_0" and (_font_size_px(s) or 0) > 1:
                return True
        return False

    def _fg(self, tag: Tag, name: str) -> RGB | None:
        parsed = parse_css_color(self._style(tag).get("color"))
        if parsed is None and name == "font":
            parsed = parse_css_color(tag.get("color"))
        return parsed[0] if parsed and parsed[1] > 0.5 else None

    def _bg(self, tag: Tag) -> RGB | None:
        bg = _background_color(self._style(tag))
        if bg is None and tag.get("bgcolor"):
            parsed = parse_css_color(tag.get("bgcolor"))
            bg = parsed[0] if parsed else None
        return bg

    def _same_color(self, tag: Tag, name: str, style: Mapping[str, str]) -> bool:
        """Text colour ~= background. With stylesheets present only the element's own inline
        colour+background count (SPEC); without, inherited inline values and the default
        black-on-white apply."""
        own_fg, own_bg = self._fg(tag, name), self._bg(tag)
        if own_fg is None and own_bg is None:
            return False
        if self.has_css:
            fg, bg = own_fg, own_bg
        else:
            fg = own_fg or self._inherited(tag, "fg")
            bg = own_bg or self._inherited(tag, "bg")
        return fg is not None and bg is not None and _nearly_same(fg, bg)

    def _inherited(self, tag: Tag, kind: str) -> RGB:
        for parent in tag.parents:
            if not isinstance(parent, Tag) or parent is self.soup:
                break
            pname = (parent.name or "").lower()
            value = self._fg(parent, pname) if kind == "fg" else self._bg(parent)
            if value is not None:
                return value
        return BLACK if kind == "fg" else WHITE

    def _text_of(self, tag: Tag) -> str:
        """All text under `tag` (no scripts/styles/comments), block boundaries as newlines."""
        parts: list[str] = []
        stack: list[Any] = [tag]
        while stack:
            node = stack.pop()
            if node is _NEWLINE:
                parts.append("\n")
            elif isinstance(node, (Comment, Doctype, Declaration, ProcessingInstruction)):
                continue
            elif isinstance(node, NavigableString):
                parts.append(str(node))
            elif isinstance(node, Tag):
                name = (node.name or "").lower()
                if name in ("script", "style"):
                    continue
                if name in BLOCK_TAGS or name == "br":
                    parts.append("\n")
                    stack.append(_NEWLINE)
                stack.extend(reversed(list(node.children)))
        lines = (" ".join(line.split()) for line in "".join(parts).split("\n"))
        return "\n".join(line for line in lines if line)

    # ----- metadata
    def _attribute_metadata(self, tag: Tag, name: str, path: str) -> None:
        if name == "img":
            self.n_img += 1
            self.out.add(tag.get("alt"), "metadata", f"img[{self.n_img}][alt]", "img_alt")
        elif name == "area" or (name == "input" and str(tag.get("type", "")).lower() == "image"):
            self.out.add(tag.get("alt"), "metadata", f"{path}[alt]", "img_alt")
        if name not in ("title",):
            self.out.add(tag.get("title"), "metadata", f"{path}[title]", "title_attr")
        self.out.add(tag.get("aria-label"), "metadata", f"{path}[aria-label]", "aria_label")
        self.out.add(tag.get("aria-description"), "metadata", f"{path}[aria-description]", "aria_label")
        self.out.add(tag.get("placeholder"), "metadata", f"{path}[placeholder]", "placeholder")

    def _meta(self, tag: Tag) -> None:
        for attr in ("name", "property", "http-equiv", "itemprop"):
            key = tag.get(attr)
            if key:
                if str(key).lower() not in _META_SKIP:
                    self.out.add(tag.get("content"), "metadata", f"meta[{attr}={key}]", "meta_tag")
                return

    def _script(self, tag: Tag) -> None:
        if "ld+json" not in str(tag.get("type", "")).lower():
            return                                          # never executed, text ignored
        self.n_jsonld += 1
        where = f"script[type=application/ld+json][{self.n_jsonld}]"
        raw = tag.get_text()
        try:
            data = json.loads(raw)
        except ValueError:
            self.out.add(raw, "metadata", where, "json_ld")
            return
        walk_json(data, self.out, self.ctx, loc_prefix=f"{where} · ", channel="metadata",
                  reason="json_ld", skip_at_keys=True)

    def _input(self, tag: Tag, path: str, hidden: bool) -> None:
        kind = str(tag.get("type", "text")).lower()
        value = tag.get("value")
        if kind == "hidden":
            self.out.add(value, "hidden", f"{path}[value]", "hidden_input")
        elif kind in ("submit", "button", "reset") and not hidden:
            self._text(f" {value} " if value else "")         # a button's label is displayed
        else:
            self.out.add(value, "metadata", f"{path}[value]", "input_value")


# ---------------------------------------------------------------- entry points

_META_CHARSET = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?\s*([A-Za-z0-9_.:-]+)""", re.I)


def decode_html(data: bytes) -> str:
    """Honour a declared <meta charset> when valid, else BOM/UTF-8/cp1252 detection."""
    m = _META_CHARSET.search(data[:4096])
    if m and not data.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode(m.group(1).decode("ascii"))
        except (LookupError, UnicodeDecodeError):
            pass
    return decode_text(data)


def parse_html_raw(html: str, ctx: ParseContext) -> list[RawSeg]:
    """Parse an HTML string (document or fragment) into RawSegs."""
    soup = BeautifulSoup(html, "lxml")
    out = Out(ctx)
    _Walker(ctx, out, soup).run()
    return out.segs


def parse(data: bytes, ctx: ParseContext, *, filename: str | None = None,
          content_type: str | None = None) -> list[RawSeg]:
    return parse_html_raw(decode_html(data), ctx)
