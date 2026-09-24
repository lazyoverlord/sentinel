"""DOCX (SPEC §6): body, tables, headers/footers, footnotes, text boxes, comments, properties.

The zip is size-checked BEFORE python-docx opens it. Text is read from the WordprocessingML
elements directly, so runs inside hyperlinks, content controls, fields, text boxes and tracked
insertions are all seen. Run formatting is resolved through direct formatting -> character style
-> paragraph style -> document defaults. Hidden runs: w:vanish -> docx_vanish; white (or
near-background) colour -> white_text / low_contrast; size < 2pt -> font_lt_2pt; deleted
revisions -> docx_deleted. One visible segment per paragraph (per cell in tables).
"""
from __future__ import annotations

import io
from collections.abc import Iterator

import docx
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from lxml import etree

from .base import (
    RGB,
    WHITE,
    LOW_CONTRAST_MAX,
    WHITE_LUMINANCE,
    Out,
    ParseContext,
    RawSeg,
    check_zip_limits,
    contrast_ratio,
    luminance,
    rgb_from_hex,
    safe_xml_parser,
)

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
MC = "{http://schemas.openxmlformats.org/markup-compatibility/2006}"
WP = "{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}"
_CUSTOM_PROPS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties"
_APP_PROPS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties"

FONT_MIN_HALF_POINTS = 4                     # w:sz is in half-points: < 4 means < 2pt
_OFF = ("0", "false", "off", "none")
_HIGHLIGHT = {
    "yellow": "FFFF00", "green": "00FF00", "cyan": "00FFFF", "magenta": "FF00FF", "blue": "0000FF",
    "red": "FF0000", "darkBlue": "000080", "darkCyan": "008080", "darkGreen": "008000",
    "darkMagenta": "800080", "darkRed": "800000", "darkYellow": "808000", "darkGray": "808080",
    "lightGray": "C0C0C0", "black": "000000", "white": "FFFFFF",
}
_THEME_LIGHT = ("background1", "light1")
_THEME_DARK = ("text1", "dark1")
_CORE_FIELDS = ("title", "subject", "author", "keywords", "comments", "category",
                "last_modified_by", "content_status")


def _on(el: etree._Element | None) -> bool:
    """Toggle property present and not switched off (<w:vanish/> or w:val="1")."""
    return el is not None and (el.get(W + "val") or "1").lower() not in _OFF


def _fill(el: etree._Element | None) -> RGB | None:
    """Shading fill colour (w:shd/@w:fill); None for auto/absent."""
    if el is None:
        return None
    value = el.get(W + "fill")
    return None if not value or value.lower() == "auto" else rgb_from_hex(value)


class _Styles:
    """styles.xml lookup: rPr chains for character and paragraph styles, and document defaults."""

    def __init__(self, styles_el: etree._Element | None) -> None:
        self.by_id: dict[str, etree._Element] = {}
        self.default_para: str | None = None
        self.defaults_rpr: etree._Element | None = None
        if styles_el is None:
            return
        for style in styles_el.iter(W + "style"):
            sid = style.get(W + "styleId")
            if sid:
                self.by_id[sid] = style
                is_default = (style.get(W + "default") or "").lower() in ("1", "true", "on")
                if style.get(W + "type") == "paragraph" and is_default:
                    self.default_para = sid
        self.defaults_rpr = styles_el.find(f"{W}docDefaults/{W}rPrDefault/{W}rPr")

    def chain(self, style_id: str | None, child: str) -> list[etree._Element]:
        """`child` elements (rPr / pPr) along the basedOn chain, nearest first."""
        found: list[etree._Element] = []
        seen: set[str] = set()
        while style_id and style_id not in seen and len(seen) < 20:
            seen.add(style_id)
            style = self.by_id.get(style_id)
            if style is None:
                break
            el = style.find(W + child)
            if el is not None:
                found.append(el)
            based = style.find(W + "basedOn")
            style_id = based.get(W + "val") if based is not None else None
        return found


class _DocxWalker:
    def __init__(self, ctx: ParseContext, out: Out, styles: _Styles, page_bg: RGB | None) -> None:
        self.ctx, self.out, self.styles = ctx, out, styles
        self.page_bg = page_bg or WHITE
        self.visited = 0

    # ----- block containers
    def _blocks(self, el: etree._Element) -> Iterator[etree._Element]:
        """Block-level children (w:p / w:tbl), looking through sdt/customXml/ins/AlternateContent."""
        for child in el:
            tag = child.tag
            if tag in (W + "p", W + "tbl"):
                yield child
            elif tag == W + "sdt":
                content = child.find(W + "sdtContent")
                if content is not None:
                    yield from self._blocks(content)
            elif tag in (W + "customXml", W + "ins", W + "moveTo", W + "smartTag"):
                yield from self._blocks(child)
            elif tag == MC + "AlternateContent":
                choice = child.find(MC + "Choice")
                if choice is not None:
                    yield from self._blocks(choice)

    def container(self, el: etree._Element, prefix: str = "", bg: RGB | None = None) -> None:
        n_para = n_table = 0
        for block in self._blocks(el):
            self.visited += 1
            if self.visited % 200 == 0:
                self.ctx.checkpoint()
                if self.out.full:
                    return
            if block.tag == W + "p":
                n_para += 1
                loc = f"{prefix}paragraph {n_para}"
                seg = self.out.reserve("visible", loc)
                text = self.paragraph(block, loc, bg)
                self.out.fill(seg, text)
            else:
                n_table += 1
                self.table(block, f"{prefix}table {n_table}")

    def table(self, tbl: etree._Element, loc: str) -> None:
        rows = [r for r in self._iter_tag(tbl, W + "tr")]
        for r_i, tr in enumerate(rows, 1):
            for c_i, tc in enumerate(self._iter_tag(tr, W + "tc"), 1):
                cell_loc = f"{loc} · row {r_i} · cell {c_i}"
                tc_pr = tc.find(W + "tcPr")
                cell_bg = _fill(tc_pr.find(W + "shd")) if tc_pr is not None else None
                seg = self.out.reserve("visible", cell_loc)
                texts: list[str] = []
                n_para = n_table = 0
                for block in self._blocks(tc):
                    if block.tag == W + "p":
                        n_para += 1
                        texts.append(self.paragraph(block, f"{cell_loc} · paragraph {n_para}", cell_bg))
                    else:
                        n_table += 1
                        self.table(block, f"{cell_loc} · table {n_table}")
                self.out.fill(seg, "\n".join(t for t in texts if t.strip()))

    @staticmethod
    def _iter_tag(el: etree._Element, tag: str) -> Iterator[etree._Element]:
        for child in el:
            if child.tag == tag:
                yield child
            elif child.tag in (W + "sdt", W + "customXml"):
                inner = child.find(W + "sdtContent") if child.tag == W + "sdt" else child
                if inner is not None:
                    yield from (c for c in inner if c.tag == tag)

    # ----- paragraphs and runs
    @staticmethod
    def _owned(el: etree._Element, p: etree._Element) -> bool:
        """True if `el` belongs to paragraph `p` itself (not a nested text-box paragraph or a
        VML fallback copy)."""
        node = el.getparent()
        while node is not None and node is not p:
            if node.tag == W + "p" or node.tag == MC + "Fallback":
                return False
            node = node.getparent()
        return node is p

    def paragraph(self, p: etree._Element, loc: str, bg: RGB | None) -> str:
        """Emit hidden/metadata segments of paragraph `p`; return its visible text."""
        p_pr = p.find(W + "pPr")
        p_style = None
        para_bg = None
        if p_pr is not None:
            ps = p_pr.find(W + "pStyle")
            p_style = ps.get(W + "val") if ps is not None else None
            para_bg = _fill(p_pr.find(W + "shd"))
        para_rprs = self.styles.chain(p_style or self.styles.default_para, "rPr")
        base_bg = para_bg or bg or self.page_bg

        visible: list[str] = []
        group: tuple[str, RawSeg, list[str]] | None = None    # (reason, segment, parts)
        fields: list[str] = []

        def close() -> None:
            nonlocal group
            if group is not None:
                self.out.fill(group[1], "".join(group[2]))
                group = None

        runs = [r for r in p.iter(W + "r") if self._owned(r, p)]
        for k, run in enumerate(runs, 1):
            text, deleted, instr = self._run_text(run)
            if instr.strip():
                fields.append(instr.strip())
            reason: str | None
            if self._in_deleted(run, p):
                text, reason = deleted, "docx_deleted"
            else:
                reason = self._run_reason(run, para_rprs, base_bg)
            if not text:
                continue
            if not text.strip():                     # whitespace joins whatever is open
                (group[2] if group is not None else visible).append(text)
                continue
            if reason is None:
                close()
                visible.append(text)
            else:
                if group is None or group[0] != reason:
                    close()
                    group = (reason, self.out.reserve("hidden", f"{loc} · run {k}", reason), [])
                group[2].append(text)
        close()
        fields.extend(f.get(W + "instr", "").strip() for f in p.iter(W + "fldSimple") if self._owned(f, p))
        fields = [f for f in fields if f]
        if fields:                                   # field instructions are never displayed
            self.out.add("\n".join(fields), "metadata", f"{loc} · field code", "docx_field_code")
        for n, pic in enumerate((d for d in p.iter(WP + "docPr") if self._owned(d, p)), 1):
            alt = "\n".join(v for v in (pic.get("title"), pic.get("descr")) if v and v.strip())
            self.out.add(alt, "metadata", f"{loc} · image {n}", "img_alt")
        for n, box in enumerate((b for b in p.iter(W + "txbxContent") if self._owned(b, p)), 1):
            self.container(box, f"{loc} · textbox {n} · ")
        return "".join(visible)

    @staticmethod
    def _in_deleted(run: etree._Element, p: etree._Element) -> bool:
        node = run.getparent()
        while node is not None and node is not p:
            if node.tag in (W + "del", W + "moveFrom"):
                return True
            node = node.getparent()
        return False

    @staticmethod
    def _run_text(run: etree._Element) -> tuple[str, str, str]:
        """(displayed text, deleted text, field instruction text) of one w:r."""
        shown: list[str] = []
        deleted: list[str] = []
        instr: list[str] = []
        for child in run:
            tag = child.tag
            if tag == W + "t":
                shown.append(child.text or "")
            elif tag == W + "delText":
                deleted.append(child.text or "")
            elif tag in (W + "instrText", W + "delInstrText"):
                instr.append(child.text or "")
            elif tag in (W + "tab", W + "ptab"):
                shown.append("\t")
            elif tag in (W + "br", W + "cr"):
                shown.append("\n")
            elif tag == W + "noBreakHyphen":
                shown.append("-")
        return "".join(shown), "".join(deleted), "".join(instr)

    def _run_reason(self, run: etree._Element, para_rprs: list[etree._Element], base_bg: RGB) -> str | None:
        r_pr = run.find(W + "rPr")
        rprs: list[etree._Element] = []
        if r_pr is not None:
            rprs.append(r_pr)
            rs = r_pr.find(W + "rStyle")
            if rs is not None:
                rprs.extend(self.styles.chain(rs.get(W + "val"), "rPr"))
        rprs.extend(para_rprs)
        if self.styles.defaults_rpr is not None:
            rprs.append(self.styles.defaults_rpr)

        def prop(name: str) -> etree._Element | None:
            for rpr in rprs:
                el = rpr.find(W + name)
                if el is not None:
                    return el
            return None

        if _on(prop("vanish")) or _on(prop("specVanish")):
            return "docx_vanish"
        color = self._color(prop("color"))
        if color is not None:
            bg = base_bg
            highlight = prop("highlight")
            run_shd = _fill(prop("shd"))
            if highlight is not None and highlight.get(W + "val") in _HIGHLIGHT:
                bg = rgb_from_hex(_HIGHLIGHT[highlight.get(W + "val")]) or bg
            elif run_shd is not None:
                bg = run_shd
            if contrast_ratio(color, bg) < LOW_CONTRAST_MAX:
                return "white_text" if luminance(color) > WHITE_LUMINANCE else "low_contrast"
        size = prop("sz")
        if size is not None:
            try:
                if int(size.get(W + "val") or 99) < FONT_MIN_HALF_POINTS:
                    return "font_lt_2pt"
            except ValueError:
                pass
        return None

    @staticmethod
    def _color(el: etree._Element | None) -> RGB | None:
        """Run colour; None for 'auto' (Word picks a contrasting colour) or unknown."""
        if el is None:
            return None
        value = el.get(W + "val") or ""
        if value.lower() != "auto":
            rgb = rgb_from_hex(value)
            if rgb is not None:
                return rgb
        theme = el.get(W + "themeColor") or ""
        if theme in _THEME_LIGHT:
            return WHITE
        if theme in _THEME_DARK:
            return (0.0, 0.0, 0.0)
        return None


def _xml_part(part: object) -> etree._Element | None:
    element = getattr(part, "element", None)
    if element is not None:
        return element
    blob = getattr(part, "blob", None)
    return etree.fromstring(blob, parser=safe_xml_parser()) if blob else None


def _properties(doc: docx.document.Document, out: Out) -> None:
    core = doc.core_properties
    for field in _CORE_FIELDS:
        try:
            value = getattr(core, field)
        except Exception:  # noqa: BLE001 - malformed core.xml value
            continue
        if isinstance(value, str):
            out.add(value, "metadata", f"DOCX:core:{field}", "docx_core")
    package_rels = doc.part.package.rels.values()
    for rel in package_rels:
        if rel.is_external or rel.reltype not in (_CUSTOM_PROPS, _APP_PROPS):
            continue
        root = _xml_part(rel.target_part)
        if root is None:
            continue
        if rel.reltype == _CUSTOM_PROPS:
            for prop in root:
                name = prop.get("name") or "property"
                value = "".join(prop.itertext()).strip()
                out.add(value, "metadata", f"DOCX:custom:{name}", "docx_custom")
        else:
            for el in root:
                local = etree.QName(el).localname if isinstance(el.tag, str) else ""
                if local in ("Company", "Manager", "HyperlinkBase"):
                    out.add(el.text, "metadata", f"DOCX:app:{local}", "docx_app")


def parse(data: bytes, ctx: ParseContext, *, filename: str | None = None,
          content_type: str | None = None) -> list[RawSeg]:
    check_zip_limits(data, ctx.settings)                 # ParseLimitError before decompressing
    doc = docx.Document(io.BytesIO(data))
    out = Out(ctx)
    _properties(doc, out)

    body = doc.element.body
    background = doc.element.find(W + "background")
    page_bg = rgb_from_hex(background.get(W + "color")) if background is not None else None
    styles_el = None
    try:
        styles_el = doc.styles.element
    except Exception:  # noqa: BLE001 - no/invalid styles part
        pass
    walker = _DocxWalker(ctx, out, _Styles(styles_el), page_bg)

    rels = [rel for rel in doc.part.rels.values() if not rel.is_external]

    def parts_of(reltype: str) -> list[object]:
        unique = {id(rel.target_part): rel.target_part for rel in rels if rel.reltype == reltype}
        return sorted(unique.values(), key=lambda part: str(getattr(part, "partname", "")))

    for n, part in enumerate(parts_of(RT.HEADER), 1):
        root = _xml_part(part)
        if root is not None:
            walker.container(root, f"header {n} · ")
    walker.container(body)
    for reltype, label in ((RT.FOOTNOTES, "footnote"), (RT.ENDNOTES, "endnote")):
        for part in parts_of(reltype):
            root = _xml_part(part)
            if root is None:
                continue
            for note in root:
                kind = note.get(W + "type")
                if kind in ("separator", "continuationSeparator", "continuationNotice"):
                    continue
                walker.container(note, f"{label} {note.get(W + 'id')} · ")
    for n, part in enumerate(parts_of(RT.FOOTER), 1):
        root = _xml_part(part)
        if root is not None:
            walker.container(root, f"footer {n} · ")

    try:
        comments = list(doc.comments)
    except Exception:  # noqa: BLE001 - malformed comments part
        comments = []
        ctx.warn("parse_error: DOCX comments part could not be read")
    for n, comment in enumerate(comments, 1):
        out.add(comment.text, "comment", f"comment {n}", "docx_comment")
    return out.segs
