"""Neutralizer (SPEC §10): strip / quarantine / block, then verify by re-scanning the output.

Builds the released ("clean") content from visible channels only. Hidden/comment/metadata segments are
never released; flagged ones are listed in `quarantined` so the UI can reveal them.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from firewall.detection.ensemble import VISIBLE
from firewall.detection.obfuscation import strip_invisible
from firewall.schemas import EnsembleResult, ParsedContent

STRIP_MARKER = "[...]"
PLACEHOLDER = "[External content withheld: suspected prompt injection · audit {audit_id}]"
HOLD_PLACEHOLDER = "[Content held for human review · audit {audit_id}]"
SHOW_MAX = 2000


@dataclass
class Neutralized:
    clean: str | None
    quarantined: list[dict] = field(default_factory=list)
    removed_spans: list[dict] = field(default_factory=list)


def visible_text(parsed: ParsedContent) -> str:
    return "\n\n".join(s.text for s in parsed.segments if s.channel in VISIBLE)


def visible_chars(text: str) -> int:
    return len(strip_invisible(text)[0].strip())


def residual_fraction(parsed: ParsedContent, ens: EnsembleResult) -> float:
    total = kept = 0
    by_seg: dict[str, list[tuple[int, int]]] = {}
    for sp in ens.localized_spans:
        by_seg.setdefault(sp["segment_id"], []).append((sp["start"], sp["end"]))
    for s in parsed.segments:
        if s.channel not in VISIBLE:
            continue
        n = visible_chars(s.text)
        total += n
        text = s.text
        for a, b in sorted(by_seg.get(s.id, []), reverse=True):
            text = text[:a] + text[b:]
        kept += visible_chars(text)
    return kept / total if total else 0.0


def _quarantine_entry(s) -> dict:
    return {"segment_id": s.id, "channel": s.channel, "location": s.location,
            "hidden_reason": s.hidden_reason, "text": s.text[:SHOW_MAX]}


def sanitize(parsed: ParsedContent, ens: EnsembleResult) -> Neutralized:
    """Quarantine flagged non-visible segments; strip localized spans (and invisible chars) from visible."""
    flagged = set(ens.flagged_segments)
    by_seg: dict[str, list[dict]] = {}
    for sp in ens.localized_spans:
        by_seg.setdefault(sp["segment_id"], []).append(sp)
    out = Neutralized(clean=None)
    parts: list[str] = []
    for s in parsed.segments:
        if s.channel not in VISIBLE:
            if s.id in flagged:
                out.quarantined.append(_quarantine_entry(s))
            continue
        text = s.text
        for sp in sorted(by_seg.get(s.id, []), key=lambda x: -x["start"]):
            a, b = sp["start"], sp["end"]
            out.removed_spans.append({"segment_id": s.id, "start": a, "end": b, "label": sp["label"],
                                      "text": text[a:b][:SHOW_MAX]})
            text = text[:a] + STRIP_MARKER + text[b:]
        text, inv = strip_invisible(text)
        for a, b in inv:
            if b - a >= 4:
                out.removed_spans.append({"segment_id": s.id, "start": a, "end": b, "label": "invisible_chars"})
        parts.append(text)
    out.clean = "\n\n".join(parts)
    return out


def quarantine_all(parsed: ParsedContent, ens: EnsembleResult, audit_id: str) -> Neutralized:
    flagged = set(ens.flagged_segments) or {s.id for s in parsed.segments}
    q = [_quarantine_entry(s) for s in parsed.segments if s.id in flagged]
    return Neutralized(clean=PLACEHOLDER.format(audit_id=audit_id), quarantined=q)


def neutralize(action: str, parsed: ParsedContent, ens: EnsembleResult, audit_id: str) -> Neutralized:
    if action in ("allow", "allow_with_warning"):
        return Neutralized(clean=visible_text(parsed))
    if action == "allow_sanitized":
        return sanitize(parsed, ens)
    if action == "quarantine":
        return quarantine_all(parsed, ens, audit_id)
    if action == "hold_for_review":
        return Neutralized(clean=HOLD_PLACEHOLDER.format(audit_id=audit_id))
    return Neutralized(clean=None)          # block (and allow_rewritten is not implemented: Could tier)
