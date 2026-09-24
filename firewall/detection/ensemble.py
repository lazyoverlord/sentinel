"""Ensemble (SPEC §7.4–§7.5): run classifiers + rules over all variants of all segments, compute the
exact flags the gate uses, scripts, DLP and localization spans.
"""
from __future__ import annotations

import re
from typing import Any

from firewall.detection import dlp
from firewall.detection.heuristics import HeuristicEngine
from firewall.detection.obfuscation import (CONDITIONAL_KINDS, DECODED_KINDS, INVISIBLE_KINDS, expand_all,
                                            strip_invisible)
from firewall.detection.scripts import covered_scripts, scripts_present, uncovered
from firewall.gate import Signals, risk_score
from firewall.schemas import EnsembleResult, HeuristicMatch, ParsedContent, Segment, Variant
from firewall.security.canary import REGISTRY

VISIBLE = frozenset({"visible", "ocr", "ocr_layer"})
_SENT = re.compile(r"[^.!?\n]+[.!?]?")


def _merge(spans: list[dict]) -> list[dict]:
    out: list[dict] = []
    for sp in sorted(spans, key=lambda s: (s["segment_id"], s["start"], s["end"])):
        if out and out[-1]["segment_id"] == sp["segment_id"] and sp["start"] <= out[-1]["end"]:
            out[-1]["end"] = max(out[-1]["end"], sp["end"])
            out[-1]["label"] = out[-1]["label"] if sp["label"] in out[-1]["label"] else out[-1]["label"] + "+" + sp["label"]
        else:
            out.append(dict(sp))
    return out


class Ensemble:
    def __init__(self, settings: Any, heuristics: HeuristicEngine, bank: Any | None = None):
        self.s = settings
        self.h = heuristics
        self.bank = bank

    # --- classifier helper: returns per-classifier score lists (possibly empty dict)
    def _classify(self, texts: list[str]) -> dict[str, list[float]]:
        if not self.bank or not texts:
            return {}
        try:
            return self.bank.score(texts)
        except Exception:  # a classifier failure never breaks the request
            return {}

    @property
    def loaded(self) -> list[str]:
        return list(self.bank.loaded) if self.bank else []

    def run(self, parsed: ParsedContent, source: str) -> EnsembleResult:
        s = self.s
        segs = {sg.id: sg for sg in parsed.segments}
        exp = expand_all(parsed.segments, max_per_segment=s.MAX_VARIANTS_PER_SEGMENT,
                         max_per_request=s.MAX_VARIANTS_PER_REQUEST, max_depth=s.MAX_DECODE_DEPTH)
        variants = exp.variants
        scores = self._classify([v.text for v in variants])
        names = list(scores.keys())

        def c_of(i: int, name: str | None = None) -> float | None:
            if name:
                return scores[name][i] if name in scores else None
            vals = [scores[n][i] for n in names]
            return max(vals) if vals else None

        matches_by_v: list[list[HeuristicMatch]] = [self.h.scan(v.text, v.segment_id, v.kind) for v in variants]
        orig_c: dict[str, float] = {}
        for i, v in enumerate(variants):
            if v.kind == "original":
                orig_c[v.segment_id] = c_of(i) or 0.0

        kept: list[int] = []
        for i, v in enumerate(variants):
            if v.kind in CONDITIONAL_KINDS:
                ci = c_of(i) or 0.0
                if not matches_by_v[i] and ci - orig_c.get(v.segment_id, 0.0) < 0.3:
                    continue
            kept.append(i)

        flags: set[str] = set()
        all_matches: list[HeuristicMatch] = []
        per_seg: dict[str, dict] = {sid: {"C": None, "C1": None, "C2": None, "H": 0.0} for sid in segs}
        decoded: list[dict] = []
        c1_by_seg: dict[str, float] = {}
        c2_by_seg: dict[str, float] = {}

        def upd(d: dict, k: str, val: float | None):
            if val is not None:
                d[k] = val if d[k] is None else max(d[k], val)

        for i in kept:
            v: Variant = variants[i]
            ms = matches_by_v[i]
            all_matches += ms
            hv = HeuristicEngine.H(ms)
            cv = c_of(i)
            ps = per_seg[v.segment_id]
            upd(ps, "C", cv)
            upd(ps, "C1", c_of(i, "c1"))
            c2n = next((n for n in names if n.startswith("c2")), None)
            upd(ps, "C2", c_of(i, c2n) if c2n else None)
            ps["H"] = max(ps["H"], hv)
            cvv = cv or 0.0
            if v.kind in DECODED_KINDS:
                decoded.append({"segment_id": v.segment_id, "kind": v.kind, "depth": v.depth,
                                "text": v.text[:500], "C": cv, "H": hv, "span": v.span})
                if v.kind in INVISIBLE_KINDS and (cvv >= s.FLAG_INVISIBLE_C or hv >= s.FLAG_INVISIBLE_H):
                    flags.add("invisible")
                if cvv >= s.FLAG_ENC_STRONG_C or hv >= s.FLAG_ENC_STRONG_H:
                    flags.add("encoded_strong")
                if cvv >= s.FLAG_ENC_WEAK_C or hv >= s.FLAG_ENC_WEAK_H:
                    flags.add("encoded_weak")
            if v.kind in ("original", "normalized"):
                c1 = c_of(i, "c1")
                c2 = c_of(i, c2n) if c2n else None
                if c1 is not None:
                    c1_by_seg[v.segment_id] = max(c1_by_seg.get(v.segment_id, 0.0), c1)
                if c2 is not None:
                    c2_by_seg[v.segment_id] = max(c2_by_seg.get(v.segment_id, 0.0), c2)

        flags |= HeuristicEngine.flags(all_matches)
        for sid, sg in segs.items():
            ps = per_seg[sid]
            if sg.channel not in VISIBLE:
                ai_imp = any(m.segment_id == sid and m.category == "ai_addressed_imperative" for m in all_matches)
                if (ps["C"] or 0.0) >= s.FLAG_HIDDEN_C or ps["H"] >= s.FLAG_HIDDEN_H or ai_imp:
                    flags.add("hidden")
            if sid in c1_by_seg and sid in c2_by_seg and abs(c1_by_seg[sid] - c2_by_seg[sid]) >= s.FLAG_DISAGREE_DELTA:
                flags.add("disagree")

        scripts = scripts_present([sg.text for sg in parsed.segments], s.SCRIPT_MIN_LETTERS)
        if uncovered(scripts, covered_scripts(s.COVERED_SCRIPTS, self.loaded)):
            flags.add("uncovered_script")
        if any(w.startswith("parse_error") for w in parsed.warnings):
            flags.add("parse_error")
        untrusted = source in ("retrieved", "uploaded")
        if exp.truncated or (parsed.truncated and untrusted):
            flags.add("parse_truncated")

        # --- aggregate scores
        c_all = [ps["C"] for ps in per_seg.values() if ps["C"] is not None]
        C = max(c_all) if c_all else None
        c1s = [ps["C1"] for ps in per_seg.values() if ps["C1"] is not None]
        c2s = [ps["C2"] for ps in per_seg.values() if ps["C2"] is not None]
        H = HeuristicEngine.H(all_matches)

        # --- flagged segments + localization
        flagged: list[str] = []
        spans: list[dict] = []
        for sid, sg in segs.items():
            ps = per_seg[sid]
            seg_dec = [d for d in decoded if d["segment_id"] == sid and ((d["C"] or 0) >= s.FLAG_ENC_WEAK_C
                       or d["H"] >= s.FLAG_ENC_WEAK_H or d["kind"] in INVISIBLE_KINDS)]
            is_flag = (ps["C"] or 0.0) >= s.FLAG_HIDDEN_C or ps["H"] >= s.FLAG_ENC_WEAK_H or bool(seg_dec)
            if sg.channel not in VISIBLE and "hidden" in flags and (
                    (ps["C"] or 0.0) >= s.FLAG_HIDDEN_C or ps["H"] >= s.FLAG_HIDDEN_H
                    or any(m.segment_id == sid and m.category == "ai_addressed_imperative" for m in all_matches)):
                is_flag = True
            if is_flag:
                flagged.append(sid)
            for d in seg_dec:
                if d["span"]:
                    spans.append({"segment_id": sid, "start": d["span"][0], "end": d["span"][1],
                                  "source": "decoded", "label": d["kind"]})
            _, inv = strip_invisible(sg.text)
            for a, b in inv:
                if b - a >= 4:
                    spans.append({"segment_id": sid, "start": a, "end": b, "source": "invisible", "label": "invisible"})
        norm = exp.normalized
        for m in all_matches:
            if m.weight < s.FLAG_ENC_WEAK_H:
                continue
            a, b = m.span
            if m.variant_kind == "original":
                spans.append({"segment_id": m.segment_id, "start": a, "end": b, "source": "rule", "label": m.pattern_id})
            elif m.variant_kind == "normalized" and m.segment_id in norm:
                im = norm[m.segment_id].index_map
                if a < len(im) and 0 < b <= len(im):
                    spans.append({"segment_id": m.segment_id, "start": im[a], "end": im[b - 1] + 1,
                                  "source": "rule", "label": m.pattern_id})
            if m.segment_id not in flagged:
                flagged.append(m.segment_id)
        # sentence-level classifier localization for flagged visible segments with C >= 0.5
        if names:
            for sid in flagged:
                sg = segs[sid]
                if sg.channel in VISIBLE and (per_seg[sid]["C"] or 0.0) >= 0.5:
                    sents = [(m.start(), m.end(), m.group(0)) for m in _SENT.finditer(sg.text) if m.group(0).strip()]
                    if 1 < len(sents) <= 200:
                        sc = self._classify([t for _, _, t in sents])
                        vals = [max(col) for col in zip(*sc.values())] if sc else []
                        for (a, b, _), val in zip(sents, vals):
                            if val >= 0.5:
                                spans.append({"segment_id": sid, "start": a, "end": b, "source": "classifier",
                                              "label": f"C={val:.2f}"})
        spans = _merge(spans)

        sensitive = sorted({k for sg in parsed.segments for k in dlp.scan(sg.text, REGISTRY.all())})
        types = sorted({t for m in all_matches if m.weight >= 0.3 for t in m.types})
        degraded = list(self.bank.degraded) if self.bank else ["classifiers: none configured"]
        if self.bank is not None and not names and parsed.segments:
            degraded = degraded or ["classifiers: none loaded"]
        sig = Signals(source, C, H, flags, HeuristicEngine.all_high_quoted(all_matches))
        return EnsembleResult(
            C=C, C1=max(c1s) if c1s else None, C2=max(c2s) if c2s else None, H=H,
            matches=all_matches[:200], flags=sorted(flags),
            all_high_matches_quoted=sig.all_high_matches_quoted,
            sensitive_data_present=sensitive, types_from_heuristics=types,
            flagged_segments=flagged, localized_spans=spans, scripts=scripts, degraded=degraded,
            risk_score=risk_score(sig), per_segment=per_seg, decoded=decoded[:50])


def signals(ens: EnsembleResult, source: str) -> Signals:
    return Signals(source, ens.C, ens.H, set(ens.flags), ens.all_high_matches_quoted)


def segment_map(segments: list[Segment]) -> dict[str, str]:
    return {s.id: s.text for s in segments}
