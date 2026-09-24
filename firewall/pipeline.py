"""Ingress pipeline (SPEC §4): parse → expand → detect → gate → review? → checks → policy → neutralize →
verify → report. Plain async Python; all decisions come from firewall.gate.

`Firewall` owns the detectors, the LLM client and all state. The API process creates one instance.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import time
from typing import Any

from firewall import gate as G
from firewall.agents.judge import PROMPT_VERSION, judge
from firewall.agents.neutralizer import (PLACEHOLDER, Neutralized, neutralize, residual_fraction,
                                         visible_text)
from firewall.config import Settings, get_settings
from firewall.detection.ensemble import VISIBLE, Ensemble, signals
from firewall.detection.heuristics import HeuristicEngine
from firewall.llm import LLMClient, LLMError
from firewall.learning.exemplars import ExemplarMemory
from firewall.learning.feedback import FeedbackStore
from firewall.learning.review_queue import ReviewQueue
from firewall.observability.audit import AuditLog, new_audit_id
from firewall.observability.metrics import Metrics
from firewall.parsing import ParseLimitError, parse, parse_text
from firewall.resilience.budget import QuotaExceeded
from firewall.resilience.cache import VerdictCache, content_hash
from firewall.schemas import (AnalyzeRequest, EnsembleResult, FirewallResponse, ParsedContent, Segment)
from firewall.security.canary import REGISTRY
from firewall.security.redact import excerpt, redact
from firewall.security.spotlight import wrap_provenance
from firewall.session.memory import SessionStore, TurnRecord
from firewall.taxonomy import type_dicts

log = logging.getLogger(__name__)

RELEASING = {"allow", "allow_with_warning", "allow_sanitized", "allow_rewritten"}


class Firewall:
    def __init__(self, settings: Settings | None = None, *, llm: Any = None, bank: Any = None,
                 heuristics: HeuristicEngine | None = None, load_classifiers: bool = True) -> None:
        self.s = s = settings or get_settings()
        self.t = G.Thresholds.from_settings(s)
        self.heuristics = heuristics or HeuristicEngine(s.patterns_path, timeout_s=s.REGEX_TIMEOUT_S)
        if bank is None and load_classifiers:
            from firewall.detection.classifiers import ClassifierBank
            bank = ClassifierBank(s)
        self.bank = bank
        self.ensemble = Ensemble(s, self.heuristics, bank)
        self.llm = llm if llm is not None else LLMClient(s)
        self.sessions = SessionStore(s)
        self.audit = AuditLog(s)
        self.metrics = Metrics()
        self.review_queue = ReviewQueue(s)
        self.feedback = FeedbackStore(s)
        self.exemplars = ExemplarMemory(s)
        self.verdict_cache = VerdictCache(s.cache_dir / "verdicts", ttl_s=s.VERDICT_CACHE_TTL_S,
                                          enabled=s.VERDICT_CACHE)
        self.started = False

    # ------------------------------------------------------------------ lifecycle
    async def startup(self) -> dict:
        info: dict = {}
        if self.bank is not None and hasattr(self.bank, "load"):
            t0 = time.perf_counter()
            await asyncio.to_thread(self.bank.load)
            info["classifier_load_ms"] = round((time.perf_counter() - t0) * 1000)
            info["classifiers"] = list(self.bank.loaded)
            info["degraded"] = list(self.bank.degraded)
        self.started = True
        return info

    def close(self) -> None:
        self.verdict_cache.close()
        close = getattr(self.llm, "close", None)
        if close:
            close()

    # ------------------------------------------------------------------ helpers
    def _parse(self, req: AnalyzeRequest) -> tuple[ParsedContent, str]:
        if req.text is not None:
            return parse_text(req.text, source_type=req.source_type, settings=self.s), content_hash(req.text)
        assert req.file is not None
        try:
            data = base64.b64decode(req.file.data_base64, validate=True)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"file.data_base64 is not valid base64: {e}") from e
        parsed = parse(data, filename=req.file.filename, content_type=req.file.content_type,
                       source_type=req.source_type, settings=self.s)
        return parsed, content_hash(data)

    def rescan_clean(self, text: str, source: str) -> bool:
        """Verify step (SPEC §8): expand + detect + R1–R4 + thresholds on the output."""
        if not text:
            return True
        seg = Segment(id="S1", text=text, channel="visible", location="rescan")
        pc = ParsedContent(format="text", source_type=source, segments=[seg])
        ens = self.ensemble.run(pc, source)
        sig = signals(ens, source)
        if G.gate_hits_block_rule(sig, self.t):
            return False
        return (ens.C or 0.0) < self.s.RESCAN_C_MAX and ens.H < self.s.RESCAN_H_MAX

    def _localization(self, parsed: ParsedContent, ens: EnsembleResult, judge_types: list[int]) -> G.Localization:
        segs = {s.id: s for s in parsed.segments}
        flagged_channels = {segs[i].channel for i in ens.flagged_segments if i in segs}
        vis_spans = [sp for sp in ens.localized_spans if sp["segment_id"] in segs
                     and segs[sp["segment_id"]].channel in VISIBLE]
        localized = bool(vis_spans)
        return G.Localization(
            is_image=parsed.format == "image",
            flagged_channels=flagged_channels,
            localized=localized,
            residual_fraction=residual_fraction(parsed, ens) if localized else 0.0,
            not_separable_type6=(6 in judge_types) and not localized)

    def _add_judge_spans(self, parsed: ParsedContent, ens: EnsembleResult, evidence) -> None:
        from firewall.security.grounding import locate
        segs = {s.id: s for s in parsed.segments}
        added = False
        for ev in evidence:
            if ev.grounded and ev.segment_id in segs:
                sp = locate(ev.quote, segs[ev.segment_id].text, min_score=self.s.GROUNDING_MIN_SCORE)
                if sp:
                    ens.localized_spans.append({"segment_id": ev.segment_id, "start": sp[0], "end": sp[1],
                                                "source": "judge", "label": "judge_quote"})
                    if ev.segment_id not in ens.flagged_segments:
                        ens.flagged_segments.append(ev.segment_id)
                    added = True
        if added:
            from firewall.detection.ensemble import _merge
            ens.localized_spans[:] = _merge(ens.localized_spans)

    # ------------------------------------------------------------------ main entry
    async def analyze(self, req: AnalyzeRequest, *, pin_model: bool = False) -> FirewallResponse:
        s = self.s
        t0 = time.perf_counter()
        lat: dict[str, float] = {}
        audit_id = new_audit_id()
        chain: list[str] = []
        source = req.source_type
        untrusted = source in ("retrieved", "uploaded")

        # 1. parse
        try:
            parsed, chash = await asyncio.to_thread(self._parse, req)
        except ParseLimitError as e:
            return self._limit_response(audit_id, req, str(getattr(e, "reason", e)), t0)
        lat["parse"] = _ms(t0)
        chain.append(f"parsed as {parsed.format}: {len(parsed.segments)} segment(s)"
                     + (f", warnings: {'; '.join(parsed.warnings[:3])}" if parsed.warnings else ""))

        # 2. verdict cache (session-less only)
        vkey = None
        if s.VERDICT_CACHE and not req.session_id:
            vkey = VerdictCache.make_key(chash, source, s.policy_version)
            hit = self.verdict_cache.get(vkey)
            if hit:
                resp = FirewallResponse(**hit)
                resp.audit_id = audit_id
                resp.path = {**resp.path, "cache": True}
                resp.latency_ms = {"total": _ms(t0)}
                resp.reasoning_chain = ["verdict cache hit (same content, source and policy)"] + resp.reasoning_chain
                self._finish(resp, req, parsed, None, source, cache_hit=True)
                return resp

        # 3. detect
        t1 = time.perf_counter()
        ens = await asyncio.to_thread(self.ensemble.run, parsed, source)
        lat["detect"] = _ms(t1)
        sig = signals(ens, source)
        chain.append(f"detectors: C={_f(ens.C)} (C1={_f(ens.C1)}, C2={_f(ens.C2)}), H={ens.H:.2f}, "
                     f"flags={','.join(ens.flags) or 'none'}")

        # 4. session + gate
        sid = req.session_id
        turn_id = req.turn_id or (self.sessions.next_turn_id(sid) if sid else None)
        watch = self.sessions.watch_mode(sid) if sid else False
        sample = G.audit_sample_hit(audit_id, s.AUDIT_SAMPLE_RATE)
        g = G.gate(sig, watch, sample_hit=sample, untrusted_always_review=s.UNTRUSTED_ALWAYS_REVIEW, t=self.t)
        chain.append(f"gate {g.rule} → {g.route}: {G.RULE_REASONS[g.rule]}")

        verdict, confidence, action = "safe", 0.0, "allow"
        judge_types: list[int] = []
        reviewed, degraded_llm, multi, hold = False, False, False, False
        jinfo: dict = {}
        retro: list[str] = []
        evidence = []
        contributing: list[str] = []

        if g.route == "pass_fast":
            verdict, confidence, action = "safe", round(1 - ens.risk_score, 3), "allow"
        elif g.route == "block_fast":
            verdict, confidence = "injection", 0.99
        else:
            reviewed = True
            t2 = time.perf_counter()
            ctx = self.sessions.context(sid) if sid and (g.rule == "R6" or watch) else None
            exemplars = []
            try:
                exemplars = self.exemplars.top_k(visible_text(parsed)[:5000]) if len(self.exemplars) else []
            except Exception:
                exemplars = []
            try:
                jr = await judge(self.llm, parsed, ens, source=source, settings=s, session_ctx=ctx,
                                 exemplars=exemplars, pin_model=pin_model)
                lat["judge"] = _ms(t2)
                v = jr.verdict
                evidence = v.evidence
                jinfo = {"model": jr.model, "latency_ms": round(jr.latency_ms), "tokens_in": jr.tokens_in,
                         "tokens_out": jr.tokens_out, "cache_hit": jr.cache_hit, "fallback": jr.fallback_used,
                         "prompt_version": PROMPT_VERSION, "grounded": jr.grounded,
                         "raw_verdict": v.verdict, "confidence": v.confidence, "rationale": v.rationale}
                self.metrics.record_llm(role="judge", model=jr.model, ok=True, latency_ms=jr.latency_ms,
                                        fallback=jr.fallback_used, tokens_in=jr.tokens_in, tokens_out=jr.tokens_out)
                review = G.Review(v.verdict, v.confidence, jr.grounded, v.multi_step, v.contributing_turns)
                verdict, hold = G.post_review(sig, review, self.t)
                confidence = v.confidence
                multi = v.multi_step and verdict == "injection"
                judge_types = v.attack_types
                contributing = list(v.contributing_turns)
                chain.append(f"judge ({jr.model}) said {v.verdict} @ {v.confidence:.2f}, "
                             f"{jr.grounded}/{len(v.evidence)} quotes grounded: {v.rationale}")
                if verdict != v.verdict:
                    chain.append(f"post-review checks changed verdict to {verdict} "
                                 "(ungrounded evidence or low confidence)")
                if hold:
                    chain.append("floor: strong deterministic evidence; the judge cannot clear it → hold")
                if verdict == "injection":
                    self._add_judge_spans(parsed, ens, v.evidence)
            except (LLMError, QuotaExceeded) as e:
                if pin_model and isinstance(e, QuotaExceeded):
                    raise
                degraded_llm = True
                lat["judge"] = _ms(t2)
                self.metrics.record_llm(role="judge", model="-", ok=False, latency_ms=lat["judge"],
                                        fallback=False, tokens_in=None, tokens_out=None)
                action = G.degraded_action(sig, watch, s.FAIL_MODE_UNTRUSTED)
                verdict = "safe" if action == "allow_with_warning" else "suspicious"
                chain.append(f"LLM unavailable ({type(e).__name__}) → degraded policy: {action}")

        # 5. policy
        loc = self._localization(parsed, ens, judge_types or ens.types_from_heuristics)
        if not degraded_llm:
            action = G.action_policy(verdict, sig, loc, multi_step=multi, hold_by_floor=hold,
                                     rewrite_enabled=s.REWRITE_ENABLED, t=self.t)
        chain.append(f"policy → {action}" + (f" (residual {loc.residual_fraction:.0%})" if loc.localized else ""))

        # 6. neutralize + verify
        t3 = time.perf_counter()
        try:
            neu = neutralize(action, parsed, ens, audit_id)
        except Exception as e:  # neutralizer error ⇒ block (SPEC §12)
            log.exception("neutralizer failed")
            neu, action = Neutralized(clean=None), "block"
            chain.append(f"neutralizer error ({type(e).__name__}) → block")
        verify_passed = None
        if action in ("allow_sanitized", "allow_rewritten"):
            verify_passed = await asyncio.to_thread(self.rescan_clean, neu.clean or "", source)
            new_action = G.after_verify(action, verify_passed)
            chain.append(f"verify re-scan {'passed' if verify_passed else 'FAILED'}"
                         + (f" → {new_action}" if new_action != action else ""))
            if new_action != action:
                action = new_action
                neu = neutralize(action, parsed, ens, audit_id)
        elif action == "quarantine" and parsed.format == "image":
            vis = visible_text(parsed)
            if vis and await asyncio.to_thread(self.rescan_clean, vis, source):
                pass  # visible OCR text is re-scanned; we still withhold the image as a whole (conservative)
        lat["neutralize"] = _ms(t3)

        # 7. types, session, retro warnings
        types = set(judge_types) if (reviewed and not degraded_llm and verdict != "safe") else set()
        if verdict != "safe" or g.route == "block_fast":
            types |= set(ens.types_from_heuristics) if not types else set()
            if any(d for d in ens.decoded if (d["C"] or 0) >= 0.5 or d["H"] >= 0.4) or g.rule in ("R1", "R2"):
                types.add(8)
            if untrusted:
                types.add(9)
            if multi:
                types.add(7)
        if verdict == "safe":
            types = set()
        if multi and sid:
            retro = self.sessions.retroactive_warnings(sid, contributing, turn_id)
        wrapped = None
        clean = neu.clean
        if action in RELEASING and untrusted and clean is not None:
            wrapped = wrap_provenance(clean, source=source)
        elif action in ("quarantine", "hold_for_review") and untrusted:
            wrapped = clean

        risk = G.risk_score(sig, g.rule)
        session_info = None
        if sid:
            session_info = {"session_id": sid, "turn_id": turn_id, "watch_mode_before": watch,
                            "single_message_risk": risk}

        resp = FirewallResponse(
            audit_id=audit_id, verdict=verdict, action=action, confidence=round(float(confidence), 3),
            attack_types=type_dicts(types), clean_content=clean, wrapped_content=wrapped,
            quarantined=neu.quarantined, removed_spans=neu.removed_spans, retroactive_warnings=retro,
            sensitive_data_present=ens.sensitive_data_present,
            path={"rule": g.rule, "route": g.route, "reviewed": reviewed, "sampled": g.rule == "R8a",
                  "model": jinfo.get("model"), "degraded": degraded_llm or bool(ens.degraded),
                  "degraded_llm": degraded_llm, "degraded_detectors": ens.degraded,
                  "verify_passed": verify_passed, "cache": False, "watch_mode": watch,
                  "policy_version": s.policy_version, "patterns_version": self.heuristics.version},
            reasoning_chain=chain, latency_ms={**lat, "total": _ms(t0)}, session=session_info,
            trace=self._trace(parsed, ens, jinfo, risk, loc))
        self._finish(resp, req, parsed, ens, source, cache_hit=False, turn_id=turn_id, risk=risk)
        if vkey and resp.action in ("allow", "block", "allow_sanitized", "quarantine") and not degraded_llm:
            self.verdict_cache.set(vkey, resp.model_dump(mode="json"))
        if sid:
            resp.session = {**(resp.session or {}), **{k: v for k, v in self.sessions.snapshot(sid).items()
                                                       if k in ("watch_mode", "sticky", "lifetime_triggers")}}
        return resp

    async def analyze_text(self, text: str, source: str = "user", **kw) -> FirewallResponse:
        return await self.analyze(AnalyzeRequest(text=text, source_type=source, **kw))

    def append_pattern(self, pat: dict) -> bool:
        """Human-approved patch (SPEC §14): append to patterns.json, bump version, reload the engine."""
        import json as _json
        data = _json.loads(self.s.patterns_path.read_text(encoding="utf-8"))
        if any(p["id"] == pat["id"] for p in data["patterns"]):
            return False
        pat.setdefault("description", f"approved red-team pattern {pat['id']}")
        data["patterns"].append(pat)
        parts = data.get("version", "1.0.0").split(".")
        parts[-1] = str(int(parts[-1]) + 1)
        data["version"] = ".".join(parts)
        self.s.patterns_path.write_text(_json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        self.heuristics.reload()
        return True

    # ------------------------------------------------------------------ reporting
    def _trace(self, parsed: ParsedContent, ens: EnsembleResult, jinfo: dict, risk: float, loc) -> dict:
        return {
            "format": parsed.format, "warnings": parsed.warnings,
            "scores": {"C": ens.C, "C1": ens.C1, "C2": ens.C2, "H": ens.H, "risk": risk},
            "flags": ens.flags, "scripts": ens.scripts,
            "matches": [{"pattern_id": m.pattern_id, "category": m.category, "weight": m.weight,
                         "segment_id": m.segment_id, "variant": m.variant_kind, "quoted": m.quoted,
                         "text": redact(m.text)} for m in ens.matches[:30]],
            "decoded": [{k: d[k] for k in ("segment_id", "kind", "depth", "C", "H")} | {"text": redact(d["text"])}
                        for d in ens.decoded[:10]],
            "segments": [{"id": sg.id, "channel": sg.channel, "location": sg.location,
                          "hidden_reason": sg.hidden_reason, "chars": len(sg.text),
                          "flagged": sg.id in ens.flagged_segments,
                          "text": redact(sg.text[:1000]) if sg.channel not in VISIBLE or sg.id in ens.flagged_segments else None,
                          **{k: v for k, v in ens.per_segment.get(sg.id, {}).items()}}
                         for sg in parsed.segments[:100]],
            "localized_spans": ens.localized_spans[:50],
            "localization": {"is_image": loc.is_image, "flagged_channels": sorted(loc.flagged_channels),
                             "localized": loc.localized, "residual_fraction": round(loc.residual_fraction, 3)},
            "judge": {k: v for k, v in jinfo.items()},
            "classifiers": list(self.ensemble.loaded),
        }

    def _finish(self, resp: FirewallResponse, req: AnalyzeRequest, parsed: ParsedContent, ens, source: str, *,
                cache_hit: bool, turn_id: str | None = None, risk: float | None = None) -> None:
        s = self.s
        text_for_excerpt = req.text if req.text is not None else visible_text(parsed)
        exc = excerpt(text_for_excerpt or "", 200, canaries=REGISTRY.all())
        if req.session_id and turn_id:
            self.sessions.record(req.session_id, TurnRecord(
                turn_id=turn_id, excerpt=exc, risk=risk if risk is not None else 0.0, verdict=resp.verdict,
                action=resp.action, rule=resp.path.get("rule", ""), types=[t["id"] for t in resp.attack_types],
                ts=time.time()))
        if resp.action == "hold_for_review":
            self.review_queue.add({"audit_id": resp.audit_id, "source": source, "summary": exc,
                                   "verdict": resp.verdict, "action": resp.action, "rule": resp.path.get("rule"),
                                   "reasons": resp.reasoning_chain[-4:],
                                   "evidence": [q.get("text", "")[:300] for q in resp.quarantined[:5]],
                                   "raw_text": text_for_excerpt[:5000] if text_for_excerpt else None})
        rec = {
            "audit_id": resp.audit_id, "source": source, "format": parsed.format,
            "filename": req.file.filename if req.file else None, "session_id": req.session_id, "turn_id": turn_id,
            "rule": resp.path.get("rule"), "route": resp.path.get("route"), "sampled": resp.path.get("sampled"),
            "C1": ens.C1 if ens else None, "C2": ens.C2 if ens else None, "H": ens.H if ens else None,
            "flags": ens.flags if ens else None, "scripts": ens.scripts if ens else None,
            "matches": [{"id": m.pattern_id, "w": m.weight, "q": m.quoted} for m in (ens.matches[:20] if ens else [])],
            "judge": resp.trace.get("judge"), "verdict": resp.verdict, "action": resp.action,
            "types": [t["id"] for t in resp.attack_types], "spans": len(resp.removed_spans),
            "quarantined": len(resp.quarantined), "latency_ms": resp.latency_ms, "degraded": resp.path.get("degraded"),
            "verify_passed": resp.path.get("verify_passed"), "cache": cache_hit, "excerpt": exc,
            "versions": {"patterns": self.heuristics.version, "policy": s.policy_version,
                         "classifiers": getattr(self.bank, "revisions", {}) if self.bank else {}},
            "raw_text": text_for_excerpt,
        }
        try:
            self.audit.write(rec)
        except Exception:
            log.exception("audit write failed")
        self.metrics.record_request(source=source, route=resp.path.get("route", "-"), rule=resp.path.get("rule", "-"),
                                    action=resp.action, latency_ms=resp.latency_ms.get("total", 0.0),
                                    cache_hit=cache_hit, degraded=bool(resp.path.get("degraded")))

    def _limit_response(self, audit_id: str, req: AnalyzeRequest, reason: str, t0: float) -> FirewallResponse:
        resp = FirewallResponse(
            audit_id=audit_id, verdict="suspicious", action="quarantine", confidence=1.0, attack_types=[],
            clean_content=PLACEHOLDER.format(audit_id=audit_id), wrapped_content=PLACEHOLDER.format(audit_id=audit_id),
            quarantined=[{"segment_id": "-", "channel": "attachment", "location": req.file.filename if req.file else "-",
                          "hidden_reason": "resource_limit", "text": reason}],
            removed_spans=[], retroactive_warnings=[], sensitive_data_present=[],
            path={"rule": "LIMIT", "route": "block_fast", "reviewed": False, "sampled": False, "model": None,
                  "degraded": False, "verify_passed": None, "cache": False},
            reasoning_chain=[f"resource limit: {reason} → quarantine (the file was not parsed)"],
            latency_ms={"total": _ms(t0)}, session=None, trace={})
        self.audit.write({"audit_id": audit_id, "source": req.source_type, "rule": "LIMIT", "action": "quarantine",
                          "reason": reason})
        self.metrics.record_request(source=req.source_type, route="block_fast", rule="LIMIT", action="quarantine",
                                    latency_ms=_ms(t0), cache_hit=False, degraded=False)
        return resp

    # ------------------------------------------------------------------ review + feedback
    def decide_review(self, audit_id: str, decision: str, label: str | None, note: str) -> dict:
        item = self.review_queue.decide(audit_id, decision, label, note)
        self.feedback.add(audit_id, "review", note=note, evidence={"decision": decision, "label": label})
        text = item.get("raw_text") or item.get("summary") or ""
        if label in ("attack", "benign") and text:
            self.exemplars.add(text, label, note=note)
        return item


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 1)


def _f(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.2f}"
