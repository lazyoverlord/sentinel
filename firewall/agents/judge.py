"""Semantic judge (SPEC §9): one schema-locked, spotlighted LLM call over an evidence bundle.

The judge only advises: grounding, the confidence check and the deterministic floor are applied
afterwards by firewall.gate.post_review (the LLM never overrules strong deterministic evidence).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from firewall.detection.ensemble import VISIBLE
from firewall.schemas import AnalyzerVerdict, EnsembleResult, JudgeOutput, ParsedContent
from firewall.security import spotlight
from firewall.security.grounding import ground, grounded_count
from firewall.taxonomy import prompt_block

PROMPT_VERSION = "judge_v1"
_TEMPLATE = (Path(__file__).parent / "prompts" / f"{PROMPT_VERSION}.md").read_text(encoding="utf-8")
CHARS_PER_TOKEN = 4


@dataclass
class JudgeResult:
    verdict: AnalyzerVerdict
    grounded: int
    model: str
    latency_ms: float
    tokens_in: int | None
    tokens_out: int | None
    cache_hit: bool
    fallback_used: bool
    prompt_chars: int


def system_prompt(nonce: str, source: str) -> str:
    return _TEMPLATE.format(rules=spotlight.system_rules(nonce), taxonomy=prompt_block(), source=source)


def build_bundle(parsed: ParsedContent, ens: EnsembleResult, *, source: str, nonce: str,
                 session_ctx: list[dict] | None, exemplars: list[dict] | None, max_chars: int,
                 datamarking: bool = True) -> str:
    """Evidence bundle, budgeted: non-visible + flagged segments first, then highest-risk visible."""
    per = ens.per_segment
    flagged = set(ens.flagged_segments)

    def prio(sg):
        risk = max(per.get(sg.id, {}).get("C") or 0.0, per.get(sg.id, {}).get("H") or 0.0)
        return (0 if sg.channel not in VISIBLE else 1, 0 if sg.id in flagged else 1, -risk)

    parts = [f"Source: {source}\nFormat: {parsed.format}\n"]
    top = sorted(ens.matches, key=lambda m: -m.weight)[:8]
    det = [f"C1={ens.C1}", f"C2={ens.C2}", f"H={ens.H:.2f}", f"flags={','.join(ens.flags) or 'none'}",
           f"scripts={','.join(ens.scripts) or 'none'}"]
    parts.append("## Detector summary\n" + " · ".join(det))
    if top:
        parts.append("Top rule matches (segment, category, weight, quoted): " + "; ".join(
            f"{m.segment_id}/{m.category}/{m.weight}/{'quoted' if m.quoted else 'unquoted'}" for m in top))
    budget = max_chars - sum(len(p) for p in parts) - 2000
    if ens.decoded:
        parts.append("## Decoded hidden payloads")
        for d in ens.decoded[:6]:
            blk = spotlight.data_block(d["text"][:800], nonce=nonce, datamarking=datamarking,
                                       attrs={"id": d["segment_id"], "decoded": d["kind"]})
            parts.append(blk)
            budget -= len(blk)
    if session_ctx:
        parts.append("## Session context (earlier turns of this conversation, oldest first)")
        for t in session_ctx[-10:]:
            blk = spotlight.data_block(t.get("excerpt", ""), nonce=nonce, datamarking=datamarking,
                                       attrs={"id": t["turn_id"], "prior_verdict": t.get("verdict"),
                                              "rule": t.get("rule")})
            parts.append(blk)
            budget -= len(blk)
    if exemplars:
        parts.append("## Labeled examples from past reviews (advisory)")
        for i, ex in enumerate(exemplars[:3], 1):
            blk = spotlight.data_block(ex["text"], nonce=nonce, datamarking=datamarking,
                                       attrs={"id": f"X{i}", "label": ex["label"]})
            parts.append(blk)
            budget -= len(blk)
    parts.append("## Content to judge (current turn)")
    omitted = 0
    for sg in sorted(parsed.segments, key=prio):
        attrs = {"id": sg.id, "channel": sg.channel, "location": sg.location}
        if sg.hidden_reason:
            attrs["reason"] = sg.hidden_reason
        text = sg.text
        if budget <= 200:
            omitted += len(text)
            continue
        if len(text) > budget:
            omitted += len(text) - budget
            text = text[:budget]
        blk = spotlight.data_block(text, nonce=nonce, attrs=attrs, datamarking=datamarking)
        parts.append(blk)
        budget -= len(blk)
    if omitted:
        parts.append(f"[… {omitted} chars omitted]")
    parts.append("Judge the current turn. Respond with JSON only.")
    return "\n\n".join(parts)


async def judge(llm: Any, parsed: ParsedContent, ens: EnsembleResult, *, source: str, settings: Any,
                session_ctx: list[dict] | None = None, exemplars: list[dict] | None = None,
                pin_model: bool = False) -> JudgeResult:
    nonce = spotlight.new_nonce()
    bundle = build_bundle(parsed, ens, source=source, nonce=nonce, session_ctx=session_ctx,
                          exemplars=exemplars, max_chars=settings.JUDGE_MAX_INPUT_TOKENS * CHARS_PER_TOKEN,
                          datamarking=settings.DATAMARKING)
    res = await llm.generate_structured(role="judge", system=system_prompt(nonce, source), prompt=bundle,
                                        schema=JudgeOutput, prompt_version=PROMPT_VERSION, temperature=0.0,
                                        pin_model=pin_model)
    out: JudgeOutput = res.parsed
    segs = {s.id: s.text for s in parsed.segments}
    evidence = ground(out.evidence, segs, min_score=settings.GROUNDING_MIN_SCORE)
    verdict = AnalyzerVerdict(
        verdict=out.verdict, confidence=max(0.0, min(1.0, float(out.confidence))),
        attack_types=sorted({t for t in out.attack_types if 1 <= t <= 9}), evidence=evidence,
        multi_step=out.multi_step, contributing_turns=out.contributing_turns,
        rationale=" ".join(out.rationale.split()[:80]), recommended_strategy=out.recommended_strategy)
    return JudgeResult(verdict, grounded_count(evidence), res.model, res.latency_ms, res.tokens_in,
                       res.tokens_out, res.cache_hit, res.fallback_used, len(bundle))
