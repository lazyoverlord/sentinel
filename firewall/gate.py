"""Deterministic control plane (SPEC §8, §11, §12): gate R1–R8a, post-review checks, action policy,
verify fallback, degraded policy, session watch mode.

Port of docs/reference/gate_reference.py. Pure functions, no I/O. Thresholds are configurable through
`Thresholds` (built from Settings); defaults equal the reference constants, so the reference tests run
unchanged in tests/unit/test_gate.py.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

REVIEW_FLAGS = frozenset({"encoded_weak", "hidden", "manip", "rolespoof", "exfil", "ai_imperative",
                          "disagree", "uncovered_script", "parse_error", "parse_truncated"})
NON_VISIBLE = frozenset({"hidden", "metadata", "comment", "attachment", "ocr_enhanced"})


@dataclass(frozen=True)
class Thresholds:
    C_BLOCK: float = 0.90
    H_BLOCK: float = 0.70
    C_REVIEW: float = 0.30
    H_REVIEW: float = 0.30
    RESIDUAL_MIN_FRACTION: float = 0.30
    CONFIDENCE_MIN: float = 0.60
    AUDIT_SAMPLE_RATE: float = 0.03
    WATCH_WINDOW: int = 10
    WATCH_RISK_SUM: float = 1.2
    WATCH_OFF_AFTER: int = 5
    WATCH_OFF_AFTER_STICKY: int = 10
    STICKY_TRIGGERS: int = 2
    CLEAN_RISK_MAX: float = 0.15

    @classmethod
    def from_settings(cls, s) -> "Thresholds":
        return cls(**{k: getattr(s, k) for k in cls.__dataclass_fields__})


DEFAULT = Thresholds()


@dataclass
class Signals:
    """Condensed EnsembleResult."""
    source: str                      # user | retrieved | uploaded
    C: float | None                  # None = no classifier available
    H: float
    flags: set[str] = field(default_factory=set)
    all_high_matches_quoted: bool = False

    @property
    def untrusted(self) -> bool:
        return self.source in ("retrieved", "uploaded")

    @property
    def c(self) -> float:
        return self.C or 0.0


@dataclass
class Gate:
    route: str                       # block_fast | review | pass_fast
    rule: str


RULE_REASONS = {
    "R1": "invisible payload (Unicode tags / zero-width) carries an instruction",
    "R2": "decoded payload is a strong injection signal",
    "R3": "untrusted content tries to manipulate an AI system or its reviewer",
    "R4": "classifier and rules both strongly indicate injection (not quoted)",
    "R5": "untrusted source: mandatory semantic review",
    "R6": "session watch mode: reviewed with conversation context",
    "R7": "risk signals above review thresholds",
    "R8a": "deterministic sampled audit of the fast lane",
    "R8": "no signals: fast lane",
}


def risk_score(s: Signals, rule: str | None = None) -> float:
    base = 0.6 * s.c + 0.4 * s.H
    floor = 0.95 if rule in ("R1", "R2") else 0.90 if rule in ("R3", "R4") else 0.0
    return round(max(base, floor), 4)


def audit_sample_hit(audit_id: str, rate: float = DEFAULT.AUDIT_SAMPLE_RATE) -> bool:
    """Deterministic, reproducible sampling for R8a."""
    bucket = int(hashlib.sha256(audit_id.encode()).hexdigest()[:8], 16) % 10_000
    return bucket < int(rate * 10_000)


def gate(s: Signals, watch_mode: bool, *, sample_hit: bool = False,
         untrusted_always_review: bool = True, t: Thresholds = DEFAULT) -> Gate:
    if "invisible" in s.flags:
        return Gate("block_fast", "R1")
    if "encoded_strong" in s.flags:
        return Gate("block_fast", "R2")
    if s.untrusted and "manip" in s.flags:
        return Gate("block_fast", "R3")
    if s.C is not None and s.C >= t.C_BLOCK and s.H >= t.H_BLOCK and not s.all_high_matches_quoted:
        return Gate("block_fast", "R4")
    if s.untrusted and untrusted_always_review:
        return Gate("review", "R5")
    if watch_mode:
        return Gate("review", "R6")
    if s.c >= t.C_REVIEW or s.H >= t.H_REVIEW or (s.flags & REVIEW_FLAGS):
        return Gate("review", "R7")
    if sample_hit:
        return Gate("review", "R8a")      # sampled audit of the fast lane
    return Gate("pass_fast", "R8")


def gate_hits_block_rule(s: Signals, t: Thresholds = DEFAULT) -> str | None:
    """R1–R4 only (used by the re-scan in the verify loop)."""
    g = gate(s, False, untrusted_always_review=False, t=t)
    return g.rule if g.route == "block_fast" else None


@dataclass
class Review:
    verdict: str                     # safe | suspicious | injection
    confidence: float
    grounded_evidence: int           # evidence quotes that passed grounding
    multi_step: bool = False
    contributing_turns: list[str] = field(default_factory=list)


def strong_deterministic_evidence(s: Signals, t: Thresholds = DEFAULT) -> bool:
    return bool({"encoded_weak", "hidden", "manip"} & s.flags) or (
        s.untrusted and (s.c >= t.C_BLOCK or s.H >= t.H_BLOCK))


def post_review(s: Signals, r: Review, t: Thresholds = DEFAULT) -> tuple[str, bool]:
    """Returns (final_verdict, hold_by_floor)."""
    verdict = r.verdict
    if verdict == "injection" and r.grounded_evidence == 0 and not r.multi_step:
        verdict = "suspicious"                       # ungrounded -> downgrade
    if r.confidence < t.CONFIDENCE_MIN:
        verdict = "suspicious"                       # uncertainty is a signal
    if verdict == "safe" and strong_deterministic_evidence(s, t):
        return verdict, True                         # floor -> hold_for_review
    return verdict, False


@dataclass
class Localization:
    is_image: bool = False
    flagged_channels: set[str] = field(default_factory=set)
    localized: bool = False
    residual_fraction: float = 0.0   # visible chars left after removing flagged spans / total visible
    not_separable_type6: bool = False


def action_policy(verdict: str, s: Signals, loc: Localization, *, multi_step: bool = False,
                  hold_by_floor: bool = False, rewrite_enabled: bool = False,
                  t: Thresholds = DEFAULT) -> str:
    """Intended action before verification (verify may escalate one step). Rewrite is off by default."""
    if hold_by_floor:
        return "hold_for_review"
    if verdict == "safe":
        return "allow"
    if verdict == "suspicious":
        return "hold_for_review" if s.untrusted else "allow_with_warning"
    if multi_step:
        return "block"
    if loc.is_image:
        return "quarantine"
    if loc.flagged_channels and loc.flagged_channels <= NON_VISIBLE:
        return "allow_sanitized"          # quarantine non-visible segments, release visible residual
    if loc.localized and loc.residual_fraction >= t.RESIDUAL_MIN_FRACTION:
        return "allow_sanitized"          # strip spans
    if loc.not_separable_type6 and s.untrusted:
        return "allow_rewritten" if rewrite_enabled else "quarantine"
    return "block"


def after_verify(intended: str, verify_passed: bool) -> str:
    if verify_passed:
        return intended
    return {"allow_sanitized": "block", "allow_rewritten": "quarantine"}.get(intended, intended)


def degraded_action(s: Signals, watch_mode: bool, fail_mode_untrusted: str = "closed") -> str:
    """Gate said review but no LLM is available (after retries + fallback model)."""
    if s.untrusted:
        if fail_mode_untrusted == "open":
            return "allow_with_warning"
        clean = s.c < 0.10 and s.H == 0 and not s.flags
        return "allow_with_warning" if clean else "quarantine"
    risky = watch_mode or s.c >= 0.50 or s.H >= 0.50 or bool(s.flags)
    return "hold_for_review" if risky else "allow_with_warning"


# ---- session watch mode (SPEC §11) ----
@dataclass
class Turn:
    turn_id: str
    risk: float
    verdict: str
    action: str
    rule: str


def is_trigger(tn: Turn) -> bool:
    return tn.rule == "R7" or tn.verdict in ("suspicious", "injection") or tn.action != "allow"


def is_clean(tn: Turn, t: Thresholds = DEFAULT) -> bool:
    return not is_trigger(tn) and tn.action == "allow" and tn.risk < t.CLEAN_RISK_MAX


def watch_mode_on(history: list[Turn], t: Thresholds = DEFAULT) -> bool:
    if not history:
        return False
    lifetime_triggers = sum(is_trigger(x) for x in history)
    off_after = t.WATCH_OFF_AFTER_STICKY if lifetime_triggers >= t.STICKY_TRIGGERS else t.WATCH_OFF_AFTER
    tail = history[-off_after:]
    if len(tail) == off_after and all(is_clean(x, t) for x in tail):
        return False
    window = history[-t.WATCH_WINDOW:]
    return any(is_trigger(x) for x in window) or sum(x.risk for x in window) >= t.WATCH_RISK_SUM


def sticky(history: list[Turn], t: Thresholds = DEFAULT) -> bool:
    return sum(is_trigger(x) for x in history) >= t.STICKY_TRIGGERS
