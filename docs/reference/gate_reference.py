"""Reference implementation of SPEC §7 (gate, post-review, policy), §10 (watch mode),
§11 (degraded), §14.2 (egress decision). v4.

Pure functions, no I/O. Port into firewall/gate.py and firewall/integrations/egress.py (types from
schemas.py). test_gate_reference.py encodes the SPEC §21 demo traces and the v4 attack cases;
those tests must keep passing after the port.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# ---- thresholds (SPEC §17 defaults) ----
C_BLOCK, H_BLOCK = 0.90, 0.70
C_REVIEW, H_REVIEW = 0.30, 0.30
RESIDUAL_MIN_FRACTION = 0.30
CONFIDENCE_MIN = 0.60
AUDIT_SAMPLE_RATE = 0.03
WATCH_WINDOW, WATCH_RISK_SUM = 10, 1.2
WATCH_OFF_AFTER, WATCH_OFF_AFTER_STICKY, STICKY_TRIGGERS = 5, 10, 2
CLEAN_RISK_MAX = 0.15

REVIEW_FLAGS = {"encoded_weak", "hidden", "manip", "rolespoof", "exfil", "ai_imperative",
                "disagree", "uncovered_script", "parse_error", "parse_truncated"}
NON_VISIBLE = {"hidden", "metadata", "comment", "attachment", "ocr_enhanced"}


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


def risk_score(s: Signals, rule: str | None = None) -> float:
    base = 0.6 * s.c + 0.4 * s.H
    floor = 0.95 if rule in ("R1", "R2") else 0.90 if rule in ("R3", "R4") else 0.0
    return round(max(base, floor), 4)


def audit_sample_hit(audit_id: str, rate: float = AUDIT_SAMPLE_RATE) -> bool:
    """Deterministic, reproducible sampling for R8a."""
    bucket = int(hashlib.sha256(audit_id.encode()).hexdigest()[:8], 16) % 10_000
    return bucket < int(rate * 10_000)


def gate(s: Signals, watch_mode: bool, *, sample_hit: bool = False,
         untrusted_always_review: bool = True) -> Gate:
    if "invisible" in s.flags:
        return Gate("block_fast", "R1")
    if "encoded_strong" in s.flags:
        return Gate("block_fast", "R2")
    if s.untrusted and "manip" in s.flags:
        return Gate("block_fast", "R3")
    if s.C is not None and s.C >= C_BLOCK and s.H >= H_BLOCK and not s.all_high_matches_quoted:
        return Gate("block_fast", "R4")
    if s.untrusted and untrusted_always_review:
        return Gate("review", "R5")
    if watch_mode:
        return Gate("review", "R6")
    if s.c >= C_REVIEW or s.H >= H_REVIEW or (s.flags & REVIEW_FLAGS):
        return Gate("review", "R7")
    if sample_hit:
        return Gate("review", "R8a")      # sampled audit of the fast lane
    return Gate("pass_fast", "R8")


@dataclass
class Review:
    verdict: str                     # safe | suspicious | injection
    confidence: float
    grounded_evidence: int           # evidence quotes that passed grounding
    multi_step: bool = False
    contributing_turns: list[str] = field(default_factory=list)


def strong_deterministic_evidence(s: Signals) -> bool:
    return bool({"encoded_weak", "hidden", "manip"} & s.flags) or (
        s.untrusted and (s.c >= C_BLOCK or s.H >= H_BLOCK))


def post_review(s: Signals, r: Review) -> tuple[str, bool]:
    """Returns (final_verdict, hold_by_floor)."""
    verdict = r.verdict
    if verdict == "injection" and r.grounded_evidence == 0 and not r.multi_step:
        verdict = "suspicious"                       # ungrounded -> downgrade
    if r.confidence < CONFIDENCE_MIN:
        verdict = "suspicious"                       # uncertainty is a signal
    if verdict == "safe" and strong_deterministic_evidence(s):
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
                  hold_by_floor: bool = False, rewrite_enabled: bool = False) -> str:
    """Intended action before verification (verify may escalate one step). Rewrite is off by default in v4."""
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
    if loc.localized and loc.residual_fraction >= RESIDUAL_MIN_FRACTION:
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


# ---- session watch mode (SPEC §10) ----
@dataclass
class Turn:
    turn_id: str
    risk: float
    verdict: str
    action: str
    rule: str


def is_trigger(t: Turn) -> bool:
    return t.rule == "R7" or t.verdict in ("suspicious", "injection") or t.action != "allow"


def is_clean(t: Turn) -> bool:
    return not is_trigger(t) and t.action == "allow" and t.risk < CLEAN_RISK_MAX


def watch_mode_on(history: list[Turn]) -> bool:
    if not history:
        return False
    lifetime_triggers = sum(is_trigger(t) for t in history)
    off_after = WATCH_OFF_AFTER_STICKY if lifetime_triggers >= STICKY_TRIGGERS else WATCH_OFF_AFTER
    tail = history[-off_after:]
    if len(tail) == off_after and all(is_clean(t) for t in tail):
        return False
    window = history[-WATCH_WINDOW:]
    return any(is_trigger(t) for t in window) or sum(t.risk for t in window) >= WATCH_RISK_SUM


# ---- egress guard for sensitive tool calls (SPEC §14.2) ----
@dataclass
class Alignment:
    aligned: bool                    # does the proposed action serve the user's original request?
    confidence: float


def egress_decision(*, sensitive: bool, external_destination: bool, dlp_in_args: bool,
                    canary_in_args: bool, invocation_flagged: bool,
                    alignment: Alignment | None) -> str:
    """Returns allow | confirm | block. `alignment` is None when the LLM check is unavailable."""
    if not sensitive:
        return "allow"
    if canary_in_args:
        return "block"                               # a canary leaving is proven exfiltration
    if not (external_destination or dlp_in_args or invocation_flagged):
        return "allow"
    if alignment is None:
        return "block" if invocation_flagged else "confirm"   # ask the human when we can't judge
    if not alignment.aligned or alignment.confidence < CONFIDENCE_MIN:
        return "block"
    return "allow"
