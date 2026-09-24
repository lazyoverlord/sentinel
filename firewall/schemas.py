"""Data contracts (SPEC §5). Public shapes are exactly as specified; helper models are marked."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

Source = Literal["user", "retrieved", "uploaded"]
Channel = Literal["visible", "hidden", "metadata", "comment", "attachment", "ocr", "ocr_enhanced", "ocr_layer"]
Action = Literal["allow", "allow_with_warning", "allow_sanitized", "allow_rewritten",
                 "quarantine", "hold_for_review", "block"]
Verdict = Literal["safe", "suspicious", "injection"]
Route = Literal["block_fast", "review", "pass_fast"]

UNTRUSTED_SOURCES: frozenset[str] = frozenset({"retrieved", "uploaded"})


class FileInput(BaseModel):
    filename: str
    content_type: str | None = None
    data_base64: str


class AnalyzeRequest(BaseModel):
    text: str | None = None
    file: FileInput | None = None
    source_type: Source
    session_id: str | None = None
    turn_id: str | None = None
    metadata: dict[str, str] = {}

    @model_validator(mode="after")
    def _exactly_one(self) -> "AnalyzeRequest":
        if (self.text is None) == (self.file is None):
            raise ValueError("provide exactly one of `text` or `file`")
        return self


class Segment(BaseModel):
    id: str
    text: str
    channel: Channel
    location: str
    hidden_reason: str | None = None
    parent: str | None = None


class ParsedContent(BaseModel):
    format: str
    source_type: Source
    segments: list[Segment]
    warnings: list[str] = []
    truncated: bool = False


class Variant(BaseModel):
    segment_id: str
    kind: str                          # original | normalized | base64 | base32 | hex | url | html_entities | ...
    text: str
    depth: int = 0
    span: tuple[int, int] | None = None   # payload span in the ORIGINAL segment text, when known


class HeuristicMatch(BaseModel):
    pattern_id: str
    category: str
    types: list[int]
    weight: float
    segment_id: str
    variant_kind: str
    span: tuple[int, int]
    text: str
    quoted: bool


class EnsembleResult(BaseModel):
    C: float | None
    C1: float | None
    C2: float | None
    H: float
    matches: list[HeuristicMatch]
    flags: list[str]
    all_high_matches_quoted: bool
    sensitive_data_present: list[str]
    types_from_heuristics: list[int]
    flagged_segments: list[str]
    localized_spans: list[dict]        # [{segment_id, start, end, source, label}]
    scripts: list[str]
    degraded: list[str]
    risk_score: float
    # helper fields (not in SPEC §5 table, used by the trace UI and the judge bundle)
    per_segment: dict[str, dict] = {}  # segment_id -> {C, C1, C2, H}
    decoded: list[dict] = []           # [{segment_id, kind, depth, text, C, H}]


class GateDecision(BaseModel):
    route: Route
    rule: str
    reason: str


class Evidence(BaseModel):
    segment_id: str
    quote: str
    grounded: bool | None = None


class AnalyzerVerdict(BaseModel):
    verdict: Verdict
    confidence: float
    attack_types: list[int]
    evidence: list[Evidence]
    multi_step: bool = False
    contributing_turns: list[str] = []
    rationale: str
    recommended_strategy: Literal["none", "strip", "quarantine", "block"] = "none"


class FirewallResponse(BaseModel):
    audit_id: str
    verdict: Verdict
    action: Action
    confidence: float
    attack_types: list[dict]
    clean_content: str | None
    wrapped_content: str | None
    quarantined: list[dict]
    removed_spans: list[dict]
    retroactive_warnings: list[str]
    sensitive_data_present: list[str]
    path: dict
    reasoning_chain: list[str]
    latency_ms: dict
    session: dict | None
    # helper field for the trace UI (scores, flags, scripts, decoded variants, hidden segments)
    trace: dict = {}


class AlignmentVerdict(BaseModel):
    aligned: bool
    confidence: float
    rationale: str


class EgressDecision(BaseModel):
    decision: Literal["allow", "confirm", "block"]
    tool: str
    reasons: list[str]
    audit_id: str


class RedTeamCase(BaseModel):
    case_id: str
    seed_id: str
    intended_types: list[int]
    operators: list[str]
    carrier: str
    payload: str | list[str]
    evaded: bool | None = None
    succeeded_on_victim: bool | None = None


# ---------------- helper models (not in the SPEC table) ----------------

class JudgeEvidence(BaseModel):
    """What the judge LLM may return for evidence. `grounded` is computed by us, never by the LLM."""
    segment_id: str
    quote: str


class JudgeOutput(BaseModel):
    """response_schema for the judge call. Converted to AnalyzerVerdict after grounding."""
    verdict: Verdict
    confidence: float = Field(description="0.0-1.0")
    attack_types: list[int] = Field(description="taxonomy ids 1-9; empty when safe")
    evidence: list[JudgeEvidence] = Field(description="verbatim quotes from the DATA blocks")
    multi_step: bool = False
    contributing_turns: list[str] = []
    rationale: str = Field(description="at most 80 words")
    recommended_strategy: Literal["none", "strip", "quarantine", "block"] = "none"


class EgressCheckRequest(BaseModel):
    tool: str
    args: dict[str, Any]
    user_request: str                  # the user's original (trusted) request
    session_id: str | None = None
    invocation_flagged: bool = False   # did ingress flag anything in this invocation?


class ReviewDecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]   # approve = release content; reject = keep blocked
    label: Literal["benign", "attack"] | None = None
    note: str = ""


class FeedbackRequest(BaseModel):
    kind: Literal["false_positive", "missed_attack", "confirm"]
    note: str = ""


class ChaosRequest(BaseModel):
    CHAOS_LLM_DOWN: bool | None = None
    CHAOS_C1_DOWN: bool | None = None
    CHAOS_C2_DOWN: bool | None = None
    CHAOS_LATENCY_MS: int | None = None
