"""Egress guard service: deterministic triggers → (alignment judge only if a trigger fires) → decision.
Shared by POST /v1/egress/check and the ADK plugin."""
from __future__ import annotations

from typing import Any

from firewall.agents.alignment import check_alignment
from firewall.detection import dlp
from firewall.integrations.egress import Alignment, compute_triggers, egress_decision
from firewall.observability.audit import new_audit_id
from firewall.schemas import EgressDecision
from firewall.security.canary import REGISTRY
from firewall.security.redact import redact_obj


class EgressGuard:
    def __init__(self, fw: Any):
        self.fw = fw
        self.s = fw.s

    async def check(self, *, tool: str, args: dict, user_request: str, invocation_flagged: bool = False,
                    session_id: str | None = None) -> EgressDecision:
        s = self.s
        tr = compute_triggers(tool, args, sensitive_tools=s.SENSITIVE_TOOLS, allowlist=s.EGRESS_ALLOWLIST,
                              dlp_scan=lambda t: dlp.scan(t), canaries=REGISTRY.all(),
                              invocation_flagged=invocation_flagged)
        reasons = tr.reasons()
        alignment = None
        info: dict = {}
        if tr.sensitive and not tr.canary and tr.any_trigger:
            av, info = await check_alignment(self.fw.llm, user_request=user_request, tool=tool, args=args,
                                             reasons=reasons, settings=s)
            if av is not None:
                alignment = Alignment(av.aligned, av.confidence)
                reasons.append(f"alignment judge: {'aligned' if av.aligned else 'NOT aligned'} "
                               f"@ {av.confidence:.2f} — {av.rationale}")
            else:
                reasons.append("alignment judge unavailable")
        decision = egress_decision(sensitive=tr.sensitive, external_destination=bool(tr.external),
                                   dlp_in_args=bool(tr.dlp), canary_in_args=tr.canary,
                                   invocation_flagged=tr.invocation_flagged, alignment=alignment,
                                   confidence_min=s.CONFIDENCE_MIN)
        if not tr.sensitive:
            reasons = ["not a sensitive tool"]
        elif decision == "allow" and not tr.any_trigger:
            reasons = reasons or ["sensitive tool, no trigger (internal destination, no sensitive data)"]
        audit_id = new_audit_id()
        self.fw.audit.write({"audit_id": audit_id, "kind": "egress", "tool": tool, "decision": decision,
                             "reasons": reasons, "args": redact_obj(args), "session_id": session_id,
                             "alignment": info})
        self.fw.metrics.record_egress(decision)
        return EgressDecision(decision=decision, tool=tool, reasons=reasons, audit_id=audit_id)
