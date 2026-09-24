"""ADK plugin (SPEC §15.2): guards any ADK agent. Register with `App(plugins=[SentinelPlugin(fw)])`.

Ingress: user messages scanned as `user`; tool results scanned as `retrieved` (trust comes from the hook,
not from any label) and replaced with provenance-wrapped clean content or the quarantine placeholder.
Egress: sensitive tool calls go through the egress guard; model replies through the output sanitizer.
Verified against google-adk 2.9.2 BasePlugin signatures (keyword-only callbacks).
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Any

from google.adk.plugins.base_plugin import BasePlugin
from google.genai import types

from firewall.integrations.guard import EgressGuard
from firewall.integrations.sanitizer import sanitize_output
from firewall.schemas import AnalyzeRequest, FileInput

log = logging.getLogger(__name__)
_SEVERITY = ["allow", "allow_with_warning", "allow_sanitized", "allow_rewritten", "hold_for_review",
             "quarantine", "block"]
LONG_LEAF = 80


def _text_of(content: types.Content | None) -> str:
    if not content or not content.parts:
        return ""
    return "\n".join(p.text for p in content.parts if getattr(p, "text", None))


def _looks_html(s: str) -> bool:
    low = s[:2000].lower()
    return "<html" in low or "<div" in low or "<p" in low or "<span" in low or "<body" in low


class SentinelPlugin(BasePlugin):
    def __init__(self, fw: Any, *, ingress: bool = True, egress: bool = True, name: str = "sentinel"):
        super().__init__(name=name)
        self.fw = fw
        self.guard = EgressGuard(fw)
        self.ingress = ingress
        self.egress = egress
        self.events: list[dict] = []
        self._user_request: dict[str, str] = {}
        self._flagged: dict[str, bool] = {}

    # ------------------------------------------------------------------ ingress
    async def on_user_message_callback(self, *, invocation_context, user_message: types.Content):
        text = _text_of(user_message)
        inv = invocation_context.invocation_id
        self._user_request[inv] = text
        if not self.ingress or not text:
            return None
        sid = getattr(getattr(invocation_context, "session", None), "id", None)
        r = await self.fw.analyze(AnalyzeRequest(text=text, source_type="user", session_id=sid))
        self.events.append({"hook": "on_user_message", "action": r.action, "rule": r.path.get("rule"),
                            "audit_id": r.audit_id})
        if r.action != "allow":
            self._flagged[inv] = True
        if r.action in ("block", "hold_for_review", "quarantine"):
            return types.Content(role="user", parts=[types.Part(
                text=f"[Message blocked by the firewall ({r.action}, audit {r.audit_id}). Tell the user it "
                     "could not be processed.]")])
        if r.action in ("allow_sanitized", "allow_rewritten") and r.clean_content is not None:
            return types.Content(role="user", parts=[types.Part(text=r.clean_content)])
        return None

    async def _scan_leaf(self, s: str) -> Any:
        if _looks_html(s):
            req = AnalyzeRequest(file=FileInput(filename="tool_result.html", content_type="text/html",
                                                data_base64=base64.b64encode(s.encode()).decode()),
                                 source_type="retrieved")
        else:
            req = AnalyzeRequest(text=s, source_type="retrieved")
        return await self.fw.analyze(req)

    async def after_tool_callback(self, *, tool, tool_args: dict, tool_context, result: dict):
        if not self.ingress or not isinstance(result, dict):
            return None
        inv = tool_context.invocation_id
        actions: list = []

        async def walk(obj: Any) -> Any:
            if isinstance(obj, str) and len(obj) >= LONG_LEAF:
                r = await self._scan_leaf(obj)
                actions.append(r)
                return r.wrapped_content if r.wrapped_content is not None else (r.clean_content or "")
            if isinstance(obj, dict):
                return {k: await walk(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [await walk(v) for v in obj]
            return obj

        new = await walk(result)
        if not actions:
            return None
        worst = max(actions, key=lambda r: _SEVERITY.index(r.action))
        if worst.action != "allow":
            self._flagged[inv] = True
        self.events.append({"hook": "after_tool", "tool": tool.name, "action": worst.action,
                            "rule": worst.path.get("rule"), "audit_ids": [r.audit_id for r in actions],
                            "quarantined": sum(len(r.quarantined) for r in actions),
                            "types": sorted({t["id"] for r in actions for t in r.attack_types})})
        new["_firewall"] = {"action": worst.action, "note": "tool output scanned; untrusted content is wrapped"}
        return new

    # ------------------------------------------------------------------ egress
    async def before_tool_callback(self, *, tool, tool_args: dict, tool_context):
        if not self.egress:
            return None
        inv = tool_context.invocation_id
        user_req = self._user_request.get(inv) or _text_of(getattr(tool_context, "user_content", None))
        d = await self.guard.check(tool=tool.name, args=dict(tool_args), user_request=user_req,
                                   invocation_flagged=self._flagged.get(inv, False))
        self.events.append({"hook": "before_tool", "tool": tool.name, "decision": d.decision,
                            "reasons": d.reasons, "audit_id": d.audit_id,
                            "args": json.loads(json.dumps(tool_args, default=str))})
        if d.decision == "block":
            return {"status": "error", "error": "Action blocked by firewall: not requested by the user.",
                    "audit_id": d.audit_id}
        if d.decision == "confirm":
            return {"status": "pending_confirmation",
                    "error": "The firewall needs the user to confirm this action before it runs.",
                    "audit_id": d.audit_id}
        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        if not self.egress or not llm_response or not llm_response.content or not llm_response.content.parts:
            return None
        changed = False
        parts = []
        for p in llm_response.content.parts:
            if getattr(p, "text", None):
                res = sanitize_output(p.text, allowlist=self.fw.s.EGRESS_ALLOWLIST)
                if res.changed:
                    changed = True
                    self.events.append({"hook": "after_model", "sanitizer": res.events})
                    p = types.Part(text=res.text)
            parts.append(p)
        if not changed:
            return None
        return llm_response.model_copy(update={"content": types.Content(role=llm_response.content.role, parts=parts)})
