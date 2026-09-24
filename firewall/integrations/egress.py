"""Egress guard decision logic (SPEC §15.2; port of gate_reference.egress_decision).

Pure functions. The ADK plugin and POST /v1/egress/check compute the deterministic triggers here,
call the alignment judge only when a trigger fires, then call egress_decision().
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlparse

CONFIDENCE_MIN = 0.60

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)")
_URL = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.I)


@dataclass
class Alignment:
    aligned: bool                    # does the proposed action serve the user's original request?
    confidence: float


def egress_decision(*, sensitive: bool, external_destination: bool, dlp_in_args: bool,
                    canary_in_args: bool, invocation_flagged: bool,
                    alignment: Alignment | None, confidence_min: float = CONFIDENCE_MIN) -> str:
    """Returns allow | confirm | block. `alignment` is None when the LLM check is unavailable."""
    if not sensitive:
        return "allow"
    if canary_in_args:
        return "block"                               # a canary leaving is proven exfiltration
    if not (external_destination or dlp_in_args or invocation_flagged):
        return "allow"
    if alignment is None:
        return "block" if invocation_flagged else "confirm"   # ask the human when we can't judge
    if not alignment.aligned or alignment.confidence < confidence_min:
        return "block"
    return "allow"


def _strings(obj: Any) -> Iterable[str]:
    """All string leaves of a (nested) tool-args structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            yield from _strings(v)
    elif obj is not None:
        yield str(obj)


def _domain_allowed(domain: str, allowlist: list[str]) -> bool:
    domain = domain.lower().rstrip(".")
    return any(domain == a.lower() or domain.endswith("." + a.lower()) for a in allowlist)


def destinations(args: dict[str, Any]) -> list[str]:
    """Email domains and URL hosts found anywhere in the args."""
    out: list[str] = []
    for s in _strings(args):
        out += [m.group(1).lower() for m in _EMAIL.finditer(s)]
        for m in _URL.finditer(s):
            host = urlparse(m.group(0)).hostname
            if host:
                out.append(host.lower())
    return sorted(set(out))


def external_destination(args: dict[str, Any], allowlist: list[str]) -> list[str]:
    """Destinations not on the allowlist (empty list = none)."""
    return [d for d in destinations(args) if not _domain_allowed(d, allowlist)]


def args_text(args: dict[str, Any]) -> str:
    return "\n".join(_strings(args))


@dataclass
class EgressTriggers:
    sensitive: bool
    external: list[str]
    dlp: list[str]
    canary: bool
    invocation_flagged: bool

    @property
    def any_trigger(self) -> bool:
        return bool(self.external or self.dlp or self.invocation_flagged)

    def reasons(self) -> list[str]:
        r = []
        if self.canary:
            r.append("canary token in tool arguments (proven exfiltration)")
        if self.external:
            r.append("external destination: " + ", ".join(self.external))
        if self.dlp:
            r.append("sensitive data in arguments: " + ", ".join(self.dlp))
        if self.invocation_flagged:
            r.append("ingress flagged content earlier in this invocation")
        return r


def compute_triggers(tool: str, args: dict[str, Any], *, sensitive_tools: list[str], allowlist: list[str],
                     dlp_scan, canaries: Iterable[str], invocation_flagged: bool) -> EgressTriggers:
    """dlp_scan: callable(text) -> list[str] of DLP kinds (canary excluded here, checked separately)."""
    text = args_text(args)
    canary_hit = any(c and c in text for c in canaries)
    dlp = [k for k in dlp_scan(text) if k != "canary"]
    return EgressTriggers(sensitive=tool in sensitive_tools,
                          external=external_destination(args, allowlist),
                          dlp=dlp, canary=canary_hit, invocation_flagged=invocation_flagged)
