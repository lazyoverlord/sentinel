"""Output sanitizer (SPEC §15.2, egress for replies): deterministic.

- strips markdown images/links to non-allowlisted domains that carry query parameters (exfil channel)
- redacts DLP hits and canary tokens
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from firewall.integrations.egress import _domain_allowed
from firewall.security.canary import REGISTRY
from firewall.security.redact import redact

_MD_LINK = re.compile(r"(!?)\[([^\]\n]{0,200})\]\(\s*(https?://[^\s)]{1,2000})(?:\s+\"[^\"]*\")?\s*\)")
_BARE_IMG = re.compile(r"<img[^>]+src=[\"'](https?://[^\"']+)[\"'][^>]*>", re.I)


@dataclass
class SanitizeResult:
    text: str
    events: list[dict] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.events)


def _risky_url(url: str, allowlist: list[str]) -> bool:
    u = urlparse(url)
    host = u.hostname or ""
    if _domain_allowed(host, allowlist):
        return False
    return bool(u.query) or "{" in url or "%7B" in url.upper()


def sanitize_output(text: str, *, allowlist: list[str]) -> SanitizeResult:
    events: list[dict] = []

    def md(m: re.Match) -> str:
        bang, label, url = m.group(1), m.group(2), m.group(3)
        if _risky_url(url, allowlist):
            events.append({"type": "exfil_link_removed", "url_host": urlparse(url).hostname, "image": bool(bang)})
            return f"[{label or 'link'} removed: external link with parameters]"
        return m.group(0)

    def img(m: re.Match) -> str:
        if _risky_url(m.group(1), allowlist):
            events.append({"type": "exfil_img_removed", "url_host": urlparse(m.group(1)).hostname})
            return "[image removed]"
        return m.group(0)

    out = _BARE_IMG.sub(img, _MD_LINK.sub(md, text))
    red = redact(out, canaries=REGISTRY.all())
    if red != out:
        events.append({"type": "dlp_redacted", "kinds": sorted(set(re.findall(r"\[REDACTED:([\w.-]+)\]", red)))})
    return SanitizeResult(red, events)
