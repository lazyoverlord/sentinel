"""Blue-team patch proposals (SPEC §14): cluster confirmed bypasses and propose regex patterns + exemplars.

Clustering is deterministic (by operator + intended type). A proposed pattern must pass redteam.validator
before a human sees it. The LLM (blue team, Gemini Flash) can refine the regex when a client is supplied.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from firewall.taxonomy import TAXONOMY


def cluster(bypasses: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for b in bypasses:
        op = (b.get("operators") or ["none"])[0]
        typ = (b.get("intended_types") or [0])[0]
        groups[f"{op}:type{typ}"].append(b)
    return dict(groups)


def _keyword_regex(texts: list[str]) -> str | None:
    """A conservative literal-phrase pattern from the most common 3-word shingle across the cluster."""
    counts: dict[str, int] = defaultdict(int)
    for t in texts:
        words = re.findall(r"[a-z]+", t.lower())
        for i in range(len(words) - 2):
            counts[" ".join(words[i:i + 3])] += 1
    if not counts:
        return None
    phrase, n = max(counts.items(), key=lambda kv: kv[1])
    if n < 2:
        return None
    return r"\b" + r"\s+".join(re.escape(w) for w in phrase.split()) + r"\b"


def propose_patterns(bypasses: list[dict], next_index: int = 900) -> list[dict]:
    """One proposed pattern per cluster, from a shared literal phrase. Exemplars cover the rest."""
    out = []
    for i, (name, group) in enumerate(sorted(cluster(bypasses).items())):
        texts = [b["payload_text"] for b in group if isinstance(b.get("payload_text"), str)]
        rx = _keyword_regex(texts)
        if not rx:
            continue
        typ = group[0].get("intended_types", [1])[0] or 1
        cat = {1: "instruction_override", 2: "role_change", 3: "secret_extraction", 4: "tool_abuse",
               5: "credential_request", 6: "fake_authority", 7: "instruction_override"}.get(typ, "low_signal")
        pos = next((t for t in texts if re.search(rx, t, re.I)), texts[0])
        out.append({"id": f"RT-{next_index + i:03d}", "category": cat, "types": [typ], "weight": 0.5,
                    "regex": rx, "description": f"red-team cluster {name}",
                    "example_positive": pos[:200],
                    "example_negative": f"Let's discuss {TAXONOMY[typ].name} in a security class.",
                    "_cluster": name, "_cluster_size": len(group)})
    return out


def propose_exemplars(bypasses: list[dict]) -> list[dict]:
    """Every confirmed bypass becomes a labeled attack exemplar for the judge (advisory; floor still binds)."""
    return [{"text": b["payload_text"][:500], "label": "attack", "types": b.get("intended_types", []),
             "note": f"red-team bypass ({','.join(b.get('operators', []))})"}
            for b in bypasses if isinstance(b.get("payload_text"), str)]
