"""Exemplar memory (SPEC §14, Should): confirmed cases retrieved by TF-IDF similarity for the judge.

TF-IDF over character 3-5-grams (`char_wb`) is robust to small rewordings, typos and spacing tricks,
and needs no model download. The top matches go into the judge prompt as labeled examples. Exemplars
only ADVISE the judge; the post-review floor still binds (enforced in gate.post_review), so poisoned
feedback can't clear strong deterministic evidence.

Stored text is redacted and cut to 500 chars. Pass the project's DLP redactor as `redactor=`; a small
built-in pass (keys, tokens, Aadhaar/PAN/UPI, canaries) always runs as a safety net.
Persistence: data/feedback/exemplars.jsonl (append-only, reloaded on start-up).
"""
from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any, Callable

from firewall.observability.audit import jsonl_append, jsonl_read, utc_now_iso
from firewall.security.canary import CANARY_RE

TEXT_MAX = 500
QUERY_MAX = 5000          # bound the cost of scoring huge inputs
LABELS = ("attack", "benign")

_SAFETY_NET = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("aadhaar", re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b")),
    ("pan", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("upi_id", re.compile(r"\b[\w.\-]{2,64}@[A-Za-z]{2,32}\b(?![.@\w])")),
    ("canary", CANARY_RE),
]


def basic_redact(text: str) -> str:
    for kind, rx in _SAFETY_NET:
        text = rx.sub(f"[REDACTED:{kind}]", text)
    return text


def _types(types: Any) -> list[int]:
    out: set[int] = set()
    for x in types or []:
        try:
            v = int(x)
        except (TypeError, ValueError):
            continue
        if 1 <= v <= 9:
            out.add(v)
    return sorted(out)


class ExemplarMemory:
    def __init__(self, settings: Any, *, redactor: Callable[[str], str] | None = None) -> None:
        self.path = Path(settings.feedback_dir) / "exemplars.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._redactor = redactor
        self._lock = threading.Lock()
        self._items: list[dict] = []
        self._keys: set[tuple[str, str]] = set()
        for rec in jsonl_read(self.path):
            if isinstance(rec.get("text"), str) and rec["text"].strip() and rec.get("label") in LABELS:
                self._remember({"text": rec["text"][:TEXT_MAX], "label": rec["label"],
                                "types": _types(rec.get("types")), "note": str(rec.get("note", "")),
                                "ts": rec.get("ts")})
        self._vectorizer: Any = None
        self._matrix: Any = None
        self._dirty = True

    def _remember(self, rec: dict) -> bool:
        key = (rec["text"], rec["label"])
        if key in self._keys:
            return False
        self._keys.add(key)
        self._items.append(rec)
        return True

    def _clean(self, text: str) -> str:
        t = str(text)[: TEXT_MAX * 4]                  # redact a margin first, so no secret is cut in half
        if self._redactor is not None:
            t = self._redactor(t)
        return basic_redact(t)[:TEXT_MAX]

    def add(self, text: str, label: str, types: list[int] | None = None, note: str = "") -> None:
        """Store a confirmed case (redacted, <= 500 chars). Exact duplicates are ignored."""
        if label not in LABELS:
            raise ValueError(f"label must be 'attack' or 'benign', not {label!r}")
        clean = self._clean(text)
        if not clean.strip():
            raise ValueError("exemplar text is empty")
        rec = {"text": clean, "label": label, "types": _types(types), "note": str(note)[:TEXT_MAX],
               "ts": utc_now_iso()}
        with self._lock:
            if self._remember(rec):
                jsonl_append(self.path, rec)
                self._dirty = True

    def _fit(self) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer   # lazy: keeps imports fast

        self._vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), lowercase=True,
                                           sublinear_tf=True)
        self._matrix = self._vectorizer.fit_transform([it["text"] for it in self._items])
        self._dirty = False

    def top_k(self, text: str, k: int = 3, min_sim: float = 0.2) -> list[dict]:
        """Up to k most similar exemplars with cosine similarity >= min_sim, most similar first."""
        if k <= 0:
            return []
        with self._lock:
            if not self._items:
                return []
            if self._dirty:
                self._fit()
            query = self._vectorizer.transform([str(text or "")[:QUERY_MAX]])
            sims = (self._matrix @ query.T).toarray().ravel()   # rows are L2-normalised: dot = cosine
            order = sorted(range(len(sims)), key=lambda i: (-sims[i], i))
            out = []
            for i in order[:k]:
                if sims[i] < min_sim:
                    break
                it = self._items[i]
                out.append({"text": it["text"], "label": it["label"], "types": list(it["types"]),
                            "sim": round(float(sims[i]), 4)})
            return out

    def list(self, limit: int = 100) -> list[dict]:
        """Stored exemplars, newest first (for the Review & learning tab)."""
        if limit <= 0:
            return []
        with self._lock:
            return [dict(it, types=list(it["types"])) for it in self._items[-limit:][::-1]]

    def __len__(self) -> int:
        return len(self._items)


__all__ = ["ExemplarMemory", "basic_redact", "TEXT_MAX", "LABELS"]
