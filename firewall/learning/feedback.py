"""Feedback store (SPEC §14): review decisions and false_positive / missed_attack reports, with evidence.

Append-only JSONL at data/feedback/feedback.jsonl. Only admin-token API calls may write (enforced in
api/server.py). Evidence must already be redacted; `raw_*` keys are dropped unless LOG_RAW_CONTENT=true.
"""
from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

from firewall.observability.audit import jsonl_append, jsonl_read, new_audit_id, to_jsonable, utc_now_iso

NOTE_MAX = 2000
_KIND = re.compile(r"^[a-z][a-z_]{0,31}$")   # e.g. false_positive, missed_attack, confirm, review


class FeedbackStore:
    def __init__(self, settings: Any) -> None:
        self.settings = settings
        self.path = Path(settings.feedback_dir) / "feedback.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def add(self, audit_id: str, kind: str, note: str = "", evidence: dict | None = None) -> dict:
        if not isinstance(audit_id, str) or not audit_id or len(audit_id) > 128:
            raise ValueError("audit_id must be a non-empty string (<= 128 chars)")
        if not isinstance(kind, str) or not _KIND.match(kind):
            raise ValueError(f"invalid feedback kind {kind!r}")
        rec = to_jsonable({"feedback_id": new_audit_id(), "audit_id": audit_id, "kind": kind,
                           "note": str(note)[:NOTE_MAX], "evidence": evidence or {}, "ts": utc_now_iso()},
                          drop_raw=not self.settings.LOG_RAW_CONTENT)
        with self._lock:
            jsonl_append(self.path, rec)
        return rec

    def list(self, limit: int = 100) -> list[dict]:
        """The last `limit` entries, newest first."""
        if limit <= 0:
            return []
        return jsonl_read(self.path)[-limit:][::-1]


__all__ = ["FeedbackStore"]
