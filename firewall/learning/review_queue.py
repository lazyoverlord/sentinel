"""Review queue (SPEC §15.1): items held with action `hold_for_review`, waiting for a human decision.

Persistence: data/feedback/review_queue.jsonl, one full item state per line; on start-up the file is
replayed and the last state per audit_id wins (the file doubles as the decision history).
Item fields (from the pipeline): audit_id, ts, source, summary (redacted excerpt), verdict, action, rule,
reasons, evidence. The queue adds: status (pending | approved | rejected), decision, label, note, decided_at.
"""
from __future__ import annotations

import copy
import threading
from pathlib import Path
from typing import Any

from firewall.observability.audit import jsonl_append, jsonl_read, to_jsonable, utc_now_iso

NOTE_MAX = 2000
_STATUS = {"approve": "approved", "reject": "rejected"}
_LABELS = {"benign", "attack", None}


class ReviewQueue:
    def __init__(self, settings: Any) -> None:
        self.settings = settings
        self.path = Path(settings.review_queue_dir) / "review_queue.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._items: dict[str, dict] = {}          # audit_id -> latest state, in first-seen order
        for rec in jsonl_read(self.path):
            aid = rec.get("audit_id")
            if isinstance(aid, str) and aid:
                self._items[aid] = rec

    def add(self, item: dict) -> None:
        """Queue a held item as pending. A decided item is never re-opened by a repeated add."""
        aid = item.get("audit_id")
        if not isinstance(aid, str) or not aid:
            raise ValueError("review item needs an audit_id")
        rec = to_jsonable(dict(item), drop_raw=not self.settings.LOG_RAW_CONTENT)
        rec.setdefault("ts", utc_now_iso())
        rec.update(status="pending", decision=None, label=None, note="", decided_at=None)
        with self._lock:
            current = self._items.get(aid)
            if current is not None and current.get("status") != "pending":
                return
            self._items[aid] = rec
            jsonl_append(self.path, rec)

    def pending(self) -> list[dict]:
        """Pending items, oldest first."""
        with self._lock:
            return [copy.deepcopy(r) for r in self._items.values() if r.get("status") == "pending"]

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            rec = self._items.get(audit_id)
            return copy.deepcopy(rec) if rec is not None else None

    def decide(self, audit_id: str, decision: str, label: str | None = None, note: str = "") -> dict:
        """approve = release the content, reject = keep it blocked. Raises KeyError for an unknown id and
        ValueError for a bad decision/label. Deciding again overwrites (the file keeps every state)."""
        if decision not in _STATUS:
            raise ValueError(f"decision must be 'approve' or 'reject', not {decision!r}")
        if label not in _LABELS:
            raise ValueError(f"label must be 'benign', 'attack' or None, not {label!r}")
        with self._lock:
            current = self._items.get(audit_id)
            if current is None:
                raise KeyError(audit_id)
            rec = {**current, "status": _STATUS[decision], "decision": decision, "label": label,
                   "note": str(note)[:NOTE_MAX], "decided_at": utc_now_iso()}
            self._items[audit_id] = rec
            jsonl_append(self.path, rec)
            return copy.deepcopy(rec)


__all__ = ["ReviewQueue"]
