"""Session memory (SPEC §11): per-session turn history and watch mode, in an in-process LRU.

Watch-mode semantics are exactly `firewall.gate.watch_mode_on` / `gate.sticky`; this store only keeps
the data. It retains the last WATCH_WINDOW*3 turns per session for display, plus a lifetime trigger
counter. `gate` needs (a) the lifetime trigger count and (b) the last max(WATCH_WINDOW, off-after)
turns, so we hand it the retained turns prefixed by synthetic trigger turns standing in for evicted
triggers (capped at STICKY_TRIGGERS). That list gives the same answer as the full history would.

Call order in the pipeline: `watch_mode(sid)` before gating a turn (history excludes that turn), then
`record(sid, TurnRecord(...))` once its verdict and action are final.
"""
from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass, replace
from typing import Any

from firewall.gate import Thresholds, Turn, is_trigger, sticky as _gate_sticky, watch_mode_on

EXCERPT_MAX = 200         # SPEC §11: excerpt <= 200 chars, redacted by the caller
_KEY_MAX = 128            # longer session ids are hashed so hostile ids can't eat memory
_EVICTED_TRIGGER = Turn("(evicted)", 0.0, "suspicious", "allow_with_warning", "R7")


@dataclass
class TurnRecord:
    turn_id: str
    excerpt: str
    risk: float
    verdict: str
    action: str
    rule: str
    types: list[int]
    ts: float
    retro_flagged: bool = False

    def as_turn(self) -> Turn:
        return Turn(self.turn_id, self.risk, self.verdict, self.action, self.rule)


@dataclass
class _Session:
    turns: deque                          # deque[TurnRecord], maxlen = SessionStore.keep
    total: int = 0                        # turns ever recorded
    lifetime_triggers: int = 0            # triggers ever recorded (including evicted turns)


def _copy(rec: TurnRecord) -> TurnRecord:
    return replace(rec, types=list(rec.types))


class SessionStore:
    def __init__(self, settings: Any) -> None:
        self.t = Thresholds.from_settings(settings)
        self.capacity = max(1, int(settings.SESSION_MAX))
        # gate looks back at most max(WATCH_WINDOW, off-after) turns; keep at least that many
        self.keep = max(int(settings.WATCH_WINDOW) * 3, self.t.WATCH_WINDOW, self.t.WATCH_OFF_AFTER,
                        self.t.WATCH_OFF_AFTER_STICKY, 1)
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._lock = threading.RLock()

    # ---- internals
    @staticmethod
    def _key(session_id: str) -> str:
        sid = str(session_id)
        return sid if len(sid) <= _KEY_MAX else "sha256:" + hashlib.sha256(sid.encode("utf-8", "replace")).hexdigest()

    def _get(self, session_id: str, *, create: bool = False) -> _Session | None:
        key = self._key(session_id)
        sess = self._sessions.get(key)
        if sess is not None:
            self._sessions.move_to_end(key)
        elif create:
            sess = self._sessions[key] = _Session(deque(maxlen=self.keep))
            while len(self._sessions) > self.capacity:
                self._sessions.popitem(last=False)             # least recently used
        return sess

    def _gate_history(self, sess: _Session) -> list[Turn]:
        retained = [r.as_turn() for r in sess.turns]
        evicted_triggers = sess.lifetime_triggers - sum(is_trigger(x) for x in retained)
        prefix = min(max(evicted_triggers, 0), max(self.t.STICKY_TRIGGERS, 0))
        return [_EVICTED_TRIGGER] * prefix + retained

    # ---- API
    def next_turn_id(self, session_id: str) -> str:
        with self._lock:
            sess = self._get(session_id)
            return f"T{(sess.total if sess else 0) + 1}"

    def history(self, session_id: str) -> list[TurnRecord]:
        with self._lock:
            sess = self._get(session_id)
            return [_copy(r) for r in sess.turns] if sess else []

    def watch_mode(self, session_id: str) -> bool:
        with self._lock:
            sess = self._get(session_id)
            return bool(sess) and watch_mode_on(self._gate_history(sess), self.t)

    def sticky(self, session_id: str) -> bool:
        with self._lock:
            sess = self._get(session_id)
            return bool(sess) and _gate_sticky(self._gate_history(sess), self.t)

    def context(self, session_id: str, n: int = 10) -> list[dict]:
        """Last n turns for the judge's session context (excerpts are already redacted)."""
        if n <= 0:
            return []
        with self._lock:
            sess = self._get(session_id)
            recs = list(sess.turns)[-n:] if sess else []
            return [{"turn_id": r.turn_id, "excerpt": r.excerpt, "verdict": r.verdict, "action": r.action,
                     "rule": r.rule, "risk": r.risk} for r in recs]

    def record(self, session_id: str, rec: TurnRecord) -> None:
        """Append a finished turn. `rec.excerpt` must already be redacted; it is cut to 200 chars here."""
        excerpt = rec.excerpt if len(rec.excerpt) <= EXCERPT_MAX else rec.excerpt[:EXCERPT_MAX - 1] + "…"
        rec = replace(rec, excerpt=excerpt, types=list(rec.types))
        with self._lock:
            sess = self._get(session_id, create=True)
            sess.turns.append(rec)
            sess.total += 1
            sess.lifetime_triggers += int(is_trigger(rec.as_turn()))

    def retroactive_warnings(self, session_id: str, contributing_turns: list[str], current_turn: str) -> list[str]:
        """Mark earlier turns that contributed to a multi-step attack; one message per turn, oldest first.

        Ids the session doesn't hold (e.g. hallucinated by the judge) and the current turn are skipped.
        """
        wanted = {str(t).strip() for t in contributing_turns} - {"", str(current_turn)}
        out: list[str] = []
        with self._lock:
            sess = self._get(session_id)
            if not sess:
                return []
            for r in sess.turns:
                if r.turn_id in wanted:
                    r.retro_flagged = True
                    msg = f"Turn {r.turn_id} contributed to a multi-step attack blocked at {current_turn}."
                    if msg not in out:
                        out.append(msg)
        return out

    def snapshot(self, session_id: str) -> dict:
        with self._lock:
            sess = self._get(session_id)
            if not sess:
                return {"session_id": session_id, "turns": [], "watch_mode": False, "sticky": False,
                        "lifetime_triggers": 0, "total_turns": 0}
            hist = self._gate_history(sess)
            return {"session_id": session_id, "turns": [asdict(r) for r in sess.turns],
                    "watch_mode": watch_mode_on(hist, self.t), "sticky": _gate_sticky(hist, self.t),
                    "lifetime_triggers": sess.lifetime_triggers, "total_turns": sess.total}

    def reset(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(self._key(session_id), None)

    def __len__(self) -> int:
        return len(self._sessions)

    def __contains__(self, session_id: object) -> bool:
        return isinstance(session_id, str) and self._key(session_id) in self._sessions


__all__ = ["TurnRecord", "SessionStore", "EXCERPT_MAX"]
