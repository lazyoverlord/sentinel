"""Session memory (SPEC §11). Watch-mode semantics must equal firewall.gate exactly, including after old
turns are evicted from the retained window."""
import random

import pytest

from firewall.config import Settings
from firewall.gate import (Review, Signals, Thresholds, Turn, action_policy, gate, post_review, risk_score,
                           sticky, watch_mode_on, Localization)
from firewall.session.memory import EXCERPT_MAX, SessionStore, TurnRecord


def store(**kw):
    return SessionStore(Settings(_env_file=None, **kw))


def rec(turn_id, risk, verdict, action, rule, excerpt="...", types=()):
    return TurnRecord(turn_id=turn_id, excerpt=excerpt, risk=risk, verdict=verdict, action=action, rule=rule,
                      types=list(types), ts=0.0)


def clean(turn_id, rule="R8", risk=0.01):
    return rec(turn_id, risk, "safe", "allow", rule)


def trigger(turn_id, rule="R7"):
    return rec(turn_id, 0.4, "suspicious", "allow_with_warning", rule)


# ---------------------------------------------------------------- SPEC §22 row 8 and gate reference scenarios

def test_multi_step_novel_escalation_row8():
    st, sid = store(), "s-row8"
    turns = [("T1", Signals("user", C=0.02, H=0.0)), ("T2", Signals("user", C=0.05, H=0.0))]
    for tid, s in turns:
        assert st.next_turn_id(sid) == tid
        g = gate(s, st.watch_mode(sid))
        assert g.rule == "R8"
        st.record(sid, rec(tid, risk_score(s), "safe", "allow", g.rule, excerpt=f"chapter {tid}"))
    assert not st.watch_mode(sid)

    t3 = Signals("user", C=0.35, H=0.4)                        # ai_manipulation_intent pattern
    g3 = gate(t3, st.watch_mode(sid))
    assert g3.rule == "R7"
    st.record(sid, rec("T3", risk_score(t3), "safe", "allow", g3.rule, types=[7]))   # judge said safe
    assert st.watch_mode(sid) and not st.sticky(sid)            # R7 is a trigger even when judged safe

    t4 = Signals("user", C=0.08, H=0.0)
    assert gate(t4, False).rule == "R8"                         # alone it would pass
    g4 = gate(t4, st.watch_mode(sid))
    assert g4.rule == "R6"
    assert [c["turn_id"] for c in st.context(sid)] == ["T1", "T2", "T3"]
    review = Review("injection", 0.88, grounded_evidence=0, multi_step=True, contributing_turns=["T3"])
    verdict, hold = post_review(t4, review)
    action = action_policy(verdict, t4, Localization(), multi_step=True, hold_by_floor=hold)
    assert (verdict, action) == ("injection", "block")
    warnings = st.retroactive_warnings(sid, review.contributing_turns, "T4")
    assert warnings == ["Turn T3 contributed to a multi-step attack blocked at T4."]
    st.record(sid, rec("T4", risk_score(t4, g4.rule), verdict, action, g4.rule, types=[7]))

    snap = st.snapshot(sid)
    assert [t["retro_flagged"] for t in snap["turns"]] == [False, False, True, False]
    assert snap["watch_mode"] and snap["sticky"] and snap["lifetime_triggers"] == 2 and snap["total_turns"] == 4
    assert st.next_turn_id(sid) == "T5"


def test_watch_mode_expires_after_five_clean_turns():
    st, sid = store(), "s-expire"
    st.record(sid, rec("T0", 0.5, "suspicious", "allow_with_warning", "R7"))
    for i in range(1, 5):
        st.record(sid, clean(f"T{i}", rule="R6"))
        assert st.watch_mode(sid)
    st.record(sid, clean("T5", rule="R6"))
    assert not st.watch_mode(sid)


def test_sticky_needs_ten_clean_turns():
    st, sid = store(), "s-sticky"
    st.record(sid, trigger("T1"))
    st.record(sid, trigger("T2", rule="R6"))                    # two lifetime triggers -> sticky
    assert st.sticky(sid)
    for i in range(5):
        st.record(sid, clean(f"C{i}", rule="R6", risk=0.02))
    assert st.watch_mode(sid)                                   # 5 clean turns no longer enough
    for i in range(5):
        st.record(sid, clean(f"D{i}", rule="R6", risk=0.02))
    assert not st.watch_mode(sid)                               # 10 clean turns: off
    assert st.sticky(sid)                                       # stickiness itself is lifetime


def test_sub_threshold_drip_accumulates():
    st, sid = store(), "s-drip"
    for i in range(4):
        st.record(sid, rec(f"T{i}", 0.29, "safe", "allow", "R8"))   # each just under R7, Σ = 1.16
    assert not st.watch_mode(sid)
    st.record(sid, rec("T4", 0.29, "safe", "allow", "R8"))           # Σ = 1.45 >= 1.2
    assert st.watch_mode(sid)


# ---------------------------------------------------------------- eviction keeps the semantics

def test_more_than_thirty_turns_keeps_sticky_semantics():
    st, sid = store(), "s-long"
    assert st.keep == 30
    st.record(sid, trigger("T1"))
    st.record(sid, trigger("T2"))
    for i in range(35):
        st.record(sid, clean(f"C{i}"))
    assert len(st.history(sid)) == 30                           # both triggers have been evicted...
    assert all(r.verdict == "safe" for r in st.history(sid))
    assert st.sticky(sid) and st.snapshot(sid)["lifetime_triggers"] == 2   # ...but still count
    assert not st.watch_mode(sid)
    st.record(sid, trigger("T38"))                              # third trigger, long after the first two
    for i in range(5):
        st.record(sid, clean(f"E{i}"))
    assert st.watch_mode(sid)                                   # a window-only count would say OFF here
    for i in range(5):
        st.record(sid, clean(f"F{i}"))
    assert not st.watch_mode(sid)


@pytest.mark.parametrize("cfg", [
    {},
    {"WATCH_WINDOW": 4, "WATCH_OFF_AFTER": 2, "WATCH_OFF_AFTER_STICKY": 6, "STICKY_TRIGGERS": 3},
    {"WATCH_WINDOW": 2, "WATCH_OFF_AFTER": 5, "WATCH_OFF_AFTER_STICKY": 9, "WATCH_RISK_SUM": 0.5},
])
def test_store_matches_gate_on_full_history(cfg):
    """Differential check: after every turn, store == gate.watch_mode_on / sticky over the FULL history."""
    st = store(**cfg)
    t = Thresholds.from_settings(Settings(_env_file=None, **cfg))
    rng = random.Random(20260924)
    full: list[Turn] = []
    kinds = [
        (0.55, lambda i: clean(f"T{i}", rule=rng.choice(["R8", "R6", "R8a"]), risk=rng.choice([0.0, 0.05, 0.14]))),
        (0.10, lambda i: rec(f"T{i}", rng.choice([0.15, 0.29]), "safe", "allow", "R8")),     # not clean, no trigger
        (0.10, lambda i: rec(f"T{i}", 0.4, "safe", "allow", "R7")),
        (0.05, lambda i: rec(f"T{i}", 0.5, "suspicious", "allow_with_warning", "R6")),
        (0.03, lambda i: rec(f"T{i}", 0.95, "injection", "block", "R4")),
        (0.02, lambda i: rec(f"T{i}", 0.3, "safe", "hold_for_review", "R5")),
        (0.15, None),                                                                      # long clean run
    ]
    i = 0
    while i < 400:
        r = rng.random()
        for weight, make in kinds:
            r -= weight
            if r <= 0:
                break
        batch = [make(i)] if make else [clean(f"T{i + j}") for j in range(rng.randint(8, 25))]
        for tr in batch:
            st.record("s", tr)
            full.append(tr.as_turn())
            i += 1
            assert st.watch_mode("s") == watch_mode_on(full, t), f"watch mismatch at turn {i}"
            assert st.sticky("s") == sticky(full, t), f"sticky mismatch at turn {i}"
    assert len(st.history("s")) == st.keep < len(full)


# ---------------------------------------------------------------- store mechanics

def test_lru_eviction_and_reset():
    st = store(SESSION_MAX=2)
    st.record("a", clean("T1"))
    st.record("b", clean("T1"))
    assert st.watch_mode("a") is False                          # any access refreshes recency
    st.record("c", clean("T1"))
    assert "b" not in st and "a" in st and "c" in st and len(st) == 2
    assert st.history("b") == [] and st.next_turn_id("b") == "T1"
    st.reset("a")
    assert "a" not in st and len(st) == 1
    assert st.snapshot("a") == {"session_id": "a", "turns": [], "watch_mode": False, "sticky": False,
                                "lifetime_triggers": 0, "total_turns": 0}


def test_reads_do_not_create_sessions():
    st = store()
    assert not st.watch_mode("ghost") and not st.sticky("ghost") and st.context("ghost") == []
    assert st.retroactive_warnings("ghost", ["T1"], "T2") == [] and len(st) == 0


def test_retroactive_warnings_skip_unknown_and_current_turns():
    st, sid = store(), "s-retro"
    for tid in ("T1", "T2", "T3"):
        st.record(sid, clean(tid))
    out = st.retroactive_warnings(sid, ["T3", "T99", "T4", "T1", "T3", " "], "T4")
    assert out == ["Turn T1 contributed to a multi-step attack blocked at T4.",
                   "Turn T3 contributed to a multi-step attack blocked at T4."]      # oldest first, deduped
    assert [r.retro_flagged for r in st.history(sid)] == [True, False, True]
    # retro flags are display-only: they don't change what counts as a trigger
    assert not st.sticky(sid) and st.snapshot(sid)["lifetime_triggers"] == 0


def test_context_and_excerpt_limits():
    st, sid = store(), "s-ctx"
    for i in range(12):
        st.record(sid, rec(f"T{i + 1}", 0.01 * i, "safe", "allow", "R8", excerpt="x" * 500))
    ctx = st.context(sid)
    assert [c["turn_id"] for c in ctx] == [f"T{i}" for i in range(3, 13)]
    assert set(ctx[0]) == {"turn_id", "excerpt", "verdict", "action", "rule", "risk"}
    assert all(len(c["excerpt"]) == EXCERPT_MAX for c in ctx)
    assert [c["turn_id"] for c in st.context(sid, n=2)] == ["T11", "T12"] and st.context(sid, n=0) == []


def test_history_returns_copies():
    st, sid = store(), "s-copy"
    st.record(sid, rec("T1", 0.01, "safe", "allow", "R8", types=[1]))
    h = st.history(sid)
    h[0].verdict, h[0].types[0] = "injection", 9
    assert st.history(sid)[0].verdict == "safe" and st.history(sid)[0].types == [1]


def test_long_session_ids_are_bounded():
    st = store()
    sid = "x" * 10_000
    st.record(sid, clean("T1"))
    assert sid in st and st.next_turn_id(sid) == "T2"
    assert st.snapshot(sid)["session_id"] == sid
    assert all(len(k) <= 128 + 7 for k in st._sessions)
