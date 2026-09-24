"""Audit JSONL and metrics (SPEC §13)."""
import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from firewall.config import Settings
from firewall.observability.audit import AuditLog, jsonl_append, jsonl_read, new_audit_id, to_jsonable
from firewall.observability.metrics import Metrics, parse_price, percentile


@pytest.fixture
def s(tmp_path):
    return Settings(_env_file=None, DATA_DIR=tmp_path)


def today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------- audit ids

def test_audit_ids_are_time_sortable():
    ids = []
    for _ in range(3):
        ids.append(new_audit_id())
        time.sleep(0.002)
    assert all(re.fullmatch(r"[0-9a-f]{12}-[0-9a-f]{8}", i) for i in ids)
    assert sorted(ids) == ids and len(set(ids)) == 3
    assert abs(int(ids[0][:12], 16) / 1000 - time.time()) < 5          # prefix = ms since epoch


# ---------------------------------------------------------------- audit log

def test_write_get_recent(s):
    log = AuditLog(s)
    ids = [log.write({"audit_id": new_audit_id(), "source": "user", "rule": f"R{i}", "action": "allow"})
           for i in range(1, 4)]
    path = s.audit_dir / f"{today()}.jsonl"
    lines = path.read_text().splitlines()
    assert len(lines) == 3 and all(json.loads(line)["ts"].endswith("Z") for line in lines)
    assert log.get(ids[1])["rule"] == "R2"
    assert log.get("nope") is None and log.get("") is None
    assert [r["rule"] for r in log.recent(2)] == ["R3", "R2"]               # newest first
    fresh = AuditLog(s)                                                      # empty index: reads files
    assert fresh.get(ids[0])["rule"] == "R1"
    assert [r["rule"] for r in fresh.recent(10)] == ["R3", "R2", "R1"]


def test_write_fills_missing_id_and_keeps_given_ts(s):
    log = AuditLog(s)
    aid = log.write({"rule": "R8"})
    assert re.fullmatch(r"[0-9a-f]{12}-[0-9a-f]{8}", aid) and log.get(aid)["rule"] == "R8"
    aid2 = log.write({"audit_id": "x-1", "ts": "2026-01-01T00:00:00Z"})
    assert aid2 == "x-1" and log.get("x-1")["ts"] == "2026-01-01T00:00:00Z"


def test_latest_line_wins_for_repeated_id(s):
    log = AuditLog(s)
    log.write({"audit_id": "a-1", "action": "hold_for_review"})
    log.write({"audit_id": "a-1", "action": "allow", "review": "approved"})
    assert log.get("a-1")["action"] == "allow"
    assert AuditLog(s).get("a-1")["action"] == "allow"


def test_raw_keys_dropped_by_default(s):
    log = AuditLog(s)
    aid = log.write({"source": "user", "raw_text": "secret prompt", "judge": {"model": "m", "raw_response": "x"},
                     "segments": [{"id": "S1", "raw_content": "y", "channel": "hidden"}]})
    rec = AuditLog(s).get(aid)
    text = (s.audit_dir / f"{today()}.jsonl").read_text()
    assert "secret prompt" not in text and "raw_" not in text
    assert rec["judge"] == {"model": "m"} and rec["segments"] == [{"id": "S1", "channel": "hidden"}]


def test_raw_keys_kept_when_logging_raw_content(tmp_path):
    s = Settings(_env_file=None, DATA_DIR=tmp_path, LOG_RAW_CONTENT=True)
    log = AuditLog(s)
    aid = log.write({"raw_text": "keep me", "judge": {"raw_response": "r"}})
    assert AuditLog(s).get(aid)["raw_text"] == "keep me"
    assert log.get(aid)["judge"]["raw_response"] == "r"


def test_records_are_serialised_safely(s):
    from firewall.schemas import GateDecision

    log = AuditLog(s)
    aid = log.write({"flags": {"hidden", "exfil"}, "gate": GateDecision(route="review", rule="R5", reason="r"),
                     "blob": b"\x00\x01binary", "path": s.audit_dir, "hindi": "नमस्ते", "odd": "a\ud800b c"})
    rec = AuditLog(s).get(aid)
    assert rec["flags"] == ["exfil", "hidden"] and rec["gate"]["rule"] == "R5"
    assert rec["blob"] == "<8 bytes>" and rec["hindi"] == "नमस्ते"             # raw binary never on disk
    assert rec["odd"] == "a\ud800b c"                                   # lossless, still one line
    assert len((s.audit_dir / f"{today()}.jsonl").read_text(encoding="utf-8").split("\n")) == 2


def test_torn_line_does_not_swallow_the_next_record(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_text('{"a": 1}\n{"b": 2, "trunc')                               # crash mid-write
    jsonl_append(p, {"c": 3})
    assert jsonl_read(p) == [{"a": 1}, {"c": 3}]


def test_concurrent_writes_are_line_atomic(s):
    log = AuditLog(s)

    def worker(k):
        for i in range(50):
            log.write({"audit_id": f"w{k}-{i}", "payload": "z" * 200})
    threads = [threading.Thread(target=worker, args=(k,)) for k in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    recs = jsonl_read(s.audit_dir / f"{today()}.jsonl")
    assert len(recs) == 400 and len({r["audit_id"] for r in recs}) == 400


def test_index_is_bounded(s):
    log = AuditLog(s, index_size=10)
    ids = [log.write({"n": i}) for i in range(25)]
    assert len(log._index) == 10
    assert log.get(ids[0])["n"] == 0                                         # falls back to the files


def test_purge_old_respects_retention(s):
    log = AuditLog(s)
    d = datetime.now(timezone.utc).date()
    names = {k: (d - timedelta(days=k)).isoformat() + ".jsonl" for k in (40, 31, 30, 1, 0)}
    for k, name in names.items():
        (s.audit_dir / name).write_text(json.dumps({"audit_id": f"old-{k}"}) + "\n")
    (s.audit_dir / "notes.txt").write_text("keep")
    (s.audit_dir / "2020-01-01.json").write_text("{}")                     # not an audit file name
    assert log.get("old-40") == {"audit_id": "old-40"}
    assert log.purge_old() == 2                                              # 40 and 31 days old
    left = sorted(p.name for p in s.audit_dir.iterdir())
    assert left == sorted([names[30], names[1], names[0], "notes.txt", "2020-01-01.json"])
    assert log.get("old-40") is None and log.get("old-30") is not None


def test_purge_disabled_with_non_positive_retention(tmp_path):
    s = Settings(_env_file=None, DATA_DIR=tmp_path, AUDIT_RETENTION_DAYS=0)
    log = AuditLog(s)
    (s.audit_dir / "2001-01-01.jsonl").write_text("{}\n")
    assert log.purge_old() == 0 and (s.audit_dir / "2001-01-01.jsonl").exists()


def test_to_jsonable_depth_guard():
    a: dict = {}
    a["self"] = a                                                            # cycle must not recurse forever
    out = to_jsonable(a)
    depth = 0
    while isinstance(out, dict):
        out, depth = out["self"], depth + 1
    assert out == "<max depth>" and depth > 10


# ---------------------------------------------------------------- metrics

def test_percentile_linear_interpolation():
    vals = list(range(1, 101))
    assert percentile(vals, 50) == pytest.approx(50.5)
    assert percentile(vals, 95) == pytest.approx(95.05)
    assert percentile([7.0], 95) == 7.0 and percentile([], 50) is None
    assert percentile([10, 20], 50) == 15


def test_request_counts_latency_and_cache():
    m = Metrics()
    for i in range(1, 101):
        m.record_request(source="user", route="pass_fast", rule="R8", action="allow", latency_ms=float(i),
                         cache_hit=i % 4 == 0, degraded=False)
    m.record_request(source="retrieved", route="review", rule="R5", action="quarantine", latency_ms=900.0,
                     cache_hit=False, degraded=True)
    snap = m.snapshot()
    req = snap["requests"]
    assert req["total"] == 101 and req["degraded"] == 1
    assert req["by_action"] == {"allow": 100, "quarantine": 1}
    assert req["by_route"] == {"pass_fast": 100, "review": 1}
    assert req["by_rule"] == {"R8": 100, "R5": 1} and req["by_source"] == {"user": 100, "retrieved": 1}
    fast = snap["latency_ms"]["by_route"]["pass_fast"]
    assert fast == {"p50": 50.5, "p95": 95.05, "n": 100}
    assert snap["latency_ms"]["by_route"]["review"]["p95"] == 900.0
    assert snap["cache"] == {"hits": 25, "hit_rate": round(25 / 101, 4)}
    assert snap["cost"] is None                                              # no price table
    json.dumps(snap)


def test_latency_window_keeps_last_1000_per_route():
    m = Metrics()
    for i in range(2000):
        m.record_request(source="user", route="pass_fast", rule="R8", action="allow",
                         latency_ms=1000.0 if i < 1000 else 1.0, cache_hit=False, degraded=False)
    lat = m.snapshot()["latency_ms"]["by_route"]["pass_fast"]
    assert lat == {"p50": 1.0, "p95": 1.0, "n": 1000}
    assert m.snapshot()["requests"]["total"] == 2000                        # counters are not windowed


def test_llm_egress_and_cost_estimate():
    m = Metrics()
    for _ in range(4):
        m.record_request(source="user", route="review", rule="R7", action="allow", latency_ms=1200.0,
                         cache_hit=False, degraded=False)
    m.record_llm(role="judge", model="m-judge", ok=True, latency_ms=800, fallback=False,
                 tokens_in=600_000, tokens_out=200_000)
    m.record_llm(role="judge", model="m-judge", ok=True, latency_ms=900, fallback=False,
                 tokens_in=400_000, tokens_out=300_000)
    m.record_llm(role="judge", model="m-lite", ok=False, latency_ms=20000, fallback=True,
                 tokens_in=None, tokens_out=None)
    m.record_llm(role="alignment", model="m-free", ok=True, latency_ms=300, fallback=False,
                 tokens_in=1000, tokens_out=10)
    for d in ("block", "allow", "block"):
        m.record_egress(d)
    snap = m.snapshot(price_table={"m-judge": "1.00/2.00", "m-lite": "0.10/0.40", "m-bad": "oops"},
                      llm_stats={"breaker": {"m-judge": "closed"}, "budget_left": {"m-judge": 190}})
    llm = snap["llm"]
    assert (llm["calls"], llm["errors"], llm["fallbacks"]) == (4, 1, 1)
    assert (llm["tokens_in"], llm["tokens_out"]) == (1_001_000, 500_010)
    assert llm["by_model"]["m-judge"]["tokens_in"] == 1_000_000
    assert llm["by_model"]["m-judge"]["latency_ms"]["p50"] == 850.0
    assert llm["by_role"]["judge"] == {"calls": 3, "errors": 1, "fallbacks": 1}
    assert llm["breaker"] == {"m-judge": "closed"} and llm["budget_left"] == {"m-judge": 190}   # merged
    assert snap["egress"] == {"total": 3, "block": 2, "allow": 1}
    cost = snap["cost"]
    # m-judge: 1.0M in * $1 + 0.5M out * $2 = $2.00; m-lite: no tokens = $0; m-free: not priced
    assert cost["by_model"] == {"m-judge": pytest.approx(2.0), "m-lite": 0.0}
    assert cost["estimated_usd"] == pytest.approx(2.0)
    assert cost["per_1k_requests_usd"] == pytest.approx(500.0)              # $2 over 4 requests
    assert cost["unpriced_models"] == ["m-free"]


def test_cost_without_requests_and_price_parsing():
    m = Metrics()
    assert m.snapshot(price_table={"x": "1/1"})["cost"]["per_1k_requests_usd"] is None
    assert parse_price("0.30/2.50") == (0.30, 2.50)
    assert parse_price("0.30") is None and parse_price(None) is None
