"""In-process metrics for GET /v1/metrics (SPEC §13). Thread-safe counters plus rolling latency windows.

Cost is a projection only (the build runs on the free tier): PRICE_TABLE "model" -> "in/out" USD per 1M
tokens, applied to the tokens recorded through record_llm().
"""
from __future__ import annotations

import math
import threading
import time
from collections import Counter, defaultdict, deque
from typing import Any

WINDOW = 1000   # latency samples kept per route / per model


def percentile(values: list[float] | deque, p: float) -> float | None:
    """Linear-interpolated percentile (numpy's default method); None for no data."""
    v = sorted(values)
    if not v:
        return None
    k = (len(v) - 1) * (p / 100.0)
    lo, hi = math.floor(k), math.ceil(k)
    return float(v[lo] + (v[hi] - v[lo]) * (k - lo))


def _lat(values: deque) -> dict[str, Any]:
    p50, p95 = percentile(values, 50), percentile(values, 95)
    return {"p50": None if p50 is None else round(p50, 2), "p95": None if p95 is None else round(p95, 2),
            "n": len(values)}


def parse_price(spec: Any) -> tuple[float, float] | None:
    """'0.30/2.50' -> (0.30, 2.50) USD per 1M input/output tokens; None if malformed."""
    try:
        a, b = str(spec).split("/", 1)
        return float(a), float(b)
    except (ValueError, TypeError):
        return None


class Metrics:
    def __init__(self, window: int = WINDOW) -> None:
        self._window = window
        self._lock = threading.Lock()
        self._started = time.time()
        self._requests = 0
        self._cache_hits = 0
        self._degraded = 0
        self._by: dict[str, Counter] = {k: Counter() for k in ("action", "route", "rule", "source")}
        self._lat_route: dict[str, deque] = defaultdict(lambda: deque(maxlen=self._window))
        self._lat_all: deque = deque(maxlen=window)
        self._llm: dict[str, dict[str, Any]] = {}
        self._roles: dict[str, Counter] = defaultdict(Counter)
        self._egress: Counter = Counter()

    def record_request(self, *, source: str, route: str, rule: str, action: str, latency_ms: float,
                       cache_hit: bool, degraded: bool) -> None:
        with self._lock:
            self._requests += 1
            self._cache_hits += int(bool(cache_hit))
            self._degraded += int(bool(degraded))
            for key, val in (("action", action), ("route", route), ("rule", rule), ("source", source)):
                self._by[key][str(val)] += 1
            self._lat_route[str(route)].append(float(latency_ms))
            self._lat_all.append(float(latency_ms))

    def record_llm(self, *, role: str, model: str, ok: bool, latency_ms: float, fallback: bool,
                   tokens_in: int | None, tokens_out: int | None) -> None:
        with self._lock:
            m = self._llm.get(model)
            if m is None:
                m = self._llm[model] = {"calls": 0, "errors": 0, "fallbacks": 0, "tokens_in": 0, "tokens_out": 0,
                                        "lat": deque(maxlen=self._window)}
            m["calls"] += 1
            m["errors"] += int(not ok)
            m["fallbacks"] += int(bool(fallback))
            m["tokens_in"] += int(tokens_in or 0)
            m["tokens_out"] += int(tokens_out or 0)
            m["lat"].append(float(latency_ms))
            r = self._roles[str(role)]
            r["calls"] += 1
            r["errors"] += int(not ok)
            r["fallbacks"] += int(bool(fallback))

    def record_egress(self, decision: str) -> None:
        with self._lock:
            self._egress[str(decision)] += 1

    def snapshot(self, *, llm_stats: dict | None = None, price_table: dict[str, str] | None = None) -> dict:
        """JSON-ready metrics. `llm_stats` (e.g. breaker state and budget left from firewall/llm.py) is
        shallow-merged into snapshot["llm"], its keys winning. `cost` is None without a price table."""
        with self._lock:
            n = self._requests
            by_model = {model: {"calls": m["calls"], "errors": m["errors"], "fallbacks": m["fallbacks"],
                                "tokens_in": m["tokens_in"], "tokens_out": m["tokens_out"],
                                "latency_ms": _lat(m["lat"])}
                        for model, m in self._llm.items()}
            llm: dict[str, Any] = {
                "calls": sum(m["calls"] for m in by_model.values()),
                "errors": sum(m["errors"] for m in by_model.values()),
                "fallbacks": sum(m["fallbacks"] for m in by_model.values()),
                "tokens_in": sum(m["tokens_in"] for m in by_model.values()),
                "tokens_out": sum(m["tokens_out"] for m in by_model.values()),
                "by_model": by_model,
                "by_role": {role: dict(c) for role, c in self._roles.items()},
            }
            snap = {
                "uptime_s": round(time.time() - self._started, 1),
                "requests": {"total": n, "degraded": self._degraded,
                             **{f"by_{k}": dict(c) for k, c in self._by.items()}},
                "latency_ms": {"overall": _lat(self._lat_all),
                               "by_route": {route: _lat(v) for route, v in self._lat_route.items()}},
                "cache": {"hits": self._cache_hits, "hit_rate": round(self._cache_hits / n, 4) if n else None},
                "llm": llm,
                "egress": {"total": sum(self._egress.values()), **dict(self._egress)},
            }
        snap["cost"] = _cost(by_model, price_table, n)
        if llm_stats:
            snap["llm"].update(llm_stats)
        return snap


def _cost(by_model: dict[str, dict], price_table: dict[str, str] | None, requests: int) -> dict | None:
    if not price_table:
        return None
    usd_by_model: dict[str, float] = {}
    unpriced: list[str] = []
    for model, m in by_model.items():
        price = parse_price(price_table[model]) if model in price_table else None
        if price is None:
            unpriced.append(model)
            continue
        usd_by_model[model] = round(m["tokens_in"] / 1e6 * price[0] + m["tokens_out"] / 1e6 * price[1], 6)
    total = sum(usd_by_model.values())
    return {"estimated_usd": round(total, 6),
            "per_1k_requests_usd": round(total / requests * 1000, 6) if requests else None,
            "by_model": usd_by_model, "unpriced_models": sorted(unpriced),
            "note": "projection from recorded tokens; the build itself runs on the free tier"}


__all__ = ["Metrics", "percentile", "parse_price", "WINDOW"]
