"""REST API (SPEC §15.1). One process owns models, sessions, caches and demo agents.

Run: uv run uvicorn api.server:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import hmac
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from firewall.config import Settings, get_settings
from firewall.integrations.guard import EgressGuard
from firewall.pipeline import Firewall
from firewall.schemas import (AnalyzeRequest, ChaosRequest, EgressCheckRequest, EgressDecision, FeedbackRequest,
                              FirewallResponse, ReviewDecisionRequest)

log = logging.getLogger("api")
MAX_BODY = 16 * 1024 * 1024       # base64 of a 10 MB file + JSON overhead


def create_app(settings: Settings | None = None, firewall: Firewall | None = None) -> FastAPI:
    s = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        fw = firewall or Firewall(s)
        app.state.fw = fw
        app.state.guard = EgressGuard(fw)
        app.state.startup = await fw.startup()
        app.state.demo = None
        try:
            fw.audit.purge_old()
        except Exception:
            pass
        yield
        fw.close()

    app = FastAPI(title=f"{s.APP_NAME} prompt-injection firewall", version="0.1.0", lifespan=lifespan)
    app.state.settings = s

    @app.middleware("http")
    async def body_limit(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_BODY:
            return JSONResponse({"detail": "request too large"}, status_code=413)
        return await call_next(request)

    def fw_dep(request: Request) -> Firewall:
        return request.app.state.fw

    def admin(x_admin_token: str | None = Header(default=None)) -> None:
        expected = s.admin_token
        if not expected:
            raise HTTPException(503, "ADMIN_TOKEN is not configured on the server")
        if not x_admin_token or not hmac.compare_digest(x_admin_token, expected):
            raise HTTPException(401, "missing or invalid X-Admin-Token")

    @app.get("/health")
    async def health(request: Request) -> dict:
        fw: Firewall = request.app.state.fw
        return {"status": "ok", "app": s.APP_NAME, "classifiers": list(fw.ensemble.loaded),
                "degraded": list(fw.bank.degraded) if fw.bank else ["classifiers: none"],
                "patterns_version": fw.heuristics.version, "policy_version": s.policy_version,
                "dev_mode": s.DEV_MODE, "llm_configured": bool(s.google_api_key),
                "chaos": {k: s.chaos(k) for k in ("CHAOS_LLM_DOWN", "CHAOS_C1_DOWN", "CHAOS_C2_DOWN",
                                                  "CHAOS_LATENCY_MS")},
                "built_with_llama": any(n.startswith("c2") for n in fw.ensemble.loaded),
                "startup": request.app.state.startup}

    @app.post("/v1/analyze", response_model=FirewallResponse)
    async def analyze(req: AnalyzeRequest, fw: Firewall = Depends(fw_dep)) -> FirewallResponse:
        try:
            return await fw.analyze(req)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/v1/egress/check", response_model=EgressDecision)
    async def egress_check(req: EgressCheckRequest, request: Request) -> EgressDecision:
        return await request.app.state.guard.check(tool=req.tool, args=req.args, user_request=req.user_request,
                                                   invocation_flagged=req.invocation_flagged,
                                                   session_id=req.session_id)

    @app.get("/v1/review/queue")
    async def review_queue(fw: Firewall = Depends(fw_dep)) -> list[dict]:
        return [{k: v for k, v in it.items() if not k.startswith("raw_")} for it in fw.review_queue.pending()]

    @app.post("/v1/review/{audit_id}", dependencies=[Depends(admin)])
    async def review_decide(audit_id: str, body: ReviewDecisionRequest, fw: Firewall = Depends(fw_dep)) -> dict:
        try:
            item = fw.decide_review(audit_id, body.decision, body.label, body.note)
        except KeyError as e:
            raise HTTPException(404, "unknown audit id") from e
        except ValueError as e:
            raise HTTPException(409, str(e)) from e
        return {k: v for k, v in item.items() if not k.startswith("raw_")}

    @app.post("/v1/feedback/{audit_id}", dependencies=[Depends(admin)])
    async def feedback(audit_id: str, body: FeedbackRequest, fw: Firewall = Depends(fw_dep)) -> dict:
        rec = fw.audit.get(audit_id)
        if rec is None:
            raise HTTPException(404, "unknown audit id")
        return fw.feedback.add(audit_id, body.kind, body.note, evidence={"verdict": rec.get("verdict"),
                                                                        "action": rec.get("action"),
                                                                        "rule": rec.get("rule")})

    @app.get("/v1/audit/{audit_id}")
    async def audit(audit_id: str, fw: Firewall = Depends(fw_dep)) -> dict:
        rec = fw.audit.get(audit_id)
        if rec is None:
            raise HTTPException(404, "unknown audit id")
        return {k: v for k, v in rec.items() if not k.startswith("raw_")}

    @app.get("/v1/audit")
    async def audit_recent(n: int = 50, fw: Firewall = Depends(fw_dep)) -> list[dict]:
        return [{k: v for k, v in r.items() if not k.startswith("raw_")} for r in fw.audit.recent(min(n, 500))]

    @app.get("/v1/metrics")
    async def metrics(fw: Firewall = Depends(fw_dep)) -> dict:
        snap = fw.metrics.snapshot(llm_stats=fw.llm.stats(), price_table=s.PRICE_TABLE)
        snap["verdict_cache"] = {"hits": fw.verdict_cache.hits, "misses": fw.verdict_cache.misses}
        snap["review_pending"] = len(fw.review_queue.pending())
        return snap

    @app.post("/v1/demo/inboxpilot")
    async def demo_inboxpilot(body: dict, request: Request) -> dict:
        from demo_agent.inboxpilot import run_demo
        mode = body.get("mode", "both")
        if mode not in ("unprotected", "ingress", "egress", "both"):
            raise HTTPException(400, "mode must be unprotected | ingress | egress | both")
        return await run_demo(request.app.state.fw, mode=mode, victim=body.get("victim", "auto"),
                              user_request=body.get("user_request"))

    @app.post("/v1/redteam/run", dependencies=[Depends(admin)])
    async def redteam_run(body: dict, fw: Firewall = Depends(fw_dep)) -> dict:
        from redteam.loop import hardening
        rounds = min(int(body.get("rounds", 2)), 5)
        return await hardening(rounds, int(body.get("per_seed", 6)), body.get("victim", "auto"),
                               bool(body.get("llm_gen", False)))

    @app.post("/v1/patterns/approve", dependencies=[Depends(admin)])
    async def patterns_approve(body: dict, fw: Firewall = Depends(fw_dep)) -> dict:
        """Append a human-approved (already-validated) pattern to data/patterns.json and reload."""
        pat = {k: v for k, v in body.get("pattern", {}).items() if not k.startswith("_")}
        from redteam.validator import validate_pattern
        valid, reasons = validate_pattern(pat, [pat.get("example_positive", "")], [])
        if not valid:
            raise HTTPException(409, f"pattern failed validation: {reasons}")
        added = fw.append_pattern(pat)
        return {"added": added, "patterns_version": fw.heuristics.version, "count": len(fw.heuristics.patterns)}

    if s.DEV_MODE:
        @app.post("/v1/chaos", dependencies=[Depends(admin)])
        async def chaos(body: ChaosRequest, fw: Firewall = Depends(fw_dep)) -> dict:
            for k, v in body.model_dump(exclude_none=True).items():
                object.__setattr__(fw.s, k, v)
            return {k: fw.s.chaos(k) for k in ("CHAOS_LLM_DOWN", "CHAOS_C1_DOWN", "CHAOS_C2_DOWN", "CHAOS_LATENCY_MS")}

    return app


app = create_app()
