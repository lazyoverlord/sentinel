"""Streamlit UI (SPEC §16): a thin HTTP client of the API. It never loads models.

Run: uv run streamlit run ui/app.py   (API must be running: uv run uvicorn api.server:app)
"""
from __future__ import annotations

import base64
import difflib
import html
import json
import os
import sys
from pathlib import Path

import httpx
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from firewall.config import get_settings  # noqa: E402  (settings only: API URL, name, admin token)

S = get_settings()
API = os.environ.get("API_URL", S.API_URL)
ADMIN = {"X-Admin-Token": S.admin_token} if S.admin_token else {}
ACTION_COLOR = {"allow": "#1b7f3b", "allow_with_warning": "#b7791f", "allow_sanitized": "#2b6cb0",
                "allow_rewritten": "#2b6cb0", "hold_for_review": "#b7791f", "quarantine": "#c05621", "block": "#c53030"}

st.set_page_config(page_title=f"{S.APP_NAME} firewall", layout="wide")


def api(method: str, path: str, **kw):
    try:
        r = httpx.request(method, API + path, timeout=120, **kw)
        if r.status_code >= 400:
            st.error(f"{r.status_code}: {r.text[:500]}")
            return None
        return r.json()
    except httpx.HTTPError as e:
        st.error(f"API not reachable at {API} ({e}). Start it with: uv run uvicorn api.server:app")
        return None


health = api("GET", "/health") or {}
st.title(f"{S.APP_NAME} · prompt-injection firewall")
cols = st.columns(4)
cols[0].metric("Classifiers", ", ".join(health.get("classifiers", [])) or "none")
cols[1].metric("LLM judge", "configured" if health.get("llm_configured") else "not configured")
cols[2].metric("Patterns", health.get("patterns_version", "?"))
cols[3].metric("Mode", "DEV" if health.get("dev_mode") else "prod")
if health.get("degraded"):
    st.warning("Degraded: " + "; ".join(health["degraded"]))
if any(v for v in health.get("chaos", {}).values()):
    st.error("CHAOS active: " + json.dumps({k: v for k, v in health["chaos"].items() if v}))

from demo_agent.scenarios import SCENARIOS  # noqa: E402


def banner(r: dict) -> None:
    color = ACTION_COLOR.get(r["action"], "#444")
    types = ", ".join(f"{t['id']} {t['name']}" for t in r["attack_types"]) or "none"
    st.markdown(f"<div style='padding:12px 16px;border-radius:8px;background:{color};color:white'>"
                f"<b>{r['action'].upper()}</b> · verdict {r['verdict']} · rule {r['path'].get('rule')} · "
                f"{r['latency_ms'].get('total')} ms · types: {html.escape(types)}</div>", unsafe_allow_html=True)


def show_trace(r: dict, original: str | None) -> None:
    tr = r.get("trace", {})
    st.subheader("Reasoning")
    for step in r["reasoning_chain"]:
        st.markdown(f"- {html.escape(step)}")
    if r.get("retroactive_warnings"):
        st.error("Retroactive: " + " ".join(r["retroactive_warnings"]))
    if r.get("sensitive_data_present"):
        st.info("Sensitive data present (DLP, not an attack signal): " + ", ".join(r["sensitive_data_present"]))
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Scores**")
        st.json(tr.get("scores", {}))
        st.markdown("**Flags / scripts**")
        st.write(tr.get("flags", []), tr.get("scripts", []))
    with c2:
        st.markdown("**Rule matches**")
        st.dataframe(tr.get("matches", []), use_container_width=True)
        if tr.get("decoded"):
            st.markdown("**Decoded hidden payloads**")
            st.dataframe(tr["decoded"], use_container_width=True)
    if r.get("quarantined"):
        st.markdown("**Quarantined (hidden / non-visible content the firewall found)**")
        for q in r["quarantined"]:
            st.code(f"{q['segment_id']} · {q['channel']} · {q.get('hidden_reason')} · {q['location']}\n{q['text']}")
    if tr.get("segments"):
        with st.expander("Segments"):
            st.dataframe(tr["segments"], use_container_width=True)
    if original is not None and r.get("clean_content") is not None and r["clean_content"] != original:
        st.markdown("**Original vs released**")
        diff = difflib.unified_diff(original.splitlines(), r["clean_content"].splitlines(), "original", "released",
                                    lineterm="")
        st.code("\n".join(diff) or "(no line-level change)", language="diff")
    if r.get("clean_content") is not None:
        with st.expander("Released content" + (" (provenance-wrapped for the agent)" if r.get("wrapped_content") else "")):
            st.code(r.get("wrapped_content") or r["clean_content"])
    fb = st.columns(3)
    if fb[0].button("Report false positive", key="fp" + r["audit_id"]):
        api("POST", f"/v1/feedback/{r['audit_id']}", json={"kind": "false_positive"}, headers=ADMIN)
    if fb[1].button("Report missed attack", key="ma" + r["audit_id"]):
        api("POST", f"/v1/feedback/{r['audit_id']}", json={"kind": "missed_attack"}, headers=ADMIN)
    fb[2].caption(f"audit {r['audit_id']}")


tab1, tab2, tab3, tab4 = st.tabs(["Analyze", "Agent demo", "Review & learning", "Evidence"])

with tab1:
    left, right = st.columns([2, 1])
    with right:
        st.markdown("**Scenarios**")
        for name, (txt, src) in SCENARIOS.items():
            if st.button(name, use_container_width=True):
                st.session_state["text"], st.session_state["source"] = txt, src
        convo = st.toggle("Conversation mode (session)", value=False)
        sid = st.text_input("Session id", value="demo-session") if convo else None
    with left:
        text = st.text_area("Input", key="text", height=160)
        source = st.selectbox("Source", ["user", "retrieved", "uploaded"], key="source")
        up = st.file_uploader("…or upload a file (PDF, DOCX, HTML, EML, JSON, XML, MD, code, image)")
        _IMAGE_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp", "image/bmp"}
        if up is not None and up.type in _IMAGE_TYPES:
            st.caption("Experimental: image carrier support is not yet measured on the locked test split.")
        if st.button("Analyze", type="primary"):
            if up is not None:
                body = {"file": {"filename": up.name, "content_type": up.type,
                                 "data_base64": base64.b64encode(up.getvalue()).decode()},
                        "source_type": "uploaded" if source == "user" else source}
                original = None
            else:
                body = {"text": text, "source_type": source}
                original = text
            if sid:
                body["session_id"] = sid
            r = api("POST", "/v1/analyze", json=body)
            if r:
                st.session_state.setdefault("history", []).append(r)
                banner(r)
                if r.get("session"):
                    ss = r["session"]
                    st.caption(f"Session {ss.get('session_id')} · turn {ss.get('turn_id')} · watch mode "
                               f"{'ON' if ss.get('watch_mode') else 'off'}{' (sticky)' if ss.get('sticky') else ''} · "
                               f"this message alone: risk {ss.get('single_message_risk')}")
                show_trace(r, original)

with tab2:
    st.markdown("InboxPilot reads a poisoned email (hidden `display:none` text asks the assistant to forward the "
                "invoice and account configuration to an attacker). `send_email` is a mock: nothing is sent.")
    victim = st.selectbox("Victim model", ["auto", "ollama", "gemini", "scripted"],
                          help="scripted = offline deterministic test double, labelled as such")
    modes = st.multiselect("Modes", ["unprotected", "ingress", "egress", "both"],
                           default=["unprotected", "ingress", "egress", "both"])
    if st.button("Run InboxPilot", type="primary"):
        cols = st.columns(max(1, len(modes)))
        for col, mode in zip(cols, modes):
            out = api("POST", "/v1/demo/inboxpilot", json={"mode": mode, "victim": victim})
            with col:
                st.markdown(f"### {mode}")
                if not out:
                    continue
                st.caption(out["victim_model"])
                if out["exfiltrated"]:
                    st.error("EMAIL SENT to " + ", ".join(m["to"] for m in out["emails_sent"])
                             + (" — secret leaked" if out["secret_leaked"] else ""))
                else:
                    st.success("No exfiltration")
                for ev in out["firewall_events"]:
                    st.write(ev)
                with st.expander("Transcript"):
                    st.json(out["transcript"])
                if out.get("error"):
                    st.warning(out["error"])

with tab3:
    st.subheader("Held for review")
    q = api("GET", "/v1/review/queue") or []
    if not q:
        st.caption("Nothing pending.")
    _REVIEW_PAGE = 20
    if len(q) > _REVIEW_PAGE:
        st.caption(f"Showing {_REVIEW_PAGE} of {len(q)} items.")
    for it in q[:_REVIEW_PAGE]:
        with st.container(border=True):
            st.markdown(f"**{it['audit_id']}** · {it.get('source')} · {it.get('verdict')} · rule {it.get('rule')}")
            st.code(it.get("summary", ""))
            for r_ in it.get("reasons", []):
                st.caption(r_)
            c = st.columns(3)
            if c[0].button("Approve (benign)", key="ap" + it["audit_id"]):
                api("POST", f"/v1/review/{it['audit_id']}", json={"decision": "approve", "label": "benign"}, headers=ADMIN)
                st.rerun()
            if c[1].button("Reject (attack)", key="rj" + it["audit_id"]):
                api("POST", f"/v1/review/{it['audit_id']}", json={"decision": "reject", "label": "attack"}, headers=ADMIN)
                st.rerun()
    st.subheader("Red/blue hardening loop")
    rc1, rc2, rc3 = st.columns(3)
    rounds = rc1.number_input("Rounds", 1, 5, 2)
    per_seed = rc2.number_input("Cases per seed", 2, 12, 6)
    rt_victim = rc3.selectbox("Victim", ["auto", "ollama", "gemini", "scripted"], key="rtv")
    if st.button("Run hardening loop", key="rtrun"):
        with st.spinner("running rounds (uses the local victim; no judge quota unless llm-gen)..."):
            rep = api("POST", "/v1/redteam/run", json={"rounds": int(rounds), "per_seed": int(per_seed),
                                                       "victim": rt_victim}, headers=ADMIN)
        if rep:
            st.session_state["hardening"] = rep
    rep = st.session_state.get("hardening")
    if rep:
        st.caption("Victim: " + rep["victim_model"])
        rates = [r["bypass_rate"] for r in rep["rounds"]]
        st.line_chart({"bypass rate": rates}) if len(rates) > 1 else st.write("bypass rate:", rates)
        for i, r in enumerate(rep["rounds"]):
            st.markdown(f"**Round {i+1}** · {r['cases']} cases · {r['stopped']} stopped · "
                        f"{r['n_bypasses']} bypasses ({r['bypass_rate']:.0%}) · "
                        f"{r['evaded_harmless']} evaded-but-harmless")
            for pat in r.get("proposed_patterns", []):
                with st.container(border=True):
                    st.code(f"{pat['id']} [{pat['category']}] w={pat['weight']}\n{pat['regex']}")
                    st.caption(("VALID · " if pat["valid"] else "REJECTED · ") + "; ".join(pat["validator"]))
                    if pat["valid"] and st.button("Approve → patterns.json", key="ap" + pat["id"]):
                        out = api("POST", "/v1/patterns/approve", json={"pattern": pat}, headers=ADMIN)
                        if out:
                            st.success(f"added; patterns now {out['count']} (v{out['patterns_version']})")

with tab4:
    try:
        from eval.self_assessment import build as build_self_assessment
        res = Path(__file__).resolve().parent.parent / "eval" / "results"
        sa = build_self_assessment(res)
        st.markdown(sa["markdown"])

        m = api("GET", "/v1/metrics") or {}
        with st.expander("Live metrics"):
            st.json(m)
        for f in sorted(res.glob("*.json")):
            with st.expander(f"Eval result: {f.name}"):
                data = json.loads(f.read_text())
                if isinstance(data, dict):
                    st.json({k: v for k, v in data.items() if k != "rows"})
                else:
                    st.json(data)
        if health.get("dev_mode"):
            st.subheader("Chaos (DEV_MODE only)")
            c = st.columns(3)
            if c[0].button("LLM down"):
                api("POST", "/v1/chaos", json={"CHAOS_LLM_DOWN": True}, headers=ADMIN)
                st.rerun()
            if c[1].button("C1 down"):
                api("POST", "/v1/chaos", json={"CHAOS_C1_DOWN": True}, headers=ADMIN)
                st.rerun()
            if c[2].button("Reset chaos"):
                api("POST", "/v1/chaos", json={"CHAOS_LLM_DOWN": False, "CHAOS_C1_DOWN": False, "CHAOS_C2_DOWN": False,
                                               "CHAOS_LATENCY_MS": 0}, headers=ADMIN)
                st.rerun()
    except Exception as e:
        st.exception(e)

if health.get("built_with_llama"):
    st.caption("Built with Llama")
