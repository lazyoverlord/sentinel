# Sentinel — a prompt-injection firewall for AI agents

Built for the ET AI Hackathon (Accenture), Problem Statement 2. Sentinel sits in front of an AI agent and
scans everything the agent reads (user messages, retrieved web/RAG content, uploaded files, tool outputs)
and guards everything the agent does (sensitive tool calls and its replies). It detects the 9 attack types
in the brief across 11 input sources, neutralizes them, and hardens itself with a red/blue-team loop.

## Why it is built this way
- **Deterministic control plane.** Routing and actions are pure, unit-tested functions (`firewall/gate.py`).
  An LLM never decides whether the LLM is consulted, and never overrules strong deterministic evidence — an
  LLM judge is itself an injection target.
- **Two directions.** Ingress catches attacks going *into* the agent; an egress guard catches a hijacked
  agent trying to act (sending data to an unrequested address, leaking a secret).
- **Fails safe.** Every failure mode is explicit per source; untrusted content is quarantined when the judge
  is unavailable, never fed through silently.
- **Free tier only, no billing.** Gemini models by role in one project; a local Ollama model for the red
  team and demo victim; two small local classifiers. Nothing here costs money to run.

## Architecture (three layers)
1. **Ingress firewall** (framework-free async Python): parse → expand obfuscation → detect (2 classifiers +
   60+ rules) → gate (R1–R8a) → semantic review (spotlighted, schema-locked judge) → grounding + floor →
   policy → neutralize → verify re-scan → report.
2. **Egress guard** (ADK plugin): an alignment check on sensitive tool calls, a sanitizer on replies.
3. **Hardening loop** (red/blue agents + a canary harness): a bypass counts only if it evaded Sentinel *and*
   succeeded on an unprotected victim; validated patches need human approval.

## Quickstart
```bash
uv sync
cp .env.example .env            # add GOOGLE_API_KEY, ADMIN_TOKEN, HF_TOKEN; set per-model limits
uv run python -m firewall.cli pin-models   # pin classifier revisions
uv run python -m firewall.cli doctor       # environment check
uv run pytest -q                # ~525 tests, no network, nothing downloaded
./run.sh                        # API on :8000, Streamlit UI on :8501
```
`HANDOFF.md` is the first thing to read: current build status and what needs a live check on your machine.

## Using it
- **CLI:** `uv run python -m firewall.cli analyze "text" --source user` (or `--file doc.pdf --source uploaded`).
- **REST:** `POST /v1/analyze` (see `api/server.py` for the full surface incl. `/v1/egress/check`).
- **In an agent:** register the ADK plugin — `App(plugins=[SentinelPlugin(firewall)])`.

## Evaluation
`uv run python -m eval.run_eval --split dev` (deterministic, no quota), `--carriers`, `--perturb`,
`--baseline {c1,c2,llm,full}`; then `uv run python -m eval.report` → `eval/results/report.md`, `metrics.json`,
`claim.md`. The test split is locked until freeze (`--i-am-freezing`). Tune on dev only.

## Docs
`docs/SPEC.md` (what to build) · `docs/BUILD_PLAN.md` (slices) · `docs/DECISIONS.md` (every deviation) ·
`docs/DEMO.md` (8-minute script) · `CLAUDE.md` (Claude Code memory).

## Threat model & limits
Adversaries: malicious user, third-party content author, multi-turn social engineer, firewall attacker,
feedback poisoner (`docs/SPEC.md` §2). Out of scope: content-safety moderation, model-weight poisoning,
agents that bypass the firewall entirely. Adaptive attackers degrade any classifier; mitigations are
mandatory review of untrusted content, egress checks and the hardening loop (`docs/SPEC.md` §24).

## Licenses
Classifier C1 `protectai/deberta-v3-base-prompt-injection-v2` — Apache-2.0. C2
`meta-llama/Llama-Prompt-Guard-2-86M` — Llama 4 Community License; the UI shows "Built with Llama" when it is
loaded. Only synthetic and public data is ever sent to Gemini.
