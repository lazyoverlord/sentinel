# CLAUDE.md — Prompt Injection Firewall (hackathon build)

## What this is
A prompt-injection firewall for AI agents (ET AI Hackathon, Accenture, Problem Statement 2). **Ingress:** it scans user messages, retrieved content, uploads, and tool outputs. **Egress:** it checks agents' sensitive tool calls and replies. It detects 9 attack types, neutralizes them, and hardens itself with a red/blue-team loop. Product name is a display string (`config.APP_NAME`); the package is `firewall/`.

## Sources of truth — read before coding
- `HANDOFF.md`: what already exists, what was verified offline, what still needs a live check. Read it first.
- `docs/SPEC.md`: what to build. Section numbers are referenced in every task. Scope tiers in §23: build Must first.
- `docs/BUILD_PLAN.md`: vertical slices, deliverables, acceptance criteria.
- `docs/reference/gate_reference.py` + tests: exact semantics of routing, policy, watch mode, degraded mode, egress. Port it and keep its tests passing.
- `docs/DECISIONS.md`: log every deviation (date · what · why). Never change a SPEC decision silently. If you think one is wrong, stop and ask.

## Owner context
The owner (Abhishek) is technical (CS + 3 years SWE) but has been away from hands-on coding for ~3 years. Explain non-obvious choices in 1–2 lines. At the end of each task, tell him what changed, how to run/verify it (exact commands), and what to look at.

## Commands
```bash
uv sync                                   # install deps
uv run pytest -q                          # unit + integration (LLM mocked, no downloads)
uv run pytest -q -m live                  # opt-in live tests (spend Gemini quota)
uv run python -m firewall.cli analyze "text" --source user
uv run python -m firewall.cli analyze --file doc.pdf --source uploaded
uv run uvicorn api.server:app --host 127.0.0.1 --port 8000     # API (owns models + state)
uv run streamlit run ui/app.py                                   # UI (thin HTTP client)
./run.sh                                  # both
uv run python -m eval.run_eval --split dev --run A              # deterministic eval, no LLM
uv run python -m firewall.cli doctor                            # environment check (keys, tesseract, torch, pins, Ollama, model ids)
uv run python -m firewall.cli pin-models                        # write HF commit SHAs to firewall/model_pins.json
uv run python -m firewall.cli bench                             # classifier load time, CPU vs MPS, peak RSS
```

## Rules
1. The core pipeline is plain async Python. Decision logic lives in pure functions (`gate.py`, `integrations/egress.py`) with exhaustive tests. ADK is only for the agent layer: plugin, InboxPilot, red/blue agents.
2. All LLM calls go through `firewall/llm.py` (google-genai, retries, budget, caches, fallback). Untrusted text is spotlighted via `security/spotlight.py`. Every call has a response schema; temperature 0 except the red-team generator.
3. Unit tests never call Gemini or download models. Live tests are `@pytest.mark.live`.
4. Never make a failing test pass by weakening the test. Fix the code or ask.
5. **Never read or tune on the test split** before Slice 7. Tune on dev only.
6. No secrets in code, tests, logs, or commits. Admin endpoints require `X-Admin-Token`; the API binds 127.0.0.1; chaos exists only when `DEV_MODE=true`.
7. Pin model revisions (commit SHA); `trust_remote_code=False`.
8. Every pattern in `data/patterns.json` ships with `example_positive` and `example_negative`; a test enforces both. Use the `regex` module with timeouts.
9. Resource limits on every parser/decoder (SPEC §6, §7.3). Inputs are hostile, including to the firewall itself.
10. Small commits after each green step; tag each slice (`git tag slice-N`). Prefer the simplest thing that meets the SPEC; no new dependency without a one-line reason in DECISIONS.md.

## Framework facts (verified 2026-09-23 — still check the installed package)
- **google-genai** (`from google import genai`), never the deprecated `google-generativeai`. Structured output via `GenerateContentConfig(response_mime_type="application/json", response_schema=<Pydantic model>)`. Retries via `HttpOptions(retry_options=HttpRetryOptions(attempts, initial_delay, max_delay, exp_base, jitter, http_status_codes))`.
- **google-adk 2.9.2** (agent layer only). **Read the installed source before writing ADK code**; your training data mostly covers ADK 1.x. Plugins register via `App(plugins=[...])` (`Runner(plugins=...)` is deprecated). `after_tool_callback` returning a dict **replaces** the tool result; `on_user_message_callback` can return replacement content; `before_tool_callback` can short-circuit a tool; `after_model_callback` sees the model response.
- **Free tier only, no billing.** Models by role, each with its own quota in the one project: judge `gemini-3.8-flash` (fallback `3.6-flash` → `3.5-flash-lite`), alignment `gemini-3.7-flash`, blue team `gemini-3.5-flash`, OCR fallback `gemini-3.5-flash-lite`. **Red team and test victim run on a local Ollama model** (`ollama_chat/gemma4:e2b` or whatever `ollama list` shows) through ADK `LiteLlm`, falling back to `gemini-3.5-flash-lite`. Never use the local model for the judge, alignment check or blue team. The 2.5 models are restricted to prior users. Verify IDs at startup (`client.models.list()`).
- **Quota:** per project, per model; RPD resets at midnight Pacific. Respect the per-model `RPM_LIMITS` / `DAILY_BUDGETS`. Use the dev cache. Eval and red-team runs go through the checkpointed batch runner (pause and resume, never redo). Eval runs pin the judge model: pause, don't fall back.
- **Never send real personal or confidential data** to Gemini; the free tier may use content to improve Google's products. Synthetic and public datasets only.
- **Never create extra Google Cloud projects to get more quota.** Google's API terms (§2.d) forbid circumventing limits. One project for this app.
- **Classifiers:** C1 `protectai/deberta-v3-base-prompt-injection-v2` (ungated, English, does not detect jailbreaks). C2 `meta-llama/Llama-Prompt-Guard-2-86M` or `-22M` (gated, optional, `HF_TOKEN`). **Default config is C1 only**; everything must work without C2 (covered scripts adapt automatically, SPEC §7.4). Read label maps from model config.
- **transformers** pinned `<5` (known-good with DeBERTa-v3; needs `sentencepiece`, `protobuf`).

## Gotchas
- The API process owns models, sessions, caches, and demo agents. Streamlit only calls HTTP; never load models there.
- If anything async must run inside Streamlit, use one cached background event loop, never `asyncio.run()` per rerun.
- Load classifiers once at API startup (lifespan), warm up, `torch.set_num_threads(4)`. Dedupe variants by text hash before inference.
- Confusables normalization maps Latin look-alikes only. Blanket transliteration destroys Hindi.
- Scanned PDFs legitimately use invisible text: no visible text + image + invisible text ⇒ `ocr_layer`.
- Google has hardened Gemini against indirect injection, so the unprotected InboxPilot may resist the bait. Tune the payload (SPEC §15.3), not the firewall.
- Mac: `brew install tesseract`; pytesseract needs it on PATH. Ollama must be running (`ollama serve` or the menu-bar app) for local models; fall back to Gemini if the health check fails.
- The owner's Mac has 16 GB RAM: C1 + Prompt Guard 2 86M + a small Ollama model fit together. Benchmark classifier device (CPU vs MPS) in Slice 1 and report.

## Definition of done (every slice)
Tests green · acceptance steps in BUILD_PLAN pass · DECISIONS.md updated if anything deviated · short run/verify note for the owner · committed and tagged.
