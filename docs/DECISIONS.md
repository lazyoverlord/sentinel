# Decisions log

Every deviation from docs/SPEC.md, and every judgment call SPEC leaves open. Newest first.

| Date | Decision | Why | SPEC § |
|---|---|---|---|
| 2026-09-24 | CLASSIFIERS default `c1,c2_86m` (Prompt Guard 2 86M) | Owner's HF access approved; adds jailbreak + Hindi coverage, so Devanagari fast-passes instead of always-review | 7.1, 7.4 |
| 2026-09-24 | Red-team generation is deterministic operators by default; the Gemini paraphraser is opt-in (`--llm-gen`) | Rounds cost zero quota; a bypass still requires the canary harness | 14 |
| 2026-09-24 | Red-team cases run through `analyze` (the firewall), not a private path; victim via the InboxPilot model picker (ollama/gemini/scripted) | One code path; offline-testable with the scripted victim | 14 |
| 2026-09-24 | Eval reports both "recall" (fast-block OR review) and "signal recall" (a detector actually flagged it) | Untrusted items are always reviewed (R5), so plain recall is trivially high for them; signal recall is the honest detector number | 17 |
| 2026-09-24 | `/v1/patterns/approve` appends to patterns.json and bumps the patch version after re-validation | Human-in-the-loop patch approval (SPEC §14 step 6) | 14, 15.1 |
| 2026-09-24 | Public-set downloader (`eval/download_public.py`) ships UNVERIFIED (HuggingFace was blocked at build); dataset ids/splits/licenses must be checked on first run | Can't reach the Hub from the sandbox | 17 |
| 2026-09-24 | Depend on `google-adk==2.9.2` + `litellm>=1.84` instead of `google-adk[extensions]` | The extensions extra now pulls kubernetes, langgraph, llama-index, crewai, docker, firestore; LiteLlm (Ollama) needs only litellm | 20 |
| 2026-09-24 | torch/transformers/sentencepiece/protobuf in a default `ml` dependency group; `datasets` in `eval` | Core imports and unit tests run without torch (built in a sandbox without it); `uv sync` still installs everything | 20 |
| 2026-09-24 | Flags manip / rolespoof / exfil / ai_imperative come from UNQUOTED matches only; quoted matches still count toward H | Otherwise a security article quoting an attack is fast-blocked by R3 or held by the floor, contradicting demo row 9 | 7.2, 7.5 |
| 2026-09-24 | Pattern library v1.0.0: 66 patterns, 13 categories; types per category fixed in the build brief | ≥ 60 required by Slice 4, built early | 7.2 |
| 2026-09-24 | rot13 / reversed variants are generated only when the text looks encoded (stopword ratio < 5% before, ≥ 15% after) | Keeps them cheap and precise; the ensemble's "kept only if rules match or C rises ≥ 0.3" still applies | 7.3 |
| 2026-09-24 | Normalization collapses spaced letters from runs of ≥ 3 letters (SPEC says ≥ 4) | "a l l" in "i g n o r e   a l l" otherwise survives and breaks the override pattern | 7.3 |
| 2026-09-24 | OCR: every pass-1 line is contrast-checked and demoted to `ocr_enhanced/low_contrast` if a reader couldn't see it; a third pass-2 variant (anything off-background becomes ink); pass-2 lines need conf ≥ 50 | Tesseract thresholds adaptively and reads #F8F8F8 text in pass 1 on its own; the SPEC recipe fails when faint and dark text share an image | 6 |
| 2026-09-24 | PDF `white_text` only if the rendered page under the span shows no contrast; near-white non-white = `low_contrast`; render mode read from span char_flags (also catches mode 7) | White headings on dark banners stay visible; same MuPDF data as get_texttrace | 6 |
| 2026-09-24 | Email: HTML-part visible text missing from the plain part stays visible | Otherwise an attacker shows a harmless plain part while the HTML carries the attack | 6 |
| 2026-09-24 | Parser timeout uses a worker thread (can't be killed; result discarded); PDF work serialized by a lock (MuPDF not thread-safe) | Process pools add ~100 ms per call on macOS; revisit if hostile PDFs pin a core | 6 |
| 2026-09-24 | Resource-limit violations (file size, zip bomb) ⇒ `quarantine` with rule `LIMIT`, file not parsed | SPEC gives the limit but not the action; quarantine is the conservative choice | 6, 12 |
| 2026-09-24 | Classifiers refuse to load without a pinned revision (`python -m firewall.cli pin-models` writes `firewall/model_pins.json`); `ALLOW_UNPINNED_MODELS` overrides | Rule 7; SHAs couldn't be fetched in the build sandbox (HuggingFace blocked) | 7.1 |
| 2026-09-24 | Judge output schema `JudgeOutput` (evidence without `grounded`); converted to `AnalyzerVerdict` after grounding | The LLM must not be able to assert its own grounding | 5, 9 |
| 2026-09-24 | InboxPilot has a third victim, `scripted` (offline deterministic test double, labelled in the UI) | Lets the ADK plugin, egress guard and all 4 demo modes be tested end to end without network | 15.3 |
| 2026-09-24 | `/v1/redteam/run` and `/v1/patterns/approve` return 501 until Slice 6 | Endpoints exist with admin auth so the contract is stable | 15.1 |
| 2026-09-23 | 16 GB Mac confirmed: target C1 + Prompt Guard 2 86M; red team + test victim on local Ollama model (Gemini fallback); classifier device auto (CPU vs MPS) | Frees Gemini quota for judge/alignment; unlimited red-team rounds; gullible local victim makes the demo reliable | 7.1, 14, 15.3, 20 |
| 2026-09-23 | v4.1: free tier only (no billing); models by role in one project; per-model limits + checkpointed runs; Prompt Guard 2 optional (default CLASSIFIERS=c1, covered scripts auto); eval LLM steps resized (~2,000 calls total) | Owner decision: no billing. Google API terms forbid multi-project quota circumvention | 7.1, 7.4, 9, 12, 14, 17, 18, 19 |
| 2026-09-23 | Architecture v4 adopted: framework-free core (ADK = agent layer), egress guard, red/blue loop, self-protection, dev/test split + baselines, vertical-slice plan | Second critique pass: constraint fit, firewall red-teaming, eval validity, pitch | all |
| 2026-09-23 | Architecture v3 adopted (see SPEC header) | Last-check review: routing, judge hardening, multi-step, D-claim, supporting features | all |
