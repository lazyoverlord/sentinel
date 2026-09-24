# HANDOFF — what exists, what was verified, what you do next

Built 2026-09-24 in a cloud sandbox. It had PyPI and tesseract, but **no access to HuggingFace, the Gemini API or Ollama**, and no torch. Everything that doesn't need those was built and tested there. Model loading and live LLM calls are what you check on your Mac.

**Test status in the sandbox:** `513 passed` (`uv run pytest -q`). LLM calls are mocked, C1/C2 are simulated by a keyword stand-in, and nothing is downloaded.

**Prompt Guard 2 86M is approved on the owner's HF account**, so `.env.example` defaults to `CLASSIFIERS=c1,c2_86m`. Set `HF_TOKEN` and it loads.

---

## 1. Status by slice

| Slice | State | Notes |
|---|---|---|
| 1 Walking skeleton | **Built, offline-verified** | config, schemas, taxonomy, gate (30/30 reference tests), 66 patterns, obfuscation (all §7.3 variants), scripts, ensemble + flags, llm.py (retries, fallback, breaker, RPM + daily budgets, dev cache), spotlight/grounding/redact, judge + prompt, neutralizer + verify, pipeline, CLI, API, Analyze tab, audit |
| 2 Documents | **Built, offline-verified** | All 11 sources, Must + nearly all Should-tier hidden-content rules, limits, carrier generator (14 carriers). OCR tested for real with tesseract |
| 3 Agents | **Built, offline-verified** | Sessions (sticky watch), ADK SentinelPlugin (ingress + egress), egress guard + alignment judge, output sanitizer, InboxPilot 4 modes, Agent demo tab. Full ADK run works offline with a scripted victim |
| 4 Hardening | **Built, offline-verified** | Classifier bank with C2, `disagree`, R8a, uncovered scripts, breaker/degraded/budgets, checkpointed runner, verdict cache, chaos, admin auth, review queue + UI, feedback, TF-IDF exemplars, provenance wrapping, metrics, `firewall.cli prewarm` demo-cache warm. **Left for the Mac:** the §7.1 memory/latency rule (needs a real RSS measurement) |
| 5 Proof | **Built, offline-verified (code + dev numbers)** | `eval/splits.py` (locked test split), `run_eval.py` (Run A + baselines c1/c2/llm/full, `--carriers`, `--perturb`, signal-recall), `datasets.py` (coverage check), `perturb.py`, `calibrate.py`, `report.py` → report.md/metrics.json/claim.md, `download_public.py` (**unverified**, see §6). `data/samples/core.jsonl`: 90 seeds, 40 benign, 20 Indian-language, 12 multi-turn — all coverage targets met. **Left for the Mac:** the LLM baselines and full run (need Gemini), public-set download, Evidence-tab charts |
| 6 Red/blue | **Built, offline-verified** | operators, red_agent (operators + optional Gemini paraphraser), canary_harness, validator, blue_agent (cluster→propose→validate), loop.py, `/v1/redteam/run` + `/v1/patterns/approve`, Review-tab UI with live approve. **Left for the Mac:** real rounds on Ollama (the scripted victim only bites on email-forward payloads, so offline bypass count is 0) |
| 7 Freeze | Not started | tune on dev, one test-split run (`--i-am-freezing`), record the demo (`docs/DEMO.md`) |

## 2. Verified here vs. needs a live check on your Mac

| Verified in the sandbox | Needs your Mac (not possible in the sandbox) |
|---|---|
| All routing rules R1–R8a, policy, watch mode, degraded mode, egress decisions | **C1 loads** (`pin-models`, then `doctor`, then `bench`); real C1 scores on the Slice 1 inputs |
| 66 patterns: positive/negative examples, extra attacks, benign corpus, ReDoS smoke | **R4 on real scores**: the DAN input only fast-blocks when C1 ≥ 0.90 (it goes to R7 review without C1) |
| Every obfuscation round trip incl. Unicode-tag smuggling, zero-width stego, nested base64 | **Real judge calls** on Gemini (`-m live`), model ids from `client.models.list()`, `thinking_level` accepted |
| Parsers on generated PDF/DOCX/HTML/email/JSON/XML/code/PNG; low-contrast OCR | **CPU vs MPS** latency, peak RSS with C1 (+ C2 86M if approved) |
| Pipeline end to end for §22 rows 2–9 with a mocked judge | **InboxPilot with the real victim** (Ollama `gemma4:e2b`, then Gemini). Tune the payload if it exfiltrates < 2/3 |
| ADK plugin: tool result replaced, hijacked `send_email` blocked, sanitizer | Streamlit on your machine (it rendered and ran in the sandbox with Playwright) |
| API: routes, validation, admin token, chaos only in DEV_MODE, file upload | torch wheel install: needs **macOS 14+** (`sw_vers -productVersion`). If older, tell Claude Code and it will pin an older torch |

Deviations from SPEC are logged in `docs/DECISIONS.md` (21 entries dated 2026-09-24). Read them once.

**Dev-split numbers from the sandbox (rules only — no C1/C2/judge, so a floor, not the real score):**
recall 71% caught / 57% flagged by a real detector, **0% benign false positives**, P50 0.5 ms. Across all 14
carriers: 98% caught, 0% benign FP. Expect recall to rise sharply once C1, C2 and the judge are on; that's
exactly what the misses are (multi-step type-7, subtle type-4/5/6, one Telugu). `eval/results/report.md`.

## 3. First run on your Mac (after SETUP.md steps 1–6)

```bash
cd sentinel
git init && git add . && git commit -m "Sentinel: slices 1-3 built offline"
gh repo create sentinel --private --source=. --remote=origin --push

uv sync                                     # installs everything incl. torch (ml group)
cp .env.example .env                        # fill GOOGLE_API_KEY, ADMIN_TOKEN, limits
uv run pytest -q                            # expect ~503 passed, same as the sandbox
uv run python -m firewall.cli pin-models    # records the C1 commit SHA in firewall/model_pins.json
uv run python -m firewall.cli doctor        # every required line should say [ok]
uv run python -m firewall.cli bench         # C1 load time, single/batch latency, CPU vs MPS, peak RSS
uv run python -m eval.run_eval --split dev --run A
./run.sh                                    # API + UI → http://127.0.0.1:8501
uv run pytest -q -m live -s                 # spends ~5 Gemini calls + runs InboxPilot 3x
```
Commit `firewall/model_pins.json` after `pin-models`. Then `git tag slice-1-3-offline`.

## 4. First Claude Code session (paste in plan mode)

```text
Read CLAUDE.md, HANDOFF.md and docs/DECISIONS.md. Slices 1-3 and most of 4 were built offline in a
sandbox without torch, HuggingFace, Gemini or Ollama. Your job this session is LIVE VERIFICATION, not
new features. Plan first.
1. Run the commands in HANDOFF.md §3 and report results. Fix anything that fails on macOS.
2. Run the Slice 1 acceptance inputs through the CLI with real C1 and the real judge; report rule/action
   for each vs BUILD_PLAN. If real C1 scores differ from the tests' keyword stand-in, fix detectors or
   patterns, never the gate rules or the tests.
3. Report load time, fast-path P50 on CPU vs MPS (single + 64 batch), peak RSS; apply SPEC §7.1's memory
   rule if exceeded and log it.
4. Run InboxPilot unprotected 3x on Ollama; if exfiltration < 2/3, tune POISONED_HTML per SPEC §15.3 and
   tell me what changed. Then the 3 protected modes.
5. Add a demo-cache pre-warm command (SPEC §12) and the per-carrier detection report (10 attacks x all
   carriers) from BUILD_PLAN Slice 2.
Commit and tag slice-3.
```
After live verification, the only build work left is Slice 7 (freeze): tune thresholds on dev with
`uv run python -m eval.calibrate`, run the baselines and the full firewall
(`uv run python -m eval.run_eval --split dev --baseline full`), then the single locked test-split run
(`--i-am-freezing`), `uv run python -m eval.report`, and record the demo from `docs/DEMO.md`.

## 5. Map of the code

```
firewall/config.py        every knob (.env)          firewall/gate.py        decision logic (pure)
firewall/schemas.py       data contracts              firewall/pipeline.py    Firewall.analyze(): the whole flow
firewall/parsing/         11 formats + limits         firewall/detection/     obfuscation, heuristics, dlp, scripts, classifiers, ensemble
firewall/agents/          judge (+prompt), neutralizer, alignment judge
firewall/llm.py           every Gemini call: retries, fallback, breaker, budgets, dev cache, FakeLLMClient
firewall/security/        spotlight, grounding, redact, canary
firewall/session/         watch mode                  firewall/learning/      review queue, feedback, exemplars
firewall/integrations/    egress (pure), guard, sanitizer, adk_plugin
api/server.py  ui/app.py  demo_agent/inboxpilot.py  eval/ (splits, run_eval, make_carriers)
tests/unit  tests/integration (pipeline acceptance, API, InboxPilot)  tests/live (opt-in)
```

## 6. Things to know

- **Without C1, nothing fast-blocks on R4.** Attacks still get caught, via R7 review or R1–R3. With no API key the review is degraded, so users see `hold_for_review`. That's the fail-safe design, not a bug.
- **Run A on the smoke set, rules only:** 20/20 attacks caught (routed to block or review), 0/20 benign fast-blocked, 21% of benign user messages reviewed. Expect the review rate to fall and fast blocks to rise once C1 is loaded.
- **`scripted` victim:** a deterministic test double (it follows any "forward … to X" it reads). It proves the plumbing, not LLM gullibility. The UI labels it. For the pitch, use Ollama and one Gemini run.
- **Parser timeouts** use a thread that can't be killed. A hostile PDF could keep a core busy after its result is discarded (logged in DECISIONS).
- **Data safety:** with `LOG_RAW_CONTENT=false` (default) the audit log and the review queue store redacted 200-char excerpts only, and exemplars are built from those. Set it to `true` locally if reviewers need full text. `data/` runtime files are gitignored.
