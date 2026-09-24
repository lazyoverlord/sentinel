# SETUP.md — your tasks (Claude Code can't do these)

Slice 0 takes about 60–90 minutes. **No billing anywhere:** everything here is free.

## 1. Machine: 16 GB M1 (confirmed)
16 GB fits everything at once: C1 + Prompt Guard 2 86M (~2.7 GB), a small local model for the red team and victim (~3–4 GB), plus macOS, a browser and Claude Code. No VM needed. Use your personal Mac, not a corporate laptop.

## 2. Install tools (10 min)
```bash
# Homebrew, only if `brew --version` fails:
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

brew install uv tesseract gh
uv python install 3.12
uv --version && tesseract --version && gh --version
claude --version        # Claude Code — update it if it's old
```

## 3. Repo (5 min)
```bash
gh auth login
gh repo create sentinel --private --clone     # or your chosen product name
cd sentinel
# copy everything from this handoff pack into the repo root (CLAUDE.md, SETUP.md, docs/, .env.example)
git add . && git commit -m "docs: spec, build plan, reference gate" && git push -u origin main
```

## 4. Gemini key: ONE new project, free tier (10 min)
- Rate limits are **per project and per model**. Your news-intelligence pipeline already uses your existing project twice a day. Put this app in **its own project** so the two never compete. One project per app is normal practice.
- **Don't create several projects for this same app to multiply free quota.** Google's API terms (§2.d) say you "will not attempt to circumvent" usage limits. The risk is suspension of the Google account you use for Gmail and Drive. Not worth it.
- **What's legitimate and built in:** using different models for different jobs. Each model has its own limits. The judge uses `gemini-3.8-flash`; the alignment check uses `gemini-3.7-flash`; the blue team uses `gemini-3.5-flash`; OCR fallback uses `gemini-3.5-flash-lite`; the red team and test victim run on a local model (step 6b), with Flash-Lite as backup.

Steps:
1. aistudio.google.com → create a **new project** (e.g. `prompt-firewall`) → create an API key in it. Don't enable billing.
2. Open aistudio.google.com/rate-limit and note the free RPM/RPD for the five models above. Google's docs no longer publish these; only your dashboard shows them. Put ~80% of each into `RPM_LIMITS` / `DAILY_BUDGETS` in `.env`.

**Budget reality:** the whole build needs ≈ 2,000 LLM calls spread across those models over several weeks. RPM, not RPD, is the constraint: an evaluation run takes 15–30 minutes. Eval and red-team runs checkpoint to disk, pause when a quota runs out, and resume after the daily reset. Unit tests never call Gemini.

**Two facts to keep straight:**
- The free tier runs the **same models** as paid. Billing buys throughput and data privacy, not a smarter model. So the pitch line is "production runs on a paid or self-hosted endpoint for throughput and privacy; the judge is model-agnostic", not "a better model would score higher".
- The free tier may use what you send to improve Google's products. So **only synthetic and public data** goes in (that's all this project uses). Never paste anything real or confidential.

## 5. .env (3 min)
```bash
cp .env.example .env     # fill GOOGLE_API_KEY; fill the per-model limits from your dashboard
openssl rand -hex 24     # paste the output as ADMIN_TOKEN (protects review/feedback/red-team endpoints)
```

## 6. Llama Prompt Guard 2 86M (do it today, 5 min)
It adds jailbreak detection and Hindi, which the main classifier lacks. On 16 GB, use the 86M version. It's optional: the build starts with C1 only and adds it whenever access arrives.
1. huggingface.co → sign up (free) → verify your email.
2. Open huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M → "Expand to review and access".
3. Fill the form carefully (it can't be edited later): full legal name, date of birth, organization = your full name or "Independent" (no acronyms or special characters). Accept the license.
4. Check status at huggingface.co/settings/gated-repos. Approval can take anywhere from minutes to days, and it isn't guaranteed.
5. Once approved: Settings → Access Tokens → "Create new token" → type **Read** → copy it into `.env` as `HF_TOKEN`.
6. In `.env`: `CLASSIFIERS=c1,c2_86m`. Tell Claude Code in the next slice; it pins the model revision and re-runs the tests. Hindi then takes the fast lane automatically.

## 6b. Local model for the red team and test victim (15 min)
Why: the red team and the "victim" agent don't need Gemini's quality. A local model is free, unlimited and works offline, so red-team rounds can be 3× larger. It's also more gullible than Gemini, which makes the "unprotected agent gets hijacked" demo reliable. Gemini stays for the judge and the alignment check.
```bash
brew install ollama
ollama serve                    # or open the Ollama app; leave it running
ollama pull gemma4:e2b          # small model (~2 GB); if the name differs, check ollama.com/library
ollama run gemma4:e2b "Reply with one word: ready"   # smoke test, then Ctrl+D
ollama list                     # confirm the exact model name
```
If you pulled a different model name, set it in `.env` (`REDTEAM_MODEL` / `VICTIM_MODEL=ollama_chat/<name>`). Claude Code wires it through ADK (the `google-adk[extensions]` package) with an automatic fallback to Gemini Flash-Lite if Ollama isn't running.

## 7. Decide the product name (optional, 5 min)
"Sentinel" collides with **Microsoft Sentinel** (Microsoft's flagship SIEM, which Accenture's security practice works with daily) and with **Qualifire's "Sentinel"**, a 2025 prompt-injection model. The code doesn't care: the name is one config value (`APP_NAME`) plus the repo name. If you rename, do it before Slice 1. Example with an India angle: *Dwarpal* (Sanskrit: gatekeeper).

## 8. Start building
```bash
cd sentinel && claude
```
Switch to plan mode, paste the Slice 1 prompt from `docs/BUILD_PLAN.md`, review the plan, approve.

---

## Your checks per slice
Each slice in BUILD_PLAN.md ends with a "You check" line. Minimum every time: run the acceptance commands yourself, skim the diff summary, confirm the tag exists (`git tag`).

## Demo-day checklist
- The daily quota resets at **midnight Pacific = 12:30 PM IST** until 1 Nov 2026 (1:30 PM IST after that). Don't run evaluations on recording day.
- Pre-warm the demo cache (Slice 7 command). Every demo input then replays real, previously recorded judge responses, so the recording spends no quota and survives a network drop. It's a documented feature; say so if asked.
- Start the API 2 minutes early so models are loaded and warm.
- Quit heavy apps (RAM). Wi-Fi stable, notifications off. `DEV_MODE=false` unless you're showing the chaos demo.
- Keep a backup recording of the InboxPilot unprotected run.
- If the network dies mid-demo: the fast path runs fully on-device, and LLM steps switch to degraded mode. Say so; that's the fault-tolerance feature working.
