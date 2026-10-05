"""Self-assessment block (SPEC §1, Evidence tab, DEMO Act 3).

Pure function: reads eval/results/ files and returns structured data + markdown.
No model loading, no API calls, no Streamlit dependency.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, OSError):
        return None


def _fmt_rate(r: dict) -> str:
    if not r.get("n"):
        return "n/a"
    ci = r.get("ci95")
    base = f"{r['k']}/{r['n']} = {r['rate']:.0%}"
    if ci:
        return f"{base} (95% CI {ci[0]:.0%}–{ci[1]:.0%})"
    return base


def build(results_dir: Path) -> dict[str, Any]:
    """Return structured self-assessment data from eval/results/ files.

    Keys: claim, f_claim, evidence, why_not_d3, experimental, limitations, markdown.
    Every field is a string or list of strings; nothing is None (missing data → "not generated").
    """
    claim_path = results_dir / "claim.md"
    metrics = _load_json(results_dir / "metrics.json")
    full_test = _load_json(results_dir / "full_test.json")
    reliability = _load_json(results_dir / "reliability.json")

    # --- D-claim from claim.md ---
    d_claim = "not generated"
    claim_notes: list[str] = []
    if claim_path.exists():
        lines = claim_path.read_text().strip().splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped and stripped[0] != "#" and not stripped.startswith("-"):
                d_claim = stripped
            if stripped.startswith("- "):
                claim_notes.append(stripped[2:])

    f_claim = "F3"
    full_claim = f"{f_claim} · {d_claim}"

    # --- Evidence from full_test.json ---
    summary = full_test.get("summary", {}) if full_test else {}

    recall = summary.get("recall", {})
    benign_fpr = summary.get("benign_fpr", {})
    per_type = summary.get("per_type", {})
    p50 = summary.get("p50_ms")
    llm_calls = summary.get("llm_calls_per_1k")
    misses = summary.get("misses", [])

    # F evidence: attack types with at least one detection
    types_detected = sum(1 for r in per_type.values() if r.get("k", 0) >= 1) if per_type else 0
    types_detected_str = f"{types_detected}/9"

    recall_str = _fmt_rate(recall) if recall else "not generated"
    fpr_str = _fmt_rate(benign_fpr) if benign_fpr else "not generated"
    p50_str = f"{p50} ms" if p50 is not None else "not generated"
    llm_str = str(llm_calls) if llm_calls is not None else "not generated"

    # Per-type table
    type_rows: list[dict[str, str]] = []
    for tid, r in sorted(per_type.items(), key=lambda x: int(x[0]) if x[0].isdigit() else x[0]):
        flags = []
        if r.get("rate") is not None and r["rate"] < 0.80:
            flags.append("below 80%")
        if r.get("n") is not None and r["n"] < 10:
            flags.append("low n")
        type_rows.append({"type": tid, "recall": _fmt_rate(r), "flags": ", ".join(flags)})

    # Reliability
    if reliability:
        n_scored = reliability.get("n_scored", 0)
        n_requested = reliability.get("n_requested", 0)
        runs = reliability.get("runs", 0)
        schema_rate = reliability.get("schema_valid_rate")
        agree = reliability.get("agreement", {})
        rescan_n = reliability.get("rescan_n", 0)
        rescan_rate = reliability.get("rescan_pass_rate")

        schema_str = f"{schema_rate:.0%}" if schema_rate is not None else "not generated"
        agree_str = f"{agree.get('k', 0)}/{agree.get('n', 0)} = {agree.get('rate', 0):.0%}" if agree.get("n") else "not generated"
        if rescan_n == 0:
            rescan_str = "not exercised (n=0)"
        elif rescan_rate is not None:
            rescan_str = f"{rescan_rate:.0%} (n={rescan_n})"
        else:
            rescan_str = "not generated"

        reliability_str = (f"{n_scored}/{n_requested} items × {runs} runs: "
                           f"schema-valid {schema_str}, agreement {agree_str}, re-scan {rescan_str}")
    else:
        reliability_str = "not generated"

    f_evidence = {
        "types_detected": types_detected_str,
        "observability": "firewall/observability/ (audit log, metrics), GET /v1/metrics, Evidence tab",
        "trainability": "firewall/learning/ (feedback, exemplars, review queue), POST /v1/feedback/{audit_id}, Review tab, redteam/ hardening loop",
        "fault_tolerance": "firewall/resilience/ (circuit breaker, budget, rate limiter, cache), LLM fallback chain in firewall/llm.py, chaos toggles",
    }

    evidence = {
        "recall": recall_str,
        "benign_fpr": fpr_str,
        "benign_n": benign_fpr.get("n") if benign_fpr else None,
        "per_type": type_rows,
        "p50_ms": p50_str,
        "llm_calls_per_1k": llm_str,
        "reliability": reliability_str,
        "f_evidence": f_evidence,
    }

    # --- Why not D3 ---
    why_not_d3 = [n for n in claim_notes if "BELOW" in n or "not measured" in n or "insufficient sample" in n]

    # --- Experimental ---
    experimental = ("Image carriers (PNG, OCR path) are experimental and were not measured "
                    "on the locked test split.")

    # --- Limitations ---
    weak_types = [r for r in type_rows if "below 80%" in r.get("flags", "")]
    limitations: list[str] = []
    if weak_types:
        limitations.append("Weakest attack types by test recall: " +
                           ", ".join(f"type {r['type']} ({r['recall']})" for r in weak_types))
    if misses:
        limitations.append("Miss IDs: " + ", ".join(misses))

    # --- Markdown ---
    md_lines = [
        f"## Self-assessment: {full_claim}",
        "",
        "### F evidence (features)",
        "",
        f"- **Attack types with at least one detection on the locked test split:** {types_detected_str}",
        f"- **Observability:** {f_evidence['observability']}",
        f"- **Trainability:** {f_evidence['trainability']}",
        f"- **Fault tolerance:** {f_evidence['fault_tolerance']}",
        "",
        "### D evidence (accuracy)",
        "",
        f"- **Overall recall:** {recall_str}",
        f"- **Benign FPR:** {fpr_str} (n={benign_fpr.get('n', '?')})" if benign_fpr else "- **Benign FPR:** not generated",
        f"- **P50 latency:** {p50_str}",
        f"- **LLM calls / 1k:** {llm_str}",
        f"- **Reliability:** {reliability_str}",
        "",
        "### Per-type recall",
        "",
        "| Type | Recall | Flags |",
        "|------|--------|-------|",
    ]
    for r in type_rows:
        md_lines.append(f"| {r['type']} | {r['recall']} | {r['flags']} |")

    if why_not_d3:
        md_lines += ["", "### Why not D3", ""]
        for note in why_not_d3:
            md_lines.append(f"- {note}")

    md_lines += [
        "",
        f"### Experimental",
        "",
        f"> {experimental}",
    ]

    if limitations:
        md_lines += ["", "### Known limitations", ""]
        for lim in limitations:
            md_lines.append(f"- {lim}")

    return {
        "claim": full_claim,
        "d_claim": d_claim,
        "f_claim": f_claim,
        "evidence": evidence,
        "why_not_d3": why_not_d3,
        "experimental": experimental,
        "limitations": limitations,
        "markdown": "\n".join(md_lines),
    }
