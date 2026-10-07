"""Ensure .env.example stays in sync with the tuned configuration."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ENV_EXAMPLE = ROOT / ".env.example"


def _parse_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" not in line or not line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def test_env_example_exists():
    assert ENV_EXAMPLE.exists(), ".env.example is missing"


def test_c_review_is_calibrated():
    env = _parse_env(ENV_EXAMPLE)
    assert "C_REVIEW" in env, "C_REVIEW missing from .env.example"
    assert float(env["C_REVIEW"]) == 0.20, f"C_REVIEW should be 0.20, got {env['C_REVIEW']}"


def test_h_review_is_calibrated():
    env = _parse_env(ENV_EXAMPLE)
    assert "H_REVIEW" in env, "H_REVIEW missing from .env.example"
    assert float(env["H_REVIEW"]) == 0.20, f"H_REVIEW should be 0.20, got {env['H_REVIEW']}"


def test_judge_model_is_flash_lite():
    env = _parse_env(ENV_EXAMPLE)
    assert "JUDGE_MODEL" in env, "JUDGE_MODEL missing from .env.example"
    assert env["JUDGE_MODEL"] == "gemini-3.5-flash-lite", (
        f"JUDGE_MODEL should be gemini-3.5-flash-lite, got {env['JUDGE_MODEL']}")
