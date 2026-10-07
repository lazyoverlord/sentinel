"""All runtime knobs (SPEC §18). Values come from .env / environment; defaults are safe.

Usage: `from firewall.config import get_settings; s = get_settings()`.
Tests build their own: `Settings(_env_file=None, DEV_MODE=True, ...)`.
"""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


def _split_list(v: Any) -> Any:
    """'a,b , c' -> ['a','b','c']; lists pass through; '' -> []."""
    if isinstance(v, str):
        v = v.strip()
        if v.startswith("["):
            return json.loads(v)
        return [x.strip() for x in v.split(",") if x.strip()]
    return v


def _split_map(v: Any, cast=int) -> Any:
    """'m1=8,m2=12' -> {'m1': 8, 'm2': 12}; dicts pass through."""
    if isinstance(v, str):
        v = v.strip()
        if not v:
            return {}
        if v.startswith("{"):
            return json.loads(v)
        out = {}
        for part in v.split(","):
            if "=" in part:
                k, val = part.split("=", 1)
                out[k.strip()] = cast(val.strip())
        return out
    return v


StrList = Annotated[list[str], NoDecode]
IntMap = Annotated[dict[str, int], NoDecode]
StrMap = Annotated[dict[str, str], NoDecode]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(ROOT / ".env"), env_file_encoding="utf-8",
                                      extra="ignore", case_sensitive=True)

    # ---- identity / secrets ----
    APP_NAME: str = "Sentinel"
    GOOGLE_API_KEY: SecretStr | None = None
    HF_TOKEN: SecretStr | None = None
    ADMIN_TOKEN: SecretStr | None = None
    BIND_HOST: str = "127.0.0.1"
    API_PORT: int = 8000
    API_URL: str = "http://127.0.0.1:8000"          # the UI's view of the API
    DEV_MODE: bool = False                          # chaos endpoints + dev conveniences only when true
    DATA_DIR: Path = ROOT / "data"
    PATTERNS_PATH: Path | None = None                # default <repo>/data/patterns.json (versioned in git)

    # ---- models by role (SPEC §9); one project, free tier ----
    JUDGE_MODEL: str = "gemini-3.8-flash"
    JUDGE_FALLBACK_MODELS: StrList = ["gemini-3.6-flash", "gemini-3.5-flash-lite"]
    ALIGNMENT_MODEL: str = "gemini-3.7-flash"
    ALIGNMENT_FALLBACK_MODELS: StrList = ["gemini-3.5-flash"]
    BLUETEAM_MODEL: str = "gemini-3.5-flash"
    REDTEAM_MODEL: str = "ollama_chat/gemma4:e2b"
    REDTEAM_FALLBACK_MODEL: str = "gemini-3.5-flash-lite"
    VICTIM_MODEL: str = "ollama_chat/gemma4:e2b"
    VICTIM_FALLBACK_MODEL: str = "gemini-3.5-flash-lite"
    OLLAMA_API_BASE: str = "http://127.0.0.1:11434"
    OCR_FALLBACK_MODEL: str = "gemini-3.5-flash-lite"
    LLM_TIMEOUT_S: float = 20.0
    LLM_THINKING_LEVEL: str = "low"                 # '' = don't send thinking_config
    JUDGE_MAX_OUTPUT_TOKENS: int = 2048             # room for thinking + ~600-token JSON verdict
    RPM_LIMITS: IntMap = {}                         # model -> requests/min (set ~80% of dashboard)
    DAILY_BUDGETS: IntMap = {}                      # model -> requests/day (set ~80% of dashboard)
    DEFAULT_RPM: int = 8
    DEFAULT_DAILY_BUDGET: int = 200
    PIN_EVAL_MODEL: bool = False                    # eval runs: pause at quota instead of falling back

    # ---- classifiers (SPEC §7.1) ----
    CLASSIFIERS: StrList = ["c1"]                   # c1, c2_86m, c2_22m, c2_alt
    CLASSIFIER_DEVICE: Literal["auto", "cpu", "mps", "cuda"] = "auto"
    MODEL_REVISIONS: StrMap = {}                    # repo -> commit sha (overrides firewall/model_pins.json)
    ALLOW_UNPINNED_MODELS: bool = False
    TORCH_THREADS: int = 4
    COVERED_SCRIPTS: str = "auto"                   # 'auto' or comma list, e.g. 'Latin,Devanagari'

    # ---- gate thresholds (SPEC §7.5, §8) ----
    C_BLOCK: float = 0.90
    H_BLOCK: float = 0.70
    C_REVIEW: float = 0.30
    H_REVIEW: float = 0.30
    CONFIDENCE_MIN: float = 0.60
    RESIDUAL_MIN_FRACTION: float = 0.30
    RESCAN_C_MAX: float = 0.50                      # re-scan "clean" = no R1-R4 AND C < this AND H < RESCAN_H_MAX
    RESCAN_H_MAX: float = 0.40
    FLAG_INVISIBLE_C: float = 0.50
    FLAG_INVISIBLE_H: float = 0.30
    FLAG_ENC_STRONG_C: float = 0.90
    FLAG_ENC_STRONG_H: float = 0.70
    FLAG_ENC_WEAK_C: float = 0.70
    FLAG_ENC_WEAK_H: float = 0.40
    FLAG_HIDDEN_C: float = 0.50
    FLAG_HIDDEN_H: float = 0.40
    FLAG_DISAGREE_DELTA: float = 0.50
    SCRIPT_MIN_LETTERS: int = 20
    UNTRUSTED_ALWAYS_REVIEW: bool = True
    AUDIT_SAMPLE_RATE: float = 0.03
    REWRITE_ENABLED: bool = False

    # ---- session watch mode (SPEC §11) ----
    WATCH_WINDOW: int = 10
    WATCH_OFF_AFTER: int = 5
    WATCH_OFF_AFTER_STICKY: int = 10
    STICKY_TRIGGERS: int = 2
    WATCH_RISK_SUM: float = 1.2
    CLEAN_RISK_MAX: float = 0.15
    SESSION_MAX: int = 1000                         # LRU capacity

    # ---- judge / spotlighting (SPEC §9) ----
    JUDGE_MAX_INPUT_TOKENS: int = 12000
    DATAMARKING: bool = True
    GROUNDING_MIN_SCORE: int = 90

    # ---- resilience (SPEC §12) ----
    BREAKER_FAILURES: int = 5
    BREAKER_RESET_S: float = 60.0
    DEV_CACHE: bool = True
    VERDICT_CACHE: bool = True
    VERDICT_CACHE_TTL_S: int = 86400
    FAIL_MODE_UNTRUSTED: Literal["closed", "open"] = "closed"

    # ---- observability ----
    LOG_RAW_CONTENT: bool = False
    AUDIT_RETENTION_DAYS: int = 30
    REVIEW_QUEUE_DIR: Path | None = None

    # ---- egress (SPEC §15.2) ----
    SENSITIVE_TOOLS: StrList = ["send_email", "transfer_funds", "delete_file", "execute_code"]
    EGRESS_ALLOWLIST: StrList = ["yourcompany.example"]

    # ---- limits (SPEC §6, §7.3) ----
    MAX_FILE_BYTES: int = 10 * 1024 * 1024
    MAX_UNCOMPRESSED_BYTES: int = 50 * 1024 * 1024
    PARSE_TIMEOUT_S: float = 10.0
    MAX_TEXT_CHARS: int = 200_000
    MAX_RECURSION_DEPTH: int = 2
    MAX_VARIANTS_PER_SEGMENT: int = 32
    MAX_VARIANTS_PER_REQUEST: int = 256
    MAX_DECODE_DEPTH: int = 3
    REGEX_TIMEOUT_S: float = 0.05
    OCR_LANGS: str = "eng"                          # tesseract language packs, e.g. 'eng+hin'

    # ---- chaos (DEV_MODE only, SPEC §12) ----
    CHAOS_LLM_DOWN: bool = False
    CHAOS_C1_DOWN: bool = False
    CHAOS_C2_DOWN: bool = False
    CHAOS_LATENCY_MS: int = 0

    # ---- cost projection only (USD per 1M tokens: "model=in/out,..."); empty = tokens only ----
    PRICE_TABLE: StrMap = {}

    # ---- demo ----
    DEMO_SECRET: SecretStr = SecretStr("INBOXPILOT-DEMO-SECRET-7731")

    @field_validator("JUDGE_FALLBACK_MODELS", "ALIGNMENT_FALLBACK_MODELS", "CLASSIFIERS",
                     "SENSITIVE_TOOLS", "EGRESS_ALLOWLIST", mode="before")
    @classmethod
    def _lists(cls, v: Any) -> Any:
        return _split_list(v)

    @field_validator("RPM_LIMITS", "DAILY_BUDGETS", mode="before")
    @classmethod
    def _int_maps(cls, v: Any) -> Any:
        return _split_map(v, int)

    @field_validator("MODEL_REVISIONS", "PRICE_TABLE", mode="before")
    @classmethod
    def _str_maps(cls, v: Any) -> Any:
        return _split_map(v, str)

    # ---- derived ----
    @property
    def admin_token(self) -> str | None:
        return self.ADMIN_TOKEN.get_secret_value() if self.ADMIN_TOKEN else None

    @property
    def google_api_key(self) -> str | None:
        return self.GOOGLE_API_KEY.get_secret_value() if self.GOOGLE_API_KEY else None

    def rpm_for(self, model: str) -> int:
        return self.RPM_LIMITS.get(model, self.DEFAULT_RPM)

    def daily_budget_for(self, model: str) -> int:
        return self.DAILY_BUDGETS.get(model, self.DEFAULT_DAILY_BUDGET)

    def chaos(self, name: str) -> bool | int:
        """Chaos toggles only exist in DEV_MODE."""
        if not self.DEV_MODE:
            return 0 if name == "CHAOS_LATENCY_MS" else False
        return getattr(self, name)

    @property
    def policy_version(self) -> str:
        """Hash of everything that changes a verdict; part of the verdict-cache key and the audit."""
        keys = [k for k in type(self).model_fields if k.startswith(("C_", "H_", "FLAG_", "RESCAN_"))]
        keys += ["CONFIDENCE_MIN", "RESIDUAL_MIN_FRACTION", "UNTRUSTED_ALWAYS_REVIEW", "REWRITE_ENABLED",
                 "FAIL_MODE_UNTRUSTED", "CLASSIFIERS", "COVERED_SCRIPTS", "JUDGE_MODEL"]
        blob = json.dumps({k: getattr(self, k) for k in sorted(keys)}, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()[:12]

    @property
    def audit_dir(self) -> Path:
        return self.DATA_DIR / "audit"

    @property
    def feedback_dir(self) -> Path:
        return self.DATA_DIR / "feedback"

    @property
    def review_queue_dir(self) -> Path:
        return self.REVIEW_QUEUE_DIR if self.REVIEW_QUEUE_DIR is not None else self.feedback_dir

    @property
    def cache_dir(self) -> Path:
        return self.DATA_DIR / "cache"

    @property
    def patterns_path(self) -> Path:
        return self.PATTERNS_PATH or (ROOT / "data" / "patterns.json")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()


__all__ = ["Settings", "get_settings", "reset_settings_cache", "ROOT"]
