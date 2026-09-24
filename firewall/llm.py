"""LLM access layer (SPEC §9, §12). ALL LLM calls in the project go through `LLMClient`.

Per generate_structured() call:
  1. chaos toggles (DEV_MODE only) and the API-key check -> LLMUnavailable
  2. for each model in the role's chain (primary, then fallbacks; only the primary when pin_model):
       dev cache -> circuit breaker -> daily budget -> RPM limiter
       -> google-genai call (the SDK itself retries 429/5xx with backoff: HttpRetryOptions)
       -> response-schema validation.  Any failure moves on to the next model.
  3. every model failed or was skipped -> LLMUnavailable; the caller applies the degraded policy.

Pinned calls (eval runs) never fall back to another model. When the pinned model is out of quota
they raise QuotaExceeded, so the checkpointed batch runner pauses and resumes after the reset.

Prompts are never logged (they carry untrusted content); only model ids and error summaries are.
`FakeLLMClient` at the bottom has the same public API for tests (no network, no quota).
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import math
import re
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, get_args

from google import genai
from google.genai import errors as genai_errors
from google.genai import types
from pydantic import BaseModel, ValidationError

from firewall.resilience.breaker import CircuitBreaker
from firewall.resilience.budget import DailyBudget, QuotaExceeded, RateLimiter, next_reset_utc
from firewall.resilience.cache import DevCache

log = logging.getLogger(__name__)

Role = Literal["judge", "alignment", "blueteam", "ocr", "redteam", "victim"]
ROLES: tuple[str, ...] = get_args(Role)

RETRY_HTTP_STATUS_CODES = (429, 500, 502, 503, 504)
RPM_WAIT_S = 10.0          # a normal call waits this long for an RPM token, then tries the next model
PINNED_RPM_WAIT_S = 70.0   # a pinned call waits out a full minute (or a 429 cooldown) before pausing
COOLDOWN_429_S = 60.0      # after a 429 that survived the SDK retries: no calls to that model for 60 s
_ERR_MAX = 300
_PER_DAY_RE = re.compile(r"per[\s_-]*day", re.I)
_FENCE_RE = re.compile(r"^\s*```[A-Za-z0-9_-]*[ \t]*\n?(.*?)\n?\s*```\s*$", re.S)


class LLMError(Exception):
    """Base class for errors raised by the LLM layer."""


class LLMUnavailable(LLMError):
    """No usable model: no API key, chaos toggle, or every model in the chain failed / was skipped.
    `attempts` lists what was tried ({model, ok, error, latency_ms})."""

    def __init__(self, message: str, *, attempts: list[dict] | None = None) -> None:
        super().__init__(message)
        self.attempts: list[dict] = list(attempts or [])


@dataclass
class LLMResult:
    parsed: BaseModel
    model: str
    latency_ms: float
    tokens_in: int | None
    tokens_out: int | None
    cache_hit: bool
    fallback_used: bool
    attempts: list[dict] = field(default_factory=list)


# ---------------- helpers (public: used by tests and the live smoke test) ----------------

def build_http_options(settings: Any) -> types.HttpOptions:
    """Client-wide HTTP options (SPEC §9): per-request timeout (ms) + SDK retries with backoff."""
    return types.HttpOptions(
        timeout=int(settings.LLM_TIMEOUT_S * 1000),
        retry_options=types.HttpRetryOptions(
            attempts=3, initial_delay=1.0, exp_base=2, max_delay=8, jitter=0.5,
            http_status_codes=list(RETRY_HTTP_STATUS_CODES)),
    )


def normalize_model_id(model: str) -> str:
    """'models/gemini-3.8-flash' -> 'gemini-3.8-flash' (budgets, limits and breakers use bare ids)."""
    return (model or "").strip().removeprefix("models/")


def is_gemini_model(model: str) -> bool:
    return normalize_model_id(model).lower().startswith("gemini")


def is_local_model(model: str) -> bool:
    """LiteLLM-style ids such as 'ollama_chat/gemma4:e2b' are served by ADK, never through here."""
    m = normalize_model_id(model).lower()
    return "/" in m or ":" in m or m.startswith("ollama")


def parse_response(response: Any, schema: type[BaseModel]) -> BaseModel:
    """Prefer the SDK's `response.parsed`; else validate `response.text` (tolerating ``` fences).
    Raises ValueError / ValidationError when there is no valid object."""
    parsed = getattr(response, "parsed", None)
    if isinstance(parsed, schema):
        return parsed
    if isinstance(parsed, Mapping):
        try:
            return schema.model_validate(dict(parsed))
        except ValidationError:
            pass
    text = getattr(response, "text", None)
    if not isinstance(text, str) or not text.strip():
        raise ValueError(f"empty response{_finish_info(response)}")
    m = _FENCE_RE.match(text)
    return schema.model_validate_json(m.group(1) if m else text)


def usage_tokens(response: Any) -> tuple[int | None, int | None]:
    """(prompt tokens, output tokens incl. thinking tokens) from usage_metadata, None if unknown."""
    um = getattr(response, "usage_metadata", None)
    if um is None:
        return None, None
    tokens_in = _int_or_none(getattr(um, "prompt_token_count", None))
    cand = _int_or_none(getattr(um, "candidates_token_count", None))
    thoughts = _int_or_none(getattr(um, "thoughts_token_count", None))
    tokens_out = None if cand is None and thoughts is None else (cand or 0) + (thoughts or 0)
    return tokens_in, tokens_out


# ---------------- the client ----------------

class LLMClient:
    def __init__(self, settings: Any, *, genai_client: Any = None, clock=time.monotonic,
                 sleep=asyncio.sleep, budget: DailyBudget | None = None,
                 limiter: RateLimiter | None = None, dev_cache: DevCache | None = None) -> None:
        self.settings = settings
        self._genai = genai_client
        self._owns_genai = genai_client is None
        self._clock = clock
        self._sleep = sleep
        self.limiter = limiter or RateLimiter(settings.rpm_for, clock=clock, sleep=sleep)
        self.budget = budget or DailyBudget(settings.daily_budget_for, settings.cache_dir)
        self._dev_cache = dev_cache            # opened lazily: no files unless a cacheable call happens
        self._dev_cache_broken = False
        self._breakers: dict[str, CircuitBreaker] = {}
        self._no_thinking: set[str] = set()    # models that rejected thinking_config
        self._available: dict[str, bool] = {}  # from verify_models()
        self._warned_level: str | None = None
        self._counters = {"calls": 0, "api_calls": 0, "errors": 0, "unavailable": 0, "fallbacks": 0,
                          "cache_hits": 0, "quota_exceeded": 0, "tokens_in": 0, "tokens_out": 0}
        self._per_model: dict[str, dict[str, int]] = {}
        self._recent: deque[dict] = deque(maxlen=50)
        self._last_error: str | None = None

    # ---- model chains ----
    def models_for(self, role: Role) -> list[str]:
        s = self.settings
        if role == "judge":
            chain = [s.JUDGE_MODEL, *s.JUDGE_FALLBACK_MODELS]
        elif role == "alignment":
            chain = [s.ALIGNMENT_MODEL, *s.ALIGNMENT_FALLBACK_MODELS]
        elif role == "blueteam":
            chain = [s.BLUETEAM_MODEL]
        elif role == "ocr":
            chain = [s.OCR_FALLBACK_MODEL]
        elif role == "redteam":   # the local Ollama primary runs via ADK LiteLlm, never here
            chain = [s.REDTEAM_FALLBACK_MODEL] if is_gemini_model(s.REDTEAM_FALLBACK_MODEL) else []
        elif role == "victim":
            chain = [s.VICTIM_FALLBACK_MODEL] if is_gemini_model(s.VICTIM_FALLBACK_MODEL) else []
        else:
            raise ValueError(f"unknown LLM role {role!r}; expected one of {ROLES}")
        out: list[str] = []
        for model in chain:
            model = normalize_model_id(model)
            if not model or model in out:
                continue
            if is_local_model(model):
                log.warning("ignoring local model %r in the %s chain (Gemini API only)", model, role)
                continue
            out.append(model)
        return out

    def all_models(self) -> list[str]:
        out: list[str] = []
        for role in ROLES:
            for model in self.models_for(role):  # type: ignore[arg-type]
                if model not in out:
                    out.append(model)
        return out

    def breaker(self, model: str) -> CircuitBreaker:
        b = self._breakers.get(model)
        if b is None:
            b = self._breakers[model] = CircuitBreaker(self.settings.BREAKER_FAILURES,
                                                       self.settings.BREAKER_RESET_S, clock=self._clock)
        return b

    # ---- main entry point ----
    async def generate_structured(self, *, role: Role, system: str, prompt: str,
                                  schema: type[BaseModel], prompt_version: str,
                                  temperature: float = 0.0, max_output_tokens: int | None = None,
                                  pin_model: bool = False, use_dev_cache: bool = True) -> LLMResult:
        s = self.settings
        started = time.perf_counter()
        self._counters["calls"] += 1
        delay_ms = s.chaos("CHAOS_LATENCY_MS")
        if delay_ms:
            await self._sleep(float(delay_ms) / 1000.0)
        if s.chaos("CHAOS_LLM_DOWN"):
            raise self._unavailable("LLM down (chaos toggle CHAOS_LLM_DOWN)", [])
        if self._genai is None and not s.google_api_key:
            raise self._unavailable("GOOGLE_API_KEY is not set", [])
        chain = self.models_for(role)
        if not chain:
            raise self._unavailable(f"no Gemini model configured for role {role!r}", [])
        if pin_model:
            chain = chain[:1]
        first = chain[0]
        attempts: list[dict] = []
        use_cache = bool(s.DEV_CACHE and use_dev_cache and temperature == 0)

        try:
            for model in chain:
                if use_cache:
                    hit = self._cache_get(model, prompt_version, system, prompt, schema)
                    if hit is not None:
                        parsed, tokens_in, tokens_out = hit
                        self._counters["cache_hits"] += 1
                        self._record(attempts, model, True, None, 0.0)
                        return LLMResult(parsed=parsed, model=model, latency_ms=_ms_since(started),
                                         tokens_in=tokens_in, tokens_out=tokens_out, cache_hit=True,
                                         fallback_used=model != first, attempts=attempts)
                outcome = await self._try_model(model, system=system, prompt=prompt, schema=schema,
                                                temperature=temperature,
                                                max_output_tokens=max_output_tokens,
                                                pin_model=pin_model, attempts=attempts)
                if outcome is None:
                    continue
                parsed, tokens_in, tokens_out = outcome
                fallback = model != first
                if fallback:
                    self._counters["fallbacks"] += 1
                if use_cache:
                    self._cache_set(model, prompt_version, system, prompt, schema, parsed,
                                    tokens_in, tokens_out)
                return LLMResult(parsed=parsed, model=model, latency_ms=_ms_since(started),
                                 tokens_in=tokens_in, tokens_out=tokens_out, cache_hit=False,
                                 fallback_used=fallback, attempts=attempts)
        except QuotaExceeded as e:
            self._counters["quota_exceeded"] += 1
            self._last_error = str(e)
            raise
        summary = "; ".join(f"{a['model']}: {a['error']}" for a in attempts if not a["ok"])
        raise self._unavailable(f"all models failed for role {role!r}: {summary or 'no attempts'}",
                                attempts)

    async def _try_model(self, model: str, *, system: str, prompt: str, schema: type[BaseModel],
                         temperature: float, max_output_tokens: int | None, pin_model: bool,
                         attempts: list[dict]) -> tuple[BaseModel, int | None, int | None] | None:
        """One model: guards, the call (plus one retry without thinking_config), validation.
        Returns (parsed, tokens_in, tokens_out) or None to move on. May raise QuotaExceeded."""
        breaker = self.breaker(model)
        if breaker.state == "open":
            self._record(attempts, model, False, "breaker_open", 0.0)
            return None
        if self.budget.remaining(model) <= 0:
            self._skip_daily(model, pin_model, attempts)
            return None
        if not await self._acquire_rpm(model, pin_model, attempts):
            return None
        if not breaker.allow():                  # half-open, and another trial call is in flight
            self._record(attempts, model, False, "breaker_open", 0.0)
            return None
        claimed = True                           # we hold the breaker slot until an outcome is recorded
        try:
            if not self.budget.consume(model):   # another process spent the last unit meanwhile
                self._skip_daily(model, pin_model, attempts)
                return None
            thinking = self._thinking_level() is not None and model not in self._no_thinking
            retried_without_thinking = False
            while True:
                config = self._config(schema, system, temperature, max_output_tokens, thinking)
                self._count_api_call(model)
                t0 = time.perf_counter()
                error: Exception | None = None
                response: Any = None
                try:
                    response = await asyncio.wait_for(
                        self._client().aio.models.generate_content(model=model, contents=prompt,
                                                                   config=config),
                        timeout=self.settings.LLM_TIMEOUT_S)
                except Exception as e:           # CancelledError (BaseException) still propagates
                    error = e
                latency = _ms_since(t0)

                if error is not None:
                    if isinstance(error, genai_errors.ClientError):
                        message = _error_message(error)
                        if (error.code == 400 and thinking and not retried_without_thinking
                                and "thinking" in message.lower()):
                            # This model doesn't accept thinking_config: remember, retry once without.
                            self._no_thinking.add(model)
                            thinking, retried_without_thinking = False, True
                            self._record(attempts, model, False, f"thinking_unsupported: {message}", latency)
                            log.info("model %s rejected thinking_config; retrying without it", model)
                            if not self.budget.consume(model):    # the retry is a new request
                                self._skip_daily(model, pin_model, attempts)
                                return None
                            if not await self._acquire_rpm(model, pin_model, attempts):
                                return None
                            continue
                        if error.code == 429:
                            kind = _quota_kind(error)
                            self.limiter.cooldown(model, COOLDOWN_429_S)
                            if kind == "daily":
                                self.budget.exhaust(model)
                            claimed = False
                            self._fail(model, breaker, attempts, f"http_429 ({kind} quota): {message}", latency)
                            if pin_model:
                                resume = (next_reset_utc() if kind == "daily"
                                          else _utcnow() + timedelta(seconds=COOLDOWN_429_S))
                                raise QuotaExceeded(model, kind, resume)
                            return None
                        reason = f"http_{error.code}: {message}"
                    elif isinstance(error, genai_errors.APIError):      # ServerError (5xx) etc.
                        reason = f"http_{error.code}: {_error_message(error)}"
                    elif isinstance(error, TimeoutError):
                        reason = f"timeout after {self.settings.LLM_TIMEOUT_S:g}s"
                    else:                                               # network errors, SDK bugs
                        reason = f"{type(error).__name__}: {_short(str(error))}"
                    claimed = False
                    self._fail(model, breaker, attempts, reason, latency)
                    return None

                try:
                    parsed = parse_response(response, schema)
                except (ValidationError, ValueError) as e:
                    claimed = False
                    self._fail(model, breaker, attempts, f"schema_invalid: {_short(str(e))}", latency)
                    return None
                claimed = False
                breaker.record_success()
                tokens_in, tokens_out = usage_tokens(response)
                self._counters["tokens_in"] += tokens_in or 0
                self._counters["tokens_out"] += tokens_out or 0
                self._record(attempts, model, True, None, latency)
                return parsed, tokens_in, tokens_out
        finally:
            if claimed:
                breaker.release()

    # ---- startup check ----
    async def verify_models(self) -> dict[str, bool]:
        """List the models this key can use and map each configured id -> available.
        Never raises: returns {} (and logs) on any error."""
        try:
            if self._genai is None and not self.settings.google_api_key:
                log.warning("verify_models skipped: GOOGLE_API_KEY is not set")
                return {}
            pager = await self._client().aio.models.list()
            listed: set[str] = set()
            if hasattr(pager, "__aiter__"):
                async for m in pager:
                    self._note_listed(m, listed)
            else:
                for m in pager:
                    self._note_listed(m, listed)
            result = {model: model in listed for model in self.all_models()}
            missing = [m for m, ok in result.items() if not ok]
            if missing:
                log.warning("configured Gemini models not available to this key: %s", ", ".join(missing))
            self._available = result
            return result
        except Exception as e:
            log.warning("verify_models failed: %s: %s", type(e).__name__, _short(str(e)))
            return {}

    def _note_listed(self, m: Any, listed: set[str]) -> None:
        name = normalize_model_id(str(getattr(m, "name", "") or ""))
        if name:
            listed.add(name)
            if getattr(m, "thinking", None) is False:   # the API says it has no thinking support
                self._no_thinking.add(name)

    # ---- observability ----
    def stats(self) -> dict:
        models: dict[str, dict] = {}
        for model in dict.fromkeys([*self.all_models(), *self._breakers, *self._per_model]):
            b = self._breakers.get(model)
            pm = self._per_model.get(model, {})
            try:
                daily_remaining: int | None = self.budget.remaining(model)
            except Exception:
                daily_remaining = None
            models[model] = {
                "breaker": b.state if b else "closed",
                "consecutive_failures": b.consecutive_failures if b else 0,
                "rpm": self.settings.rpm_for(model),
                "rpm_available": round(self.limiter.available(model), 2),
                "daily_budget": self.settings.daily_budget_for(model),
                "daily_remaining": daily_remaining,
                "api_calls": pm.get("api_calls", 0),
                "errors": pm.get("errors", 0),
                "available": self._available.get(model),
                "thinking": model not in self._no_thinking,
            }
        return {**self._counters, "models": models, "last_error": self._last_error,
                "recent_attempts": list(self._recent)}

    # ---- lifecycle ----
    def close(self) -> None:
        if self._dev_cache is not None:
            self._dev_cache.close()
            self._dev_cache = None

    async def aclose(self) -> None:
        self.close()
        if self._genai is not None and self._owns_genai:
            try:
                await self._genai.aio.aclose()
            except Exception:
                pass
            self._genai = None

    # ---- internals ----
    def _client(self) -> Any:
        if self._genai is None:
            key = self.settings.google_api_key
            if not key:
                raise LLMUnavailable("GOOGLE_API_KEY is not set")
            # vertexai=False: always the Gemini Developer API, whatever GOOGLE_GENAI_USE_* env vars say
            self._genai = genai.Client(vertexai=False, api_key=key,
                                       http_options=build_http_options(self.settings))
        return self._genai

    def _config(self, schema: type[BaseModel], system: str, temperature: float,
                max_output_tokens: int | None, thinking: bool) -> types.GenerateContentConfig:
        kwargs: dict[str, Any] = dict(
            system_instruction=system,
            temperature=temperature,
            max_output_tokens=max_output_tokens or self.settings.JUDGE_MAX_OUTPUT_TOKENS,
            response_mime_type="application/json",
            response_schema=schema,
            # no tools are passed; disabling AFC skips the SDK's function-calling loop and its warning
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )
        level = self._thinking_level() if thinking else None
        if level is not None:
            kwargs["thinking_config"] = types.ThinkingConfig(thinking_level=level)
        return types.GenerateContentConfig(**kwargs)

    def _thinking_level(self) -> types.ThinkingLevel | None:
        raw = (self.settings.LLM_THINKING_LEVEL or "").strip().upper()
        if not raw:
            return None
        if raw in types.ThinkingLevel.__members__ and raw != "THINKING_LEVEL_UNSPECIFIED":
            return types.ThinkingLevel[raw]
        if self._warned_level != raw:
            self._warned_level = raw
            log.warning("LLM_THINKING_LEVEL=%r is not a valid level (minimal/low/medium/high); "
                        "sending no thinking_config", raw)
        return None

    async def _acquire_rpm(self, model: str, pin_model: bool, attempts: list[dict]) -> bool:
        timeout = PINNED_RPM_WAIT_S if pin_model else RPM_WAIT_S
        if await self.limiter.acquire(model, timeout):
            return True
        self._record(attempts, model, False, "rpm_limited", 0.0)
        if pin_model:
            wait = self.limiter.next_available_in(model)
            wait = COOLDOWN_429_S if math.isinf(wait) else wait
            raise QuotaExceeded(model, "rpm", _utcnow() + timedelta(seconds=wait))
        return False

    def _skip_daily(self, model: str, pin_model: bool, attempts: list[dict]) -> None:
        self._record(attempts, model, False, "daily_budget_exhausted", 0.0)
        if pin_model:
            raise QuotaExceeded(model, "daily", next_reset_utc())

    def _fail(self, model: str, breaker: CircuitBreaker, attempts: list[dict], reason: str,
              latency: float) -> None:
        breaker.record_failure()
        self._record(attempts, model, False, reason, latency)
        self._counters["errors"] += 1
        self._model_counters(model)["errors"] += 1
        self._last_error = f"{model}: {reason}"
        log.warning("LLM call failed (model=%s): %s", model, reason)

    def _record(self, attempts: list[dict], model: str, ok: bool, error: str | None,
                latency: float) -> None:
        entry = {"model": model, "ok": ok, "error": error, "latency_ms": round(latency, 1)}
        attempts.append(entry)
        self._recent.append({**entry, "ts": _utcnow().isoformat(timespec="seconds")})

    def _count_api_call(self, model: str) -> None:
        self._counters["api_calls"] += 1
        self._model_counters(model)["api_calls"] += 1

    def _model_counters(self, model: str) -> dict[str, int]:
        return self._per_model.setdefault(model, {"api_calls": 0, "errors": 0})

    def _unavailable(self, message: str, attempts: list[dict]) -> LLMUnavailable:
        self._counters["unavailable"] += 1
        self._last_error = message
        return LLMUnavailable(message, attempts=attempts)

    def _devcache(self) -> DevCache | None:
        if self._dev_cache is None and not self._dev_cache_broken:
            try:
                self._dev_cache = DevCache(self.settings.cache_dir / "dev")
            except Exception as e:
                self._dev_cache_broken = True
                log.warning("dev cache disabled: %s", e)
        return self._dev_cache

    @staticmethod
    def _cache_key(model: str, prompt_version: str, system: str, prompt: str,
                   schema: type[BaseModel]) -> str:
        return DevCache.make_key(model, prompt_version, system, prompt,
                                 f"{schema.__module__}.{schema.__qualname__}")

    def _cache_get(self, model: str, prompt_version: str, system: str, prompt: str,
                   schema: type[BaseModel]) -> tuple[BaseModel, int | None, int | None] | None:
        cache = self._devcache()
        if cache is None:
            return None
        entry = cache.get(self._cache_key(model, prompt_version, system, prompt, schema))
        if not entry:
            return None
        try:
            parsed = schema.model_validate(entry.get("parsed"))
        except ValidationError:          # schema changed since the entry was written: a miss
            return None
        return parsed, _int_or_none(entry.get("tokens_in")), _int_or_none(entry.get("tokens_out"))

    def _cache_set(self, model: str, prompt_version: str, system: str, prompt: str,
                   schema: type[BaseModel], parsed: BaseModel, tokens_in: int | None,
                   tokens_out: int | None) -> None:
        cache = self._devcache()
        if cache is None:
            return
        cache.set(self._cache_key(model, prompt_version, system, prompt, schema),
                  {"parsed": parsed.model_dump(mode="json"), "model": model,
                   "prompt_version": prompt_version, "tokens_in": tokens_in,
                   "tokens_out": tokens_out, "stored_at": _utcnow().isoformat()})


# ---------------- test double ----------------

class FakeLLMClient:
    """Same public API as LLMClient; no network, no quota. For pipeline/agent tests.

    responses: {role: [item, ...]} consumed in order (the last item then repeats), or
               {role: callable(system, prompt, schema) -> item} (may be async).
    item:      a pydantic model or dict (validated against the requested schema), a JSON string,
               or an exception instance / class, which is raised (e.g. LLMUnavailable, QuotaExceeded).
    down=True: every call raises LLMUnavailable (the attribute can be flipped at runtime).
    `.calls` records {role, system, prompt, schema, prompt_version, temperature, pin_model}.
    """

    def __init__(self, responses: Mapping[str, Any] | None = None, *, down: bool = False,
                 settings: Any = None) -> None:
        self.settings = settings
        self.down = down
        self.calls: list[dict] = []
        self._responses: dict[str, Any] = {}
        for role, spec in (responses or {}).items():
            if callable(spec) and not isinstance(spec, type):
                self._responses[role] = spec
            elif isinstance(spec, (list, tuple)):
                self._responses[role] = deque(spec)
            else:
                self._responses[role] = deque([spec])
        self._unavailable = 0

    def models_for(self, role: Role) -> list[str]:
        return [f"fake-{role}"]

    def all_models(self) -> list[str]:
        return [f"fake-{r}" for r in ROLES]

    async def generate_structured(self, *, role: Role, system: str, prompt: str,
                                  schema: type[BaseModel], prompt_version: str,
                                  temperature: float = 0.0, max_output_tokens: int | None = None,
                                  pin_model: bool = False, use_dev_cache: bool = True) -> LLMResult:
        self.calls.append({"role": role, "system": system, "prompt": prompt, "schema": schema,
                           "prompt_version": prompt_version, "temperature": temperature,
                           "pin_model": pin_model})
        model = f"fake-{role}"
        if self.down:
            self._unavailable += 1
            raise LLMUnavailable("FakeLLMClient is down",
                                 attempts=[{"model": model, "ok": False, "error": "down", "latency_ms": 0.0}])
        spec = self._responses.get(role)
        if spec is None or (isinstance(spec, deque) and not spec):
            self._unavailable += 1
            raise LLMUnavailable(f"FakeLLMClient: no response configured for role {role!r}")
        if isinstance(spec, deque):
            item = spec.popleft() if len(spec) > 1 else spec[0]
        else:
            item = spec(system, prompt, schema)
            if inspect.isawaitable(item):
                item = await item
        if isinstance(item, type) and issubclass(item, BaseException):
            item = _instantiate(item)
        if isinstance(item, BaseException):
            raise item
        return LLMResult(parsed=_coerce(item, schema), model=model, latency_ms=0.0, tokens_in=None,
                         tokens_out=None, cache_hit=False, fallback_used=False,
                         attempts=[{"model": model, "ok": True, "error": None, "latency_ms": 0.0}])

    async def verify_models(self) -> dict[str, bool]:
        return {m: True for m in self.all_models()}

    def stats(self) -> dict:
        return {"calls": len(self.calls), "api_calls": 0, "errors": 0,
                "unavailable": self._unavailable, "fallbacks": 0, "cache_hits": 0,
                "quota_exceeded": 0, "tokens_in": 0, "tokens_out": 0, "models": {},
                "last_error": None, "recent_attempts": [], "fake": True}

    def close(self) -> None:
        pass

    async def aclose(self) -> None:
        pass


# ---------------- private helpers ----------------

def _coerce(item: Any, schema: type[BaseModel]) -> BaseModel:
    if isinstance(item, schema):
        return item
    if isinstance(item, BaseModel):
        return schema.model_validate(item.model_dump())
    if isinstance(item, Mapping):
        return schema.model_validate(dict(item))
    if isinstance(item, (str, bytes)):
        return schema.model_validate_json(item)
    raise TypeError(f"FakeLLMClient can't turn {type(item).__name__} into {schema.__name__}")


def _instantiate(exc_type: type[BaseException]) -> BaseException:
    try:
        return exc_type()
    except TypeError:
        return exc_type(f"FakeLLMClient: scripted {exc_type.__name__}")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ms_since(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000.0


def _int_or_none(x: Any) -> int | None:
    return x if isinstance(x, int) and not isinstance(x, bool) else None


def _short(s: str, n: int = _ERR_MAX) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _error_message(e: genai_errors.APIError) -> str:
    return _short(str(e.message or e.status or e))


def _quota_kind(e: genai_errors.APIError) -> Literal["rpm", "daily"]:
    """Per-day or per-minute 429? The QuotaFailure details carry ids like
    'GenerateRequestsPerDayPerProjectPerModel-FreeTier'."""
    try:
        blob = json.dumps(getattr(e, "details", None), default=str)
    except (TypeError, ValueError):
        blob = ""
    blob += " " + str(getattr(e, "message", "") or "")
    return "daily" if _PER_DAY_RE.search(blob) else "rpm"


def _finish_info(response: Any) -> str:
    try:
        candidates = getattr(response, "candidates", None) or []
        reason = getattr(candidates[0], "finish_reason", None) if candidates else None
        block = getattr(getattr(response, "prompt_feedback", None), "block_reason", None)
        bits = [f"finish_reason={reason}" if reason else "", f"block_reason={block}" if block else ""]
        info = ", ".join(b for b in bits if b)
        return f" ({info})" if info else ""
    except Exception:
        return ""


__all__ = ["LLMClient", "FakeLLMClient", "LLMResult", "LLMError", "LLMUnavailable", "QuotaExceeded",
           "Role", "ROLES", "build_http_options", "parse_response", "usage_tokens",
           "is_gemini_model", "is_local_model", "normalize_model_id"]
