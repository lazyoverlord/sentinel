"""Shared fixtures. No network, no model downloads: C1 is simulated by a keyword FakeClassifier and the
judge by FakeLLMClient."""
import re

import pytest

from firewall.config import Settings
from firewall.detection.classifiers import ClassifierBank, FakeClassifier
from firewall.llm import FakeLLMClient
from firewall.pipeline import Firewall

_ATTACKY = re.compile(r"ignore (all )?(previous|prior)|system prompt|you are now|dan\b|disregard|"
                      r"forward .* to .*@|reviewer|classify this|pichle|निर्देश|"
                      r"prompt injection\b", re.I)


def fake_c1(text: str) -> float:
    """Stand-in for DeBERTa C1: high on English injection phrasing, low otherwise."""
    return 0.97 if _ATTACKY.search(text) else 0.03


@pytest.fixture
def settings(tmp_path):
    return Settings(_env_file=None, DATA_DIR=tmp_path, DEV_MODE=True, VERDICT_CACHE=False, DEV_CACHE=False,
                    AUDIT_SAMPLE_RATE=0.0, ADMIN_TOKEN="test-admin-token", GOOGLE_API_KEY=None)


def make_bank(settings, c1=fake_c1):
    bank = ClassifierBank(settings)
    bank.add(FakeClassifier("c1", c1))
    return bank


@pytest.fixture
def make_fw(settings):
    created = []

    def _make(responses=None, *, down=False, c1=fake_c1, **overrides):
        s = settings.model_copy(update=overrides) if overrides else settings
        fw = Firewall(s, llm=FakeLLMClient(responses or {}, down=down), bank=make_bank(s, c1) if c1 else None,
                      load_classifiers=False)
        created.append(fw)
        return fw

    yield _make
    for fw in created:
        fw.close()


def jv(verdict="safe", confidence=0.9, types=(), evidence=(), multi=False, turns=(), rationale="ok"):
    """A judge output dict for FakeLLMClient."""
    return {"verdict": verdict, "confidence": confidence, "attack_types": list(types),
            "evidence": [{"segment_id": s, "quote": q} for s, q in evidence], "multi_step": multi,
            "contributing_turns": list(turns), "rationale": rationale, "recommended_strategy": "none"}
