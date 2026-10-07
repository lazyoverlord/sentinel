"""Review-queue isolation: eval/redteam writes go to REVIEW_QUEUE_DIR, not the live feedback dir."""
from __future__ import annotations

import json

import pytest

from firewall.config import ROOT, Settings
from tests.conftest import fake_c1, jv, make_bank

from firewall.detection.classifiers import ClassifierBank, FakeClassifier
from firewall.llm import FakeLLMClient
from firewall.pipeline import Firewall


def _fw(s, judge_response):
    bank = make_bank(s)
    return Firewall(s, llm=FakeLLMClient({"judge": judge_response}, down=False),
                    bank=bank, load_classifiers=False)


@pytest.fixture
def default_settings(tmp_path):
    return Settings(_env_file=None, DATA_DIR=tmp_path, DEV_MODE=True, VERDICT_CACHE=False,
                    DEV_CACHE=False, AUDIT_SAMPLE_RATE=0.0, ADMIN_TOKEN="test-admin-token",
                    GOOGLE_API_KEY=None)


@pytest.fixture
def isolated_settings(tmp_path):
    return Settings(_env_file=None, DATA_DIR=tmp_path, DEV_MODE=True, VERDICT_CACHE=False,
                    DEV_CACHE=False, AUDIT_SAMPLE_RATE=0.0, ADMIN_TOKEN="test-admin-token",
                    GOOGLE_API_KEY=None,
                    REVIEW_QUEUE_DIR=tmp_path / "feedback_eval")


async def test_default_fw_writes_to_default_queue(default_settings):
    fw = _fw(default_settings, jv("injection", 0.9, [1], [("S1", "text that is not in the document")]))
    text = "Our office will be closed on Friday for Diwali."
    r = await fw.analyze_text(text, "retrieved")
    assert r.action == "hold_for_review"

    queue_file = default_settings.feedback_dir / "review_queue.jsonl"
    assert queue_file.exists()
    rows = [json.loads(l) for l in queue_file.read_text().splitlines() if l.strip()]
    assert any(row["audit_id"] == r.audit_id for row in rows)
    fw.close()


async def test_isolated_fw_writes_to_separate_dir(isolated_settings):
    fw = _fw(isolated_settings, jv("injection", 0.9, [1], [("S1", "text that is not in the document")]))
    text = "Our office will be closed on Friday for Diwali."
    r = await fw.analyze_text(text, "retrieved")
    assert r.action == "hold_for_review"

    default_queue = isolated_settings.feedback_dir / "review_queue.jsonl"
    isolated_queue = isolated_settings.REVIEW_QUEUE_DIR / "review_queue.jsonl"

    assert isolated_queue.exists()
    rows = [json.loads(l) for l in isolated_queue.read_text().splitlines() if l.strip()]
    assert any(row["audit_id"] == r.audit_id for row in rows)

    assert not default_queue.exists() or all(
        json.loads(l).get("audit_id") != r.audit_id
        for l in default_queue.read_text().splitlines() if l.strip()
    )
    fw.close()


def test_review_queue_dir_defaults_to_feedback_dir(default_settings):
    assert default_settings.review_queue_dir == default_settings.feedback_dir


def test_review_queue_dir_overridden(isolated_settings):
    assert isolated_settings.review_queue_dir == isolated_settings.REVIEW_QUEUE_DIR
    assert isolated_settings.review_queue_dir != isolated_settings.feedback_dir
