"""AppTest: Evidence tab renders self-assessment markdown."""
from __future__ import annotations

from pathlib import Path

from streamlit.testing.v1 import AppTest

_APP = str(Path(__file__).resolve().parent.parent.parent / "ui" / "app.py")


def test_evidence_tab_shows_self_assessment():
    at = AppTest.from_file(_APP, default_timeout=30)
    at.run()
    md_texts = [el.value for el in at.markdown if isinstance(el.value, str)]
    assert any("Self-assessment" in t for t in md_texts), (
        f"'Self-assessment' not found in {len(md_texts)} markdown elements"
    )
