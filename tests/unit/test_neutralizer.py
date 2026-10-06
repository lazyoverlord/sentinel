"""Neutralizer unit tests: STRIP_MARKER must be classifier-inert."""
from firewall.agents.neutralizer import STRIP_MARKER

BANNED = ["prompt", "injection", "ignore", "system", "jailbreak", "instruction"]


def test_strip_marker_contains_no_attack_words():
    low = STRIP_MARKER.lower()
    for word in BANNED:
        assert word not in low, f"STRIP_MARKER contains banned word {word!r}: {STRIP_MARKER!r}"
