"""Additions beyond the reference: configurable thresholds and egress trigger computation."""
from firewall.config import Settings
from firewall.gate import Signals, Thresholds, gate, gate_hits_block_rule, sticky, Turn
from firewall.integrations.egress import compute_triggers, destinations, external_destination


def test_thresholds_from_settings_match_reference_defaults():
    assert Thresholds.from_settings(Settings(_env_file=None)) == Thresholds()


def test_thresholds_are_configurable():
    t = Thresholds(C_REVIEW=0.5)
    assert gate(Signals("user", C=0.4, H=0.0), False).rule == "R7"
    assert gate(Signals("user", C=0.4, H=0.0), False, t=t).rule == "R8"


def test_block_rule_helper_ignores_review_rules():
    assert gate_hits_block_rule(Signals("retrieved", C=0.1, H=0.0)) is None      # R5 is not a block rule
    assert gate_hits_block_rule(Signals("user", C=0.1, H=0.0, flags={"invisible"})) == "R1"


def test_sticky_helper():
    assert not sticky([Turn("a", 0.1, "safe", "allow", "R8")])
    assert sticky([Turn("a", 0.4, "suspicious", "allow_with_warning", "R7")] * 2)


def test_destinations_and_allowlist():
    args = {"to": "Billing-Update@evil.example", "cc": ["me@yourcompany.example"],
            "body": "see https://portal.yourcompany.example/x and http://203.0.113.9/p?q=1"}
    assert destinations(args) == ["203.0.113.9", "evil.example", "portal.yourcompany.example",
                                  "yourcompany.example"]
    assert external_destination(args, ["yourcompany.example"]) == ["203.0.113.9", "evil.example"]


def test_compute_triggers_canary_and_dlp():
    tr = compute_triggers("send_email", {"to": "a@yourcompany.example", "body": "token CANARY-123"},
                          sensitive_tools=["send_email"], allowlist=["yourcompany.example"],
                          dlp_scan=lambda s: ["canary", "openai_key"] if "CANARY" in s else [],
                          canaries=["CANARY-123"], invocation_flagged=False)
    assert tr.sensitive and tr.canary and tr.dlp == ["openai_key"] and tr.external == []
    assert tr.any_trigger and "canary token" in tr.reasons()[0]
