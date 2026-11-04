import pytest
import yaml

from tripwire.policy import check, decide, load_policy, parse_condition, validate_policy


def test_parse_conditions():
    assert parse_condition(">=0.8") == (">=", 0.8)
    assert parse_condition("<0.3") == ("<", 0.3)
    assert parse_condition(0.5) == (">=", 0.5)
    assert parse_condition("==1") == ("==", 1.0)
    with pytest.raises(ValueError):
        parse_condition("about 0.5")


def test_check():
    assert check(0.9, ">=0.8") and not check(0.7, ">=0.8") and check(1.0, "==1") and check(0.2, "<0.3")


def test_default_policy_loads():
    p = load_policy()
    assert {"send_email", "http_post", "write_file", "fetch_url"} <= set(p["tools"])


def test_first_matching_rule_wins():
    p = load_policy()
    assert decide(p, "send_email", {"canary": 1.0, "exfil": 0.0})[0].value == "block"
    assert decide(p, "send_email", {"exfil": 0.9})[0].value == "block"
    assert decide(p, "send_email", {"exfil": 0.55})[0].value == "require_approval"
    assert decide(p, "send_email", {"exfil": 0.0, "heuristics": 0.9})[0].value == "allow"


def test_memory_rule():
    p = load_policy()
    sig = {"memory_write": 1.0, "heuristics": 0.7, "classifier": 0.6, "taint": 0.5}
    assert decide(p, "write_file", sig) == (decide(p, "write_file", sig)[0], "memory-poisoning")
    assert decide(p, "write_file", {**sig, "memory_write": 0.0})[0].value == "allow"


def test_low_risk_tool():
    p = load_policy()
    assert decide(p, "fetch_url", {"exfil": 0.55})[0].value == "allow"
    assert decide(p, "fetch_url", {"exfil": 0.9})[0].value == "block"


def test_unknown_tool_uses_default_rules():
    p = load_policy()
    assert decide(p, "make_purchase", {"exfil": 0.9})[0].value == "block"


def test_invalid_policy_rejected(tmp_path):
    bad = {"tools": {"x": {"rules": [{"name": "r", "action": "explode"}]}}}
    with pytest.raises(ValueError):
        validate_policy(bad)
    f = tmp_path / "p.yaml"
    f.write_text(yaml.safe_dump({"tools": {"x": {"rules": [{"name": "r", "when": {"exfil": "lots"}, "action": "block"}]}}}))
    with pytest.raises(ValueError):
        load_policy(f)
