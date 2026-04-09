"""Tests for detection rules. Auto-discovers every rule in the repo
and runs true positive / benign validation against sample logs."""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
from evaluate import evaluate_detection  # noqa: E402

RULES_DIR = Path(__file__).parent.parent.parent / "rules"


def all_rules():
    rules = []
    for f in sorted(RULES_DIR.rglob("*.yml")):
        with open(f) as fh:
            det = yaml.safe_load(fh)
            rules.append(pytest.param(det["id"], id=f"{det['id']} {det['name']}"))
    return rules


@pytest.mark.parametrize("rule_id", all_rules())
def test_fires_on_true_positive(rule_id, detection_factory, sample_logs_factory):
    det = detection_factory(rule_id)
    samples = sample_logs_factory(rule_id)["true_positive"]
    assert len(samples) > 0, f"no true positive samples for {rule_id}"
    for event in samples:
        assert evaluate_detection(det, event), f"{rule_id} didn't fire on {event.get('eventName')}"


@pytest.mark.parametrize("rule_id", all_rules())
def test_silent_on_benign(rule_id, detection_factory, sample_logs_factory):
    det = detection_factory(rule_id)
    samples = sample_logs_factory(rule_id)["benign"]
    assert len(samples) > 0, f"no benign samples for {rule_id}"
    for event in samples:
        assert not evaluate_detection(det, event), f"{rule_id} fired on benign {event.get('eventName')}"
