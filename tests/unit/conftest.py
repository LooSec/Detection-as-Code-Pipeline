"""Shared test fixtures."""

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
from evaluate import evaluate_detection, load_detection  # noqa: E402

RULES_DIR = Path(__file__).parent.parent.parent / "rules"
SAMPLE_LOGS_DIR = Path(__file__).parent.parent / "sample_logs"


def _find_rule(rule_id: str) -> Path:
    for f in RULES_DIR.rglob("*.yml"):
        with open(f) as fh:
            if yaml.safe_load(fh).get("id") == rule_id:
                return f
    raise FileNotFoundError(f"No rule with id {rule_id}")


def _load_samples(rule_id: str) -> dict:
    # find the rule file first, then use its filename to locate sample logs
    rule_path = _find_rule(rule_id)
    sample_dir = SAMPLE_LOGS_DIR / rule_path.stem
    logs = {"true_positive": [], "benign": []}
    for f in sample_dir.glob("*.yml"):
        with open(f) as fh:
            data = yaml.safe_load(fh)
            if data.get("true_positive"):
                logs["true_positive"].extend(data["true_positive"])
            if data.get("benign"):
                logs["benign"].extend(data["benign"])
    return logs


import pytest  # noqa: E402

@pytest.fixture
def detection_factory():
    def _load(rule_id: str) -> dict:
        return load_detection(_find_rule(rule_id))
    return _load


@pytest.fixture
def sample_logs_factory():
    def _load(rule_id: str) -> dict:
        return _load_samples(rule_id)
    return _load
