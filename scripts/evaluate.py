#!/usr/bin/env python3
"""
Rule evaluation engine. Takes YAML detection rules and runs them against
log events. Same logic runs locally for testing and in Lambda for prod.
"""

import json
import re
from pathlib import Path
from typing import Any

import yaml


def _stringify(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)


def get_nested_field(event: dict, field_path: str) -> Any:
    """Dot-notation field access, handles nested dicts and list indexes."""
    current = event
    for key in field_path.split("."):
        if current is None:
            return None
        if isinstance(current, list):
            try:
                current = current[int(key)]
            except (IndexError, ValueError):
                return None
        elif isinstance(current, dict):
            current = current.get(key)
        else:
            return None
    return current


def evaluate_condition(event: dict, condition: dict) -> bool:
    field = condition["field"]
    operator = condition["operator"]
    expected = condition["value"]
    actual = get_nested_field(event, field)

    match operator:
        case "eq":
            return str(actual) == str(expected)
        case "neq":
            return str(actual) != str(expected)
        case "contains":
            return str(expected) in _stringify(actual) if actual is not None else False
        case "not_contains":
            return str(expected) not in _stringify(actual) if actual is not None else True
        case "regex":
            return bool(re.search(str(expected), _stringify(actual))) if actual is not None else False
        case "gt":
            return float(actual) > float(expected) if actual is not None else False
        case "lt":
            return float(actual) < float(expected) if actual is not None else False
        case "gte":
            return float(actual) >= float(expected) if actual is not None else False
        case "lte":
            return float(actual) <= float(expected) if actual is not None else False
        case "in":
            if isinstance(expected, list):
                return str(actual) in [str(v) for v in expected]
            return str(actual) == str(expected)
        case "not_in":
            if isinstance(expected, list):
                return str(actual) not in [str(v) for v in expected]
            return str(actual) != str(expected)
        case "exists":
            return actual is not None
        case "not_exists":
            return actual is None
        case _:
            raise ValueError(f"Unknown operator: {operator}")


def evaluate_detection(detection: dict, event: dict) -> bool:
    """Returns True if all conditions match. Aggregate thresholds are
    handled by the Lambda engine, not here."""
    logic = detection["logic"]

    if event.get("eventName") != logic["event_name"]:
        # detections using 'in' on eventName need a different check
        if not any(
            c.get("field") == "eventName" and c.get("operator") == "in"
            for c in logic["conditions"]
        ):
            return False

    for condition in logic["conditions"]:
        if not evaluate_condition(event, condition):
            return False

    return True


def load_detection(filepath: Path) -> dict:
    with open(filepath) as f:
        return yaml.safe_load(f)


def load_all_detections(detections_dir: Path) -> list[dict]:
    return [load_detection(f) for f in sorted(detections_dir.rglob("*.yml"))]


def evaluate_event(detections: list[dict], event: dict) -> list[dict]:
    """Run an event against all loaded detections, return matches."""
    matches = []
    for det in detections:
        if evaluate_detection(det, event):
            matches.append({
                "detection_id": det["id"],
                "detection_name": det["name"],
                "severity": det["severity"],
                "mitre_tactic": det["mitre"]["tactic"],
                "mitre_technique": det["mitre"]["technique"],
            })
    return matches
