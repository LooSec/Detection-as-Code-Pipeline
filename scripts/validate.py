#!/usr/bin/env python3
"""Validate detection YAML files against the schema. Also checks for
duplicate IDs and missing test coverage."""

import json
import sys
from pathlib import Path

import jsonschema
import yaml

RULES_DIR = Path(__file__).parent.parent / "rules"
SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "detection_schema.json"
TESTS_DIR = Path(__file__).parent.parent / "tests" / "sample_logs"


def load_schema() -> dict:
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def validate_detection(detection: dict, schema: dict) -> list[str]:
    errors = []
    validator = jsonschema.Draft7Validator(schema)
    for error in validator.iter_errors(detection):
        path = " -> ".join(str(p) for p in error.absolute_path) or "(root)"
        errors.append(f"  Schema: {path}: {error.message}")

    det_id = detection.get("id", "UNKNOWN")
    sample_dir = TESTS_DIR / det_id.lower().replace("-", "_")
    if not sample_dir.exists():
        errors.append(f"  Missing sample logs: tests/sample_logs/{det_id.lower().replace('-', '_')}/")

    return errors


def check_unique_ids(detections: list[tuple[Path, dict]]) -> list[str]:
    seen = {}
    errors = []
    for filepath, det in detections:
        det_id = det.get("id", "MISSING")
        if det_id in seen:
            errors.append(f"Duplicate ID '{det_id}': {filepath} and {seen[det_id]}")
        seen[det_id] = filepath
    return errors


def main() -> int:
    schema = load_schema()
    rule_files = sorted(RULES_DIR.rglob("*.yml"))

    if not rule_files:
        print("No detection files found")
        return 1

    print(f"Validating {len(rule_files)} detection(s)...\n")

    all_dets = []
    total_errors = 0

    for filepath in rule_files:
        rel = filepath.relative_to(RULES_DIR.parent)
        try:
            with open(filepath) as f:
                det = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"FAIL {rel}\n  YAML parse error: {e}")
            total_errors += 1
            continue

        errors = validate_detection(det, schema)
        all_dets.append((filepath, det))

        if errors:
            print(f"FAIL {rel}")
            for e in errors:
                print(e)
            total_errors += len(errors)
        else:
            print(f"PASS {rel} [{det['id']}] {det['name']}")

    dup_errors = check_unique_ids(all_dets)
    for e in dup_errors:
        print(f"  {e}")
    total_errors += len(dup_errors)

    print(f"\n{'='*60}")
    print(f"{len(rule_files)} checked, {total_errors} error(s)")
    return 1 if total_errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
