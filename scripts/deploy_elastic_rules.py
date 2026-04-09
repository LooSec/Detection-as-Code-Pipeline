#!/usr/bin/env python3
"""Convert YAML detections to Elastic Security rules and push them
via the Kibana Detection Engine API."""

import argparse
import json
import sys
import urllib.request
import urllib.error
import base64
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).parent.parent / "rules"

TACTIC_NAMES = {
    "initial-access": "Initial Access",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "execution": "Execution",
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
}

RISK_SCORES = {"low": 21, "medium": 47, "high": 73, "critical": 99}


def to_kql(logic: dict) -> str:
    """Build a KQL query string from detection logic."""
    parts = [f'event.action: "{logic["event_name"]}"']

    for c in logic["conditions"]:
        f, op, v = c["field"], c["operator"], c["value"]
        if op == "eq":
            parts.append(f'{f}: "{v}"')
        elif op == "neq":
            parts.append(f'NOT {f}: "{v}"')
        elif op == "contains":
            parts.append(f"{f}: *{v}*")
        elif op == "not_contains":
            parts.append(f"NOT {f}: *{v}*")
        elif op == "exists":
            parts.append(f"{f}: *")
        elif op == "not_exists":
            parts.append(f"NOT {f}: *")
        elif op == "in" and isinstance(v, list):
            parts.append("(" + " OR ".join(f'{f}: "{x}"' for x in v) + ")")

    return " AND ".join(parts)


def yaml_to_elastic_rule(det: dict) -> dict:
    mitre = det["mitre"]
    threat = {
        "framework": "MITRE ATT&CK",
        "tactic": {
            "id": mitre["tactic"].replace("-", "_").upper() if mitre["tactic"] != "initial-access" else "TA0001",
            "name": TACTIC_NAMES.get(mitre["tactic"], mitre["tactic"]),
        },
        "technique": [{"id": mitre["technique"], "name": mitre["technique"]}],
    }
    if mitre.get("subtechnique"):
        threat["technique"][0]["subtechnique"] = [
            {"id": mitre["subtechnique"], "name": mitre["subtechnique"]}
        ]

    rule = {
        "rule_id": det["id"].lower().replace("-", "_"),
        "name": f"[DaC] {det['name']}",
        "description": det["description"].strip(),
        "severity": det["severity"],
        "risk_score": RISK_SCORES.get(det["severity"], 47),
        "type": "query",
        "language": "kuery",
        "query": to_kql(det["logic"]),
        "index": ["logs-cloudtrail-*", "filebeat-*", "logs-aws.cloudtrail-*"],
        "interval": "5m",
        "from": "now-6m",
        "enabled": True,
        "tags": ["DaC", f"MITRE-{mitre['technique']}", det["id"]],
        "threat": [threat],
    }

    if det.get("false_positive_guidance"):
        rule["note"] = f"### FP guidance\n{det['false_positive_guidance'].strip()}"
    if det.get("references"):
        rule["references"] = det["references"]

    return rule


def deploy_rule(rule: dict, kibana_url: str, auth: str) -> bool:
    url = f"{kibana_url}/api/detection_engine/rules"

    # check if it already exists
    try:
        req = urllib.request.Request(
            f"{url}?rule_id={rule['rule_id']}",
            headers={"Authorization": auth, "kbn-xsrf": "true"},
        )
        urllib.request.urlopen(req, timeout=10)
        method = "PUT"
    except urllib.error.HTTPError as e:
        method = "POST" if e.code == 404 else None
        if method is None:
            print(f"  check failed: {e}")
            return False

    req = urllib.request.Request(
        url,
        data=json.dumps(rule).encode(),
        headers={"Content-Type": "application/json", "Authorization": auth, "kbn-xsrf": "true"},
        method=method,
    )
    try:
        urllib.request.urlopen(req, timeout=30)
        return True
    except urllib.error.HTTPError as e:
        print(f"  {e.code}: {e.read().decode()[:200]}")
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kibana-url", required=True)
    parser.add_argument("--user", default="elastic")
    parser.add_argument("--password", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    auth = "Basic " + base64.b64encode(f"{args.user}:{args.password}".encode()).decode()

    files = sorted(RULES_DIR.rglob("*.yml"))
    print(f"{len(files)} detection(s)\n")

    ok, fail = 0, 0
    for f in files:
        with open(f) as fh:
            det = yaml.safe_load(fh)
        rule = yaml_to_elastic_rule(det)

        if args.dry_run:
            print(f"[dry run] {det['id']} — {det['name']}")
            print(f"  KQL: {rule['query']}\n")
            continue

        print(f"{det['id']} {det['name']}...", end=" ")
        if deploy_rule(rule, args.kibana_url, auth):
            print("ok")
            ok += 1
        else:
            print("FAILED")
            fail += 1

    print(f"\n{ok} deployed, {fail} failed")
    return 1 if fail > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
