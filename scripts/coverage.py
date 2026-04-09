#!/usr/bin/env python3
"""Print ATT&CK coverage from detection rules."""

import sys
from pathlib import Path
import yaml

RULES_DIR = Path(__file__).parent.parent / "rules"

TACTICS = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def main() -> int:
    dets = []
    for f in sorted(RULES_DIR.rglob("*.yml")):
        with open(f) as fh:
            dets.append(yaml.safe_load(fh))

    if not dets:
        print("No detections found")
        return 1

    coverage: dict[str, list] = {t: [] for t in TACTICS}
    for d in dets:
        tactic = d["mitre"]["tactic"]
        coverage[tactic].append(d)

    print("ATT&CK Coverage")
    print("=" * 60)

    covered = 0
    for tactic in TACTICS:
        rules = coverage[tactic]
        if rules:
            covered += 1
            print(f"  + {tactic}")
            for r in rules:
                tech = r["mitre"].get("subtechnique") or r["mitre"]["technique"]
                print(f"    {r['id']} {tech} [{r['severity']}] {r['name']}")
        else:
            print(f"  - {tactic}")

    print(f"\n{covered}/{len(TACTICS)} tactics ({covered*100//len(TACTICS)}%)")
    print(f"{len(dets)} total detections")
    return 0


if __name__ == "__main__":
    sys.exit(main())
