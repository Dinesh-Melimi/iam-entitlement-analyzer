import argparse
import json
import sys

from .core import analyze, load


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find unused and risky IAM permissions.")
    ap.add_argument("--principals", required=True, help="JSON list of {arn, policies}")
    ap.add_argument("--cloudtrail", required=True, help="CloudTrail JSON ({Records:[...]})")
    ap.add_argument("--json", action="store_true", help="Print full JSON report")
    a = ap.parse_args(argv)
    rep = analyze(load(a.principals), load(a.cloudtrail).get("Records", []))
    if a.json:
        json.dump(rep, sys.stdout, indent=2)
        return 0
    for r in rep:
        print(f"\n{r['principal']}  risk={r['risk_score']}")
        print(f"  used {len(r['used'])} of {len(r['granted'])} granted patterns")
        if r["escalation_paths"]:
            print(f"  ESCALATION: {', '.join(r['escalation_paths'])}")
        if r["wildcard_actions"]:
            print(f"  wildcards: {', '.join(r['wildcard_actions'])}")
        if r["unused"]:
            print(f"  unused: {', '.join(r['unused'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
