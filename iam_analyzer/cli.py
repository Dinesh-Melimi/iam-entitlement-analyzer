import argparse
import json
import sys

from . import iga
from .core import analyze, load


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find unused and risky IAM permissions.")
    ap.add_argument("--principals", help="JSON list of {arn, policies}")
    ap.add_argument("--cloudtrail", help="CloudTrail JSON ({Records:[...]})")
    ap.add_argument("--json", action="store_true", help="Print full JSON report")
    ap.add_argument("--iga", nargs="+", metavar="SOURCE=CSV",
                    help="Identity governance: aggregate/correlate sources, e.g. workday=hr.csv active_directory=ad.csv")
    ap.add_argument("--sod", help="SoD rules JSON for --iga")
    ap.add_argument("--campaign", metavar="ID", help="build an access-certification campaign for --iga")
    a = ap.parse_args(argv)
    if a.iga:
        return _iga(a)
    if not (a.principals and a.cloudtrail):
        ap.error("--principals and --cloudtrail are required (or use --iga)")
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


def _iga(a):
    first, *rest = a.iga
    src0, _, path0 = first.partition("=")
    auth = iga.load_accounts(path0, src0)
    targets = []
    for spec in rest:
        src, _, path = spec.partition("=")
        targets.append(iga.load_accounts(path, src))
    identities, orphans = iga.correlate(auth, *targets)
    print(f"Identities: {iga.coverage(identities)}")
    print(f"Orphan accounts (no identity): {[o.source + ':' + o.native_id for o in orphans] or 'none'}")
    for v in iga.lifecycle_violations(identities):
        print(f"  LIFECYCLE {v['identity']} ({v['name']}): {v['issue']} -> {', '.join(v['accounts'])}")
    if a.sod:
        with open(a.sod) as _sf:
            _rules = json.load(_sf)
        for c in iga.sod_conflicts(identities, _rules):
            print(f"  SoD {c['identity']} ({c['name']}): {c['rule']} -> {' + '.join(c['conflict'])}")
    if a.campaign:
        camp = iga.build_campaign(identities, a.campaign)
        print(f"Certification campaign {a.campaign}: {len(camp['items'])} review items (pending)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
