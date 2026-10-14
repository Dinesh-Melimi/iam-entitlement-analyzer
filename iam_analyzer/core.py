import fnmatch
import json
from collections import defaultdict

# Permission combos that let a principal raise its own privileges (Rhino Security Labs research).
ESCALATION_PATHS = {
    "CreatePolicyVersion": [["iam:CreatePolicyVersion"]],
    "AttachUserPolicy": [["iam:AttachUserPolicy"]],
    "AttachRolePolicy": [["iam:AttachRolePolicy"]],
    "PutUserPolicy": [["iam:PutUserPolicy"]],
    "PutRolePolicy": [["iam:PutRolePolicy"]],
    "CreateAccessKey": [["iam:CreateAccessKey"]],
    "UpdateLoginProfile": [["iam:UpdateLoginProfile"]],
    "PassRole+EC2": [["iam:PassRole", "ec2:RunInstances"]],
    "PassRole+Lambda": [["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]],
    "UpdateAssumeRolePolicy": [["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"]],
}


def _as_list(v):
    return v if isinstance(v, list) else [v]


def granted_patterns(policy_docs):
    """Return (allowed action patterns, wildcard-resource flag) from Allow statements."""
    patterns, wildcard_res = set(), False
    for doc in policy_docs:
        for st in _as_list(doc.get("Statement", [])):
            if st.get("Effect") != "Allow":
                continue
            for a in _as_list(st.get("Action", [])):
                patterns.add(a.lower())
            if "*" in _as_list(st.get("Resource", [])):
                wildcard_res = True
    return patterns, wildcard_res


def allows(patterns, action):
    action = action.lower()
    return any(fnmatch.fnmatchcase(action, p) for p in patterns)


def used_actions(cloudtrail_events):
    """Map principal ARN -> set of 'service:Action' seen in CloudTrail."""
    used = defaultdict(set)
    for ev in cloudtrail_events:
        arn = ev.get("userIdentity", {}).get("arn")
        src, name = ev.get("eventSource", ""), ev.get("eventName")
        if not arn or not name:
            continue
        used[arn].add(f"{src.split('.')[0]}:{name}".lower())
    return used


def escalation_risks(patterns):
    hits = []
    for name, combos in ESCALATION_PATHS.items():
        for combo in combos:
            if all(allows(patterns, a) for a in combo):
                hits.append(name)
    return sorted(set(hits))


def analyze(principals, events):
    """principals: [{arn, policies:[policy docs]}]; events: CloudTrail records."""
    used = used_actions(events)
    report = []
    for p in principals:
        pats, wild_res = granted_patterns(p["policies"])
        seen = used.get(p["arn"], set())
        unused = sorted(x for x in pats if not any(fnmatch.fnmatchcase(u, x) for u in seen))
        wildcard_actions = sorted(x for x in pats if "*" in x)
        risks = escalation_risks(pats)
        score = 3 * len(risks) + 2 * len(wildcard_actions) + len(unused) + (2 if wild_res else 0)
        report.append({
            "principal": p["arn"],
            "granted": sorted(pats),
            "used": sorted(seen),
            "unused": unused,
            "wildcard_actions": wildcard_actions,
            "wildcard_resource": wild_res,
            "escalation_paths": risks,
            "risk_score": score,
            "suggested_policy": least_privilege(seen),
        })
    return sorted(report, key=lambda r: -r["risk_score"])


def least_privilege(seen):
    """Draft a policy limited to actions actually used. Resources still need scoping by a human."""
    if not seen:
        return None
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Action": sorted(seen),
        "Resource": "*",
        "_note": "Scope Resource to specific ARNs before applying.",
    }]}


def load(path):
    with open(path) as f:
        return json.load(f)
