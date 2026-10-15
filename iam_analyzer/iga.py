"""Identity governance (IGA): the lifecycle SailPoint IdentityIQ and similar platforms run.

Aggregates accounts from multiple authoritative and target sources (HR / Active Directory /
LDAP / apps), correlates them to a single identity, runs access-certification campaigns with
certify/revoke decisions and audit evidence, and checks segregation-of-duties policies.

This models the concepts (aggregation, correlation, certification, SoD, lifecycle state) in
plain Python so they can be tested and reasoned about; it is not the SailPoint product.
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date


@dataclass
class Account:
    source: str            # workday | active_directory | ldap | <app>
    native_id: str         # sAMAccountName, employeeId, uid, etc.
    identity_key: str      # correlation key (e.g. employee_id or email)
    display_name: str = ""
    status: str = "active"  # active | disabled
    entitlements: list[str] = field(default_factory=list)


@dataclass
class Identity:
    identity_id: str
    name: str
    status: str                       # active | terminated (from the HR authoritative source)
    manager: str = ""
    accounts: list[Account] = field(default_factory=list)

    @property
    def entitlements(self) -> set[str]:
        return {f"{a.source}:{e}" for a in self.accounts for e in a.entitlements}


def load_accounts(path, source) -> list[Account]:
    """Aggregate accounts from one source CSV: native_id,identity_key,display_name,status,entitlements."""
    out = []
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            ents = [e.strip() for e in (r.get("entitlements") or "").split(";") if e.strip()]
            out.append(Account(source, r["native_id"], r["identity_key"].strip().lower(),
                               r.get("display_name", ""), r.get("status", "active"), ents))
    return out


def correlate(authoritative: list[Account], *target_sources: list[Account]) -> list[Identity]:
    """Correlate target accounts to authoritative (HR) identities by identity_key; report orphans."""
    identities = {}
    for a in authoritative:
        identities[a.identity_key] = Identity(a.identity_key, a.display_name or a.native_id,
                                              a.status, accounts=[a])
    orphans = []
    for src in target_sources:
        for acct in src:
            ident = identities.get(acct.identity_key)
            if ident:
                ident.accounts.append(acct)
            else:
                orphans.append(acct)
    return list(identities.values()), orphans


def lifecycle_violations(identities: list[Identity]) -> list[dict]:
    """Terminated identities that still hold active accounts = deprovisioning gaps."""
    out = []
    for i in identities:
        if i.status == "terminated":
            active = [a for a in i.accounts if a.status == "active" and a.source != "workday"]
            if active:
                out.append({"identity": i.identity_id, "name": i.name,
                            "issue": "active accounts after termination",
                            "accounts": [f"{a.source}:{a.native_id}" for a in active]})
    return out


def sod_conflicts(identities: list[Identity], rules: list[dict]) -> list[dict]:
    """rules: [{name, left, right}] where left/right are entitlement strings that must not coexist."""
    out = []
    for i in identities:
        ents = i.entitlements
        for rule in rules:
            if rule["left"] in ents and rule["right"] in ents:
                out.append({"identity": i.identity_id, "name": i.name, "rule": rule["name"],
                            "conflict": [rule["left"], rule["right"]]})
    return out


def build_campaign(identities: list[Identity], campaign_id: str, today=None) -> dict:
    """Create an access-certification campaign: one review item per identity-entitlement, pending."""
    today = (today or date.today()).isoformat()
    items = []
    for i in identities:
        if i.status == "terminated":
            continue
        for ent in sorted(i.entitlements):
            items.append({"item_id": f"{campaign_id}-{len(items) + 1:04d}",
                          "identity": i.identity_id, "name": i.name, "entitlement": ent,
                          "reviewer": i.manager or "access-owner", "decision": "pending",
                          "decided_on": "", "comment": ""})
    return {"campaign_id": campaign_id, "created": today, "status": "open", "items": items}


def apply_decisions(campaign: dict, decisions: dict, today=None) -> dict:
    """decisions: {item_id: (certify|revoke, comment)}. Returns revocation work items + evidence."""
    today = (today or date.today()).isoformat()
    revocations = []
    for item in campaign["items"]:
        d = decisions.get(item["item_id"])
        if not d:
            continue
        action, comment = d
        item["decision"], item["comment"], item["decided_on"] = action, comment, today
        if action == "revoke":
            revocations.append({"identity": item["identity"], "entitlement": item["entitlement"],
                                "reason": comment or "revoked during certification"})
    done = all(i["decision"] != "pending" for i in campaign["items"])
    campaign["status"] = "complete" if done else "open"
    decided = [i for i in campaign["items"] if i["decision"] != "pending"]
    evidence = {"campaign_id": campaign["campaign_id"], "as_of": today,
                "total_items": len(campaign["items"]), "decided": len(decided),
                "certified": sum(i["decision"] == "certify" for i in decided),
                "revoked": sum(i["decision"] == "revoke" for i in decided),
                "completion_pct": round(100 * len(decided) / len(campaign["items"]), 1)
                if campaign["items"] else 100.0}
    return {"revocations": revocations, "evidence": evidence}


def coverage(identities: list[Identity]) -> dict:
    by_source = defaultdict(int)
    for i in identities:
        for a in i.accounts:
            by_source[a.source] += 1
    return {"identities": len(identities), "accounts_by_source": dict(sorted(by_source.items()))}


def to_json(obj) -> str:
    return json.dumps(obj, indent=2, default=str)
