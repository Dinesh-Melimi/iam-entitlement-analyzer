import json
from datetime import date

from iam_analyzer.iga import (
    apply_decisions,
    build_campaign,
    correlate,
    coverage,
    lifecycle_violations,
    load_accounts,
    sod_conflicts,
)

S = "samples/iga/"
TODAY = date(2026, 10, 15)


def _ids():
    wd = load_accounts(S + "workday.csv", "workday")
    ad = load_accounts(S + "active_directory.csv", "active_directory")
    fin = load_accounts(S + "finance_app.csv", "finance_app")
    return correlate(wd, ad, fin)


def test_correlation_and_orphans():
    ids, orphans = _ids()
    assert coverage(ids)["identities"] == 3
    assert [o.native_id for o in orphans] == ["svc-legacy"]   # AD account with no HR identity
    alice = next(i for i in ids if i.identity_id == "e1001")
    assert {a.source for a in alice.accounts} == {"workday", "active_directory", "finance_app"}


def test_lifecycle_violation():
    ids, _ = _ids()
    v = lifecycle_violations(ids)
    assert len(v) == 1 and v[0]["identity"] == "e1003"        # terminated, still has AD account
    assert "active_directory:cdiaz" in v[0]["accounts"]


def test_sod_conflicts():
    ids, _ = _ids()
    with open(S + "sod_rules.json") as fh:
        rules = json.load(fh)
    conflicts = {c["rule"] for c in sod_conflicts(ids, rules)}
    assert len(conflicts) == 2                                 # Bob has both AP and vendor/payment conflicts


def test_certification_campaign_and_evidence():
    ids, _ = _ids()
    c = build_campaign(ids, "CERT-2026Q4", TODAY)
    assert all(i["decision"] == "pending" for i in c["items"])
    assert not any(i["identity"] == "e1003" for i in c["items"])   # terminated excluded
    decisions = {c["items"][0]["item_id"]: ("revoke", "no longer needed"),
                 c["items"][1]["item_id"]: ("certify", "")}
    res = apply_decisions(c, decisions, TODAY)
    assert res["evidence"]["revoked"] == 1 and res["evidence"]["certified"] == 1
    assert res["revocations"][0]["entitlement"] == c["items"][0]["entitlement"]
    assert c["status"] == "open"   # not all decided


def test_full_certification_completes():
    ids, _ = _ids()
    c = build_campaign(ids, "C", TODAY)
    res = apply_decisions(c, {i["item_id"]: ("certify", "") for i in c["items"]}, TODAY)
    assert c["status"] == "complete" and res["evidence"]["completion_pct"] == 100.0
