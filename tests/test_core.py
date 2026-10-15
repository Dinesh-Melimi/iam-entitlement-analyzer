from iam_analyzer.core import allows, analyze, escalation_risks, load


def report():
    return {r["principal"].split("/")[-1]: r for r in
            analyze(load("samples/principals.json"), load("samples/cloudtrail.json")["Records"])}


def test_wildcard_matching():
    assert allows({"s3:*"}, "s3:GetObject")
    assert not allows({"s3:getobject"}, "s3:PutObject")


def test_admin_is_highest_risk():
    r = analyze(load("samples/principals.json"), load("samples/cloudtrail.json")["Records"])
    assert r[0]["principal"].endswith("legacy-admin")
    assert "CreatePolicyVersion" in r[0]["escalation_paths"]


def test_passrole_ec2_escalation_detected():
    assert "PassRole+EC2" in report()["ci-deployer"]["escalation_paths"]


def test_unused_permissions_flagged():
    ci = report()["ci-deployer"]
    assert "iam:passrole" in ci["unused"] and "ec2:runinstances" in ci["unused"]
    assert "s3:*" not in ci["unused"]


def test_least_privilege_role_is_clean():
    rr = report()["report-reader"]
    assert rr["unused"] == [] and rr["escalation_paths"] == [] and not rr["wildcard_resource"]


def test_suggested_policy_only_used_actions():
    pol = report()["ci-deployer"]["suggested_policy"]
    assert set(pol["Statement"][0]["Action"]) == {"s3:putobject", "cloudformation:createstack"}


def test_no_escalation_for_readonly():
    assert escalation_risks({"s3:getobject"}) == []
