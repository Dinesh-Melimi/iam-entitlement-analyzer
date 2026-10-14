# IAM Entitlement Analyzer

Most AWS roles hold far more permission than they use. This tool compares what each IAM principal is **granted** against what it actually **called** in CloudTrail, then flags:

- **Unused permissions** to remove
- **Wildcard actions** (`s3:*`, `*`) and `Resource: "*"`
- **Privilege-escalation paths** such as `iam:PassRole` + `ec2:RunInstances`, `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`
- A **risk score** per principal, and a **draft least-privilege policy** built from real usage

It also ships **OPA/Rego guardrails** (`policies/iam_guardrails.rego`) that block risky IAM policies in CI before they reach an account. This is the same idea CIEM tools like Wiz apply at scale.

## Run

```bash
pip install -e .
iam-analyzer --principals samples/principals.json --cloudtrail samples/cloudtrail.json
opa eval -d policies -i samples/bad_policy.json "data.iam.guardrails.deny" --format pretty
pytest -q
```

Sample output:

```
arn:aws:iam::111122223333:user/legacy-admin  risk=...
  ESCALATION: AttachRolePolicy, AttachUserPolicy, CreateAccessKey, CreatePolicyVersion, ...
arn:aws:iam::111122223333:role/ci-deployer  risk=...
  ESCALATION: PassRole+EC2
  unused: ec2:runinstances, iam:passrole
```

## Using real data

Export policies with `aws iam get-account-authorization-details` and CloudTrail events from S3 or Athena (90+ days recommended). Read-only access is enough. Review every suggested policy and scope `Resource` to specific ARNs before applying.
