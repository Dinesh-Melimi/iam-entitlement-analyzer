# OPA guardrails for IAM policy documents (e.g. from Terraform plan JSON or CI).
# Run: opa eval -d policies -i samples/bad_policy.json "data.iam.guardrails.deny"
package iam.guardrails

import rego.v1

statements contains st if {
	some st in input.Statement
	st.Effect == "Allow"
}

as_list(x) := x if is_array(x)
as_list(x) := [x] if not is_array(x)

deny contains msg if {
	some st in statements
	"*" in as_list(st.Action)
	msg := "Statement grants Action \"*\" (full admin)"
}

deny contains msg if {
	some st in statements
	some a in as_list(st.Action)
	endswith(a, ":*")
	"*" in as_list(st.Resource)
	msg := sprintf("Service-wide %s on Resource \"*\"", [a])
}

deny contains msg if {
	some st in statements
	"iam:PassRole" in as_list(st.Action)
	"*" in as_list(st.Resource)
	not st.Condition
	msg := "iam:PassRole on any role without a Condition (privilege escalation risk)"
}

escalation := {"iam:CreatePolicyVersion", "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy"}

deny contains msg if {
	some st in statements
	some a in as_list(st.Action)
	a in escalation
	"*" in as_list(st.Resource)
	msg := sprintf("%s on Resource \"*\" lets the holder grant itself admin", [a])
}
