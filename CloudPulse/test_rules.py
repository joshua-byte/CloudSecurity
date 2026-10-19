"""Offline smoke tests for all 17 CloudPulse rules.
Run from D:\\CloudPulse with: python test_rules.py
This script creates synthetic events in memory and does not modify project logs or alerts.csv.
"""
import json
from datetime import datetime, timedelta
import pandas as pd
import rules

RULES = {rule["id"]: rule for rule in rules.load_rules()}
results = []


def event(rule_id, *, name=None, source=None, user="alice", user_type="IAMUser",
          params=None, error="", mfa="", failure=False, source_ip="203.0.113.10",
          extra=None):
    rule = RULES[rule_id]
    detection = rule.get("detection", {})
    if name is None:
        expected = detection.get("eventName", "")
        name = expected[0] if isinstance(expected, list) else expected
    if source is None:
        source = detection.get("eventSource", "")
    row = {
        "time": "2026-04-04 16:59:01+00:00",
        "eventID": f"synthetic-{rule_id}",
        "eventSource": source,
        "eventName": name,
        "user": f"arn:aws:iam::123456789012:user/{user}",
        "userType": user_type,
        "sourceIP": source_ip,
        "requestParameters": json.dumps(params or {}),
        "errorCode": error,
        "mfaUsed": mfa,
        "is_failure": failure,
    }
    if extra:
        row.update(extra)
    return row


def check(label, actual, expected=True):
    passed = actual == expected
    results.append((label, passed, actual, expected))


def single(rule_id, row=None):
    if row is None:
        row = event(rule_id)
    return rules.matches_rule(row, RULES[rule_id])


# ACCESS-001: root API activity (not ConsoleLogin)
check("ACCESS-001 root API activity", single("ACCESS-001", event(
    "ACCESS-001", user="root", user_type="Root", name="ListBuckets", source="s3.amazonaws.com")))
# ACCESS-002: successful console login without MFA
check("ACCESS-002 console login without MFA", single("ACCESS-002", event(
    "ACCESS-002", name="ConsoleLogin", source="signin.amazonaws.com", mfa="no", failure=False)))
# ACCESS-003: root console login
check("ACCESS-003 root console login", single("ACCESS-003", event(
    "ACCESS-003", user="root", user_type="Root", name="ConsoleLogin", source="signin.amazonaws.com")))

# ACCESS-004: six failed console logins from the same user/IP within ten minutes
failed_login_rows = []
for i in range(6):
    row = event("ACCESS-004", name="ConsoleLogin", source="signin.amazonaws.com",
                failure=True, source_ip="198.51.100.20")
    row["time"] = f"2026-04-04 16:{50+i:02d}:00+00:00"
    row["eventID"] = f"synthetic-login-{i}"
    failed_login_rows.append(row)
login_matches = rules.threshold_matches(pd.DataFrame(failed_login_rows), RULES["ACCESS-004"])
check("ACCESS-004 failed-login threshold", len(login_matches) > 0)

# ACCESS-005: eleven access-denied errors for one user within five minutes
denied_rows = []
denied_start = datetime.fromisoformat("2026-04-04T16:55:00+00:00")
for i in range(11):
    row = event("ACCESS-005", name="GetObject", source="s3.amazonaws.com", error="AccessDenied")
    row["time"] = (denied_start + timedelta(seconds=20 * i)).isoformat(sep=" ")
    row["eventID"] = f"synthetic-denied-{i}"
    denied_rows.append(row)
denied_matches = rules.threshold_matches(pd.DataFrame(denied_rows), RULES["ACCESS-005"])
check("ACCESS-005 access-denied threshold", len(denied_matches) > 0)

# IAM-001: self-targeted inline wildcard policy
wildcard_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
check("IAM-001 self wildcard policy", single("IAM-001", event(
    "IAM-001", name="PutUserPolicy", source="iam.amazonaws.com",
    user="alice", params={"userName": "alice", "policyDocument": json.dumps(wildcard_policy)})))
# IAM-002: actor creates a key for another user
check("IAM-002 cross-identity key creation", single("IAM-002", event(
    "IAM-002", name="CreateAccessKey", source="iam.amazonaws.com",
    user="alice", params={"userName": "bob"})))
# IAM-003: privileged managed policy attachment
check("IAM-003 admin policy attachment", single("IAM-003", event(
    "IAM-003", name="AttachUserPolicy", source="iam.amazonaws.com",
    params={"userName": "bob", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})))
# IAM-004: new policy version set as default
check("IAM-004 policy version escalation", single("IAM-004", event(
    "IAM-004", name="CreatePolicyVersion", source="iam.amazonaws.com",
    params={"policyArn": "arn:aws:iam::123456789012:policy/Test", "setAsDefault": True})))
# IAM-005: console login profile created
check("IAM-005 login profile creation", single("IAM-005", event(
    "IAM-005", name="CreateLoginProfile", source="iam.amazonaws.com",
    params={"userName": "bob"})))

# LOG rules
check("LOG-001 CloudTrail StopLogging", single("LOG-001", event(
    "LOG-001", name="StopLogging", source="cloudtrail.amazonaws.com")))
check("LOG-002 CloudTrail DeleteTrail", single("LOG-002", event(
    "LOG-002", name="DeleteTrail", source="cloudtrail.amazonaws.com")))
check("LOG-003 CloudTrail UpdateTrail", single("LOG-003", event(
    "LOG-003", name="UpdateTrail", source="cloudtrail.amazonaws.com")))
check("LOG-004 GuardDuty DeleteDetector", single("LOG-004", event(
    "LOG-004", name="DeleteDetector", source="guardduty.amazonaws.com")))

# SG rules: request parameters reflect common CloudTrail ingress structures
sg_public_sensitive = {
    "ipPermissions": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
                        "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}]
}
sg_public_all = {
    "ipPermissions": [{"ipProtocol": "-1", "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}]
}
check("SG-001 public sensitive port", single("SG-001", event(
    "SG-001", name="AuthorizeSecurityGroupIngress", source="ec2.amazonaws.com",
    params=sg_public_sensitive)))
check("SG-002 public all-protocol ingress", single("SG-002", event(
    "SG-002", name="AuthorizeSecurityGroupIngress", source="ec2.amazonaws.com",
    params=sg_public_all)))
check("SG-003 security group deletion", single("SG-003", event(
    "SG-003", name="DeleteSecurityGroup", source="ec2.amazonaws.com",
    params={"groupId": "sg-0123456789abcdef0"})))

# Negative controls for important false-positive cases
check("Negative: IAM-001 different target", single("IAM-001", event(
    "IAM-001", name="PutUserPolicy", source="iam.amazonaws.com",
    user="alice", params={"userName": "bob", "policyDocument": json.dumps(wildcard_policy)})), False)
check("Negative: IAM-001 ordinary action", single("IAM-001", event(
    "IAM-001", name="PutUserPolicy", source="iam.amazonaws.com",
    user="alice", params={"userName": "alice", "policyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})})), False)
check("Negative: IAM-002 same target", single("IAM-002", event(
    "IAM-002", name="CreateAccessKey", source="iam.amazonaws.com",
    user="alice", params={"userName": "alice"})), False)

print("CLOUDPULSE RULE TESTS (synthetic events; real logs unchanged)")
for label, passed, actual, expected in results:
    print(f"{'PASS' if passed else 'FAIL'}: {label}")

passed_count = sum(1 for _, passed, _, _ in results if passed)
print(f"\nResult: {passed_count}/{len(results)} tests passed")
if passed_count != len(results):
    print("Failed tests:")
    for label, passed, actual, expected in results:
        if not passed:
            print(f" - {label}: expected {expected!r}, got {actual!r}")
    raise SystemExit(1)
