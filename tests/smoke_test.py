"""Offline tests for both monitor functions.

Stubs boto3 so no AWS account or credentials are needed, then feeds realistic
payloads: a genuine gzipped base64 subscription-filter batch for the alerter,
and a synthetic FilterLogEvents page spanning two accounts for the heartbeat.

    python3 tests/smoke_test.py
"""
import base64, gzip, io, json, os, sys, types

MGMT_ROLE = "arn:aws:iam::999999999999:role/org-keywatch-heartbeat"
ALERT_ROLE = "arn:aws:iam::999999999999:role/org-keywatch-alerter"
TRAIL_ROLE = "arn:aws:iam::999999999999:role/org-keywatch-trail-to-logs"

os.environ.update({
    "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:999999999999:t",
    "SELF_ROLE_ARNS": "{},{},{}".format(ALERT_ROLE, MGMT_ROLE, TRAIL_ROLE),
    "DANGEROUS_EVENTS": "CreateUser,CreateAccessKey,StopLogging,RunInstances,PutEventSelectors",
    "LOG_GROUP_NAME": "/aws/cloudtrail/org-keywatch-org",
    "LOOKBACK_HOURS": "1",
    "LAG_MINUTES": "15",
})

ACCOUNTS = [
    {"Id": "111111111111", "Name": "sandbox"},
    {"Id": "222222222222", "Name": "production"},
    {"Id": "999999999999", "Name": "management"},
]

published = {}
FILTER_EVENTS = []


class FakePaginator:
    def __init__(self, kind): self.kind = kind
    def paginate(self, **kw):
        if self.kind == "list_accounts":
            yield {"Accounts": ACCOUNTS}
        else:
            yield {"events": [{"message": json.dumps(e)} for e in FILTER_EVENTS]}


class FakeClient:
    def __init__(self, name): self.name = name
    def get_paginator(self, op): return FakePaginator(op)
    def publish(self, **kw): published.clear(); published.update(kw)


fake = types.ModuleType("boto3")
fake.client = lambda name, *a, **k: FakeClient(name)
sys.modules["boto3"] = fake

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lambda"))
import alerter, heartbeat  # noqa: E402


def record(**kw):
    base = {
        "eventTime": "2026-09-08T12:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "recipientAccountId": "111111111111",
        "sourceIPAddress": "198.51.100.9",
        "awsRegion": "us-east-1",
        "userIdentity": {"arn": "arn:aws:iam::111111111111:user/dev", "accessKeyId": "AKIAGOOD"},
    }
    base.update(kw)
    return base


print("=" * 72)
print("ALERTER: batch of 3 dangerous calls across 2 accounts + 1 self call")
print("=" * 72)

log_events = [
    record(eventName="CreateUser"),
    record(eventName="CreateAccessKey", recipientAccountId="222222222222"),
    record(eventName="StopLogging", recipientAccountId="222222222222", errorCode="AccessDenied"),
    record(eventName="ListBuckets", readOnly=True),  # not dangerous -> ignored
    # the stack's own alerter role -> must be filtered out
    record(eventName="CreateUser", userIdentity={
        "type": "AssumedRole",
        "arn": "arn:aws:sts::999999999999:assumed-role/org-keywatch-alerter/x",
        "sessionContext": {"sessionIssuer": {"arn": ALERT_ROLE}},
    }),
    # AWS propagating the org trail into a member account, not a principal.
    # Dangerous by name, but alerting on it would fire on every deployment.
    record(eventName="PutEventSelectors", sourceIPAddress="cloudtrail.amazonaws.com",
           userIdentity={"type": "AWSService", "invokedBy": "cloudtrail.amazonaws.com"}),
]

payload = json.dumps({"logEvents": [{"message": json.dumps(e)} for e in log_events]})
buf = io.BytesIO()
with gzip.GzipFile(fileobj=buf, mode="wb") as fh:
    fh.write(payload.encode())
encoded = base64.b64encode(buf.getvalue()).decode()

result = alerter.lambda_handler({"awslogs": {"data": encoded}}, None)
print("RETURN:", result)
print("SUBJECT:", published["Subject"])
print("-" * 72)
print(published["Message"])

assert result["matched"] == 3, "expected 3 dangerous calls, got {}".format(result)
assert result["accounts"] == 2
assert "org-keywatch-alerter" not in published["Message"], "self call leaked"
assert "ListBuckets" not in published["Message"], "non-dangerous call leaked"
assert "PutEventSelectors" not in published["Message"], "AWS service call leaked"
assert "sandbox" in published["Message"], "account name not resolved"
assert "production" in published["Message"]
assert published["Subject"].startswith("AWS alert:")
assert len(published["Subject"]) <= 100

print()
print("=" * 72)
print("HEARTBEAT: multi-account window")
print("=" * 72)

FILTER_EVENTS[:] = [
    record(eventName="CreateUser"),
    record(eventName="ListBuckets", readOnly=True, eventSource="s3.amazonaws.com"),
    record(eventName="Decrypt", readOnly=True, eventSource="kms.amazonaws.com",
           errorCode="AccessDenied", recipientAccountId="222222222222"),
    record(eventName="FilterLogEvents", readOnly=True, userIdentity={
        "type": "AssumedRole",
        "arn": "arn:aws:sts::999999999999:assumed-role/org-keywatch-heartbeat/x",
        "sessionContext": {"sessionIssuer": {"arn": MGMT_ROLE}},
    }),
    # An error, but not an authorization one: every Terraform refresh of a
    # bucket with no CORS rule produces this. Must not reach the denials list.
    record(eventName="GetBucketCors", readOnly=True, eventSource="s3.amazonaws.com",
           errorCode="NoSuchCORSConfiguration"),
    # CloudTrail assuming the stack's own delivery role to create a stream in
    # the log group this function reads. Counts as mutating and recurs every
    # time CloudTrail rotates a stream, so leaving it in means the management
    # account never reports a quiet hour. Note type is AssumedRole, not
    # AWSService: only SELF_ROLE_ARNS can catch it.
    record(eventName="CreateLogStream", eventSource="logs.amazonaws.com",
           sourceIPAddress="cloudtrail.amazonaws.com",
           recipientAccountId="999999999999", userIdentity={
               "type": "AssumedRole",
               "invokedBy": "cloudtrail.amazonaws.com",
               "arn": "arn:aws:sts::999999999999:assumed-role/org-keywatch-trail-to-logs/x",
               "sessionContext": {"sessionIssuer": {"arn": TRAIL_ROLE}},
           }),
    # CloudTrail polling the trail bucket's ACL, roughly once a minute forever.
    # No principal credentials are involved, so it is out of scope for a
    # key-misuse monitor and must not inflate the counts.
    record(eventName="GetBucketAcl", readOnly=True, eventSource="s3.amazonaws.com",
           sourceIPAddress="cloudtrail.amazonaws.com",
           recipientAccountId="999999999999",
           userIdentity={"type": "AWSService", "invokedBy": "cloudtrail.amazonaws.com"}),
]

result = heartbeat.lambda_handler({}, None)
print("RETURN:", result)
print("SUBJECT:", published["Subject"])
print("-" * 72)
print(published["Message"])

assert result["events"] == 4, "self call not filtered: {}".format(result)
# Would be 2 if the trail delivery role leaked through, and the account count
# would be 3 because that call lands in the management account.
assert result["mutating"] == 1, "stack plumbing counted as activity: {}".format(result)
assert result["accounts"] == 2
assert result["truncated"] is False
assert "org-keywatch-heartbeat" not in published["Message"]
assert "org-keywatch-trail-to-logs" not in published["Message"], "delivery role leaked"
assert "CreateLogStream" not in published["Message"], "stack plumbing in the digest"
assert "GetBucketAcl" not in published["Message"], "AWS service call in the digest"
assert "Authorization denials:" in published["Message"]
assert "AccessDenied" in published["Message"], "real denial not surfaced"
assert "NoSuchCORSConfiguration" not in published["Message"], "benign 404 in denials"
assert "Failed calls : 2 (1 authorization denials)" in published["Message"]
assert "By account:" in published["Message"]

print()
print("=" * 72)
print("HEARTBEAT: window truncated at the event cap")
print("=" * 72)

# Shrunk rather than feeding 400 records: the behaviour under test is that the
# cap announces itself, not the size of the cap.
_cap = heartbeat.MAX_EVENTS
heartbeat.MAX_EVENTS = 2
FILTER_EVENTS[:] = [
    record(eventName="CreateUser"),
    record(eventName="CreateRole"),
    record(eventName="CreateKeyPair"),
]
result = heartbeat.lambda_handler({}, None)
print("RETURN:", result)
print("-" * 72)
print("\n".join(published["Message"].splitlines()[:10]))

assert result["truncated"] is True, "cap hit but not reported: {}".format(result)
assert result["events"] == 2
assert "API calls    : 2+" in published["Message"], "count not marked as a floor"
assert "event cap" in published["Message"], "no truncation notice in the mail"
heartbeat.MAX_EVENTS = _cap

print()
print("=" * 72)
print("HEARTBEAT: quiet hour, with the noise a real idle hour actually carries")
print("=" * 72)

# Deliberately not an empty window. A real idle hour still carries CloudTrail
# polling the bucket and the stack reading its own log group, and an empty
# fixture is why both of those leaked into production digests unnoticed. If any
# of the three below reaches the digest, the subject reads "N read-only call(s)"
# and the quiet hour this design is built around becomes unreachable.
FILTER_EVENTS[:] = [
    record(eventName="GetBucketAcl", readOnly=True, eventSource="s3.amazonaws.com",
           sourceIPAddress="cloudtrail.amazonaws.com",
           userIdentity={"type": "AWSService", "invokedBy": "cloudtrail.amazonaws.com"}),
    record(eventName="CreateLogStream", eventSource="logs.amazonaws.com",
           sourceIPAddress="cloudtrail.amazonaws.com", userIdentity={
               "type": "AssumedRole",
               "invokedBy": "cloudtrail.amazonaws.com",
               "arn": "arn:aws:sts::999999999999:assumed-role/org-keywatch-trail-to-logs/x",
               "sessionContext": {"sessionIssuer": {"arn": TRAIL_ROLE}},
           }),
    record(eventName="FilterLogEvents", readOnly=True, userIdentity={
        "type": "AssumedRole",
        "arn": "arn:aws:sts::999999999999:assumed-role/org-keywatch-heartbeat/x",
        "sessionContext": {"sessionIssuer": {"arn": MGMT_ROLE}},
    }),
]
result = heartbeat.lambda_handler({}, None)
print("RETURN:", result)
print("SUBJECT:", published["Subject"])
assert result["events"] == 0, "noise reached the digest: {}".format(result)
assert published["Subject"] == "AWS org heartbeat: quiet hour"
assert "Silence is the thing to react to" in published["Message"]

print()
print("=" * 72)
print("ALERTER: batch with nothing dangerous -> no mail")
print("=" * 72)
published.clear()
quiet = json.dumps({"logEvents": [{"message": json.dumps(record(eventName="TagRole"))}]})
buf = io.BytesIO()
with gzip.GzipFile(fileobj=buf, mode="wb") as fh:
    fh.write(quiet.encode())
result = alerter.lambda_handler(
    {"awslogs": {"data": base64.b64encode(buf.getvalue()).decode()}}, None)
print("RETURN:", result)
assert result == {"received": 1, "matched": 0, "ignored": ["TagRole"]}
assert not published, "should not have published"

print("\nALL ASSERTIONS PASSED")
