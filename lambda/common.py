"""Shared helpers for the organization-wide access key monitors.

Both functions read the same CloudTrail records out of the organization trail's
CloudWatch Logs group, so parsing, scoping, and formatting live here.
"""

import functools
import json
import os

import boto3

sns = boto3.client("sns")

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
SELF_ROLE_ARNS = [a for a in os.environ.get("SELF_ROLE_ARNS", "").split(",") if a]
MONITORED_KEY_IDS = [k for k in os.environ.get("ACCESS_KEY_IDS", "").split(",") if k]


@functools.lru_cache(maxsize=1)
def _account_names():
    """Account id to name, resolved once per container rather than per event."""
    try:
        organizations = boto3.client("organizations")
        paginator = organizations.get_paginator("list_accounts")
        return {
            account["Id"]: account["Name"]
            for page in paginator.paginate()
            for account in page["Accounts"]
        }
    except Exception:
        # Not the management account, or the permission was removed. Degrading
        # to bare account ids is better than failing the whole digest.
        return {}


def account_label(account_id):
    if not account_id:
        return "unknown"
    name = _account_names().get(account_id)
    return "{} ({})".format(name, account_id) if name else account_id


def parse(raw):
    """Normalise one CloudTrail record from a log event message."""
    event = json.loads(raw) if isinstance(raw, str) else raw
    identity = event.get("userIdentity", {})
    session_issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})

    return {
        "time": event.get("eventTime", ""),
        "account": event.get("recipientAccountId", ""),
        "name": event.get("eventName", ""),
        "action": "{}:{}".format(
            event.get("eventSource", "").split(".")[0], event.get("eventName", "")
        ),
        "who": identity.get("arn") or identity.get("userName") or identity.get("type", ""),
        "itype": identity.get("type", ""),
        "key": identity.get("accessKeyId", ""),
        "issuer": session_issuer.get("arn", ""),
        "ip": event.get("sourceIPAddress", ""),
        "region": event.get("awsRegion", ""),
        "error": event.get("errorCode", ""),
        # Absent readOnly counts as mutating: err toward showing the call.
        "readonly": bool(event.get("readOnly", False)),
    }


def is_self(call):
    """True for calls made by any role this stack creates.

    Without this the monitoring reports itself, and a quiet hour stops meaning
    "nothing happened".

    Covers the trail delivery role as well as the two function roles. CloudTrail
    assumes that role to create log streams in the group the digest reads, and
    those calls carry type AssumedRole with the service only in invokedBy, so
    is_aws_service does not catch them.
    """
    if call["issuer"] and call["issuer"] in SELF_ROLE_ARNS:
        return True

    return any(
        arn.rsplit("/", 1)[-1] in call["who"] for arn in SELF_ROLE_ARNS if arn and call["who"]
    )


def in_scope(call):
    """Honour ACCESS_KEY_IDS when set; otherwise every principal is in scope."""
    if not MONITORED_KEY_IDS:
        return True
    return call["key"] in MONITORED_KEY_IDS


def is_aws_service(call):
    """True for calls AWS made on your behalf rather than a principal's.

    No access key exists in these, so they are out of scope for a key-misuse
    monitor by definition. Two concrete reasons they have to go:

    Organization trail rollout appears as cloudtrail.amazonaws.com issuing
    PutEventSelectors and StartLogging in every member account, which would
    otherwise match the anti-forensics rules on the day you deploy.

    CloudTrail also polls the trail bucket's ACL about once a minute, which
    dwarfs real activity in the hourly counts on a quiet organization.
    """
    return call["itype"] == "AWSService"


# CloudTrail spells authorization failure several ways and services wrap it
# differently: AccessDeniedException, Client.UnauthorizedOperation. Substring
# matching means a new variant still counts instead of silently dropping out.
DENIAL_MARKERS = (
    "AccessDenied",
    "UnauthorizedOperation",
    "Forbidden",
    "AuthFailure",
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
)


def is_denial(call):
    """True only for authorization failures, not for any failure.

    A bucket with no CORS rule answers NoSuchCORSConfiguration on every
    Terraform refresh. Letting that share a section with real denials is how
    the section stops being read.
    """
    return any(marker in call["error"] for marker in DENIAL_MARKERS)


def relevant(call):
    """A real principal in scope: not this stack, and not AWS itself.

    Both functions use this, deliberately. Excluding AWS service calls from the
    digest matters as much as excluding them from alerts: CloudTrail checks the
    trail bucket's ACL roughly once a minute, so counting those means a
    genuinely idle hour still reports dozens of calls and the digest can never
    say "quiet hour" - which is the one thing it exists to be able to say.
    """
    return in_scope(call) and not is_self(call) and not is_aws_service(call)


def format_call(call):
    line = "  {}  {:<34}  {}  from {}".format(
        call["time"],
        call["action"],
        account_label(call["account"]),
        call["ip"] or "unknown",
    )
    if call["error"]:
        line += "  ERROR={}".format(call["error"])
    return line


REMEDIATION = [
    "Every call above should be one you can account for. If not, deactivate the",
    "key in the affected account:",
    "  aws iam update-access-key --access-key-id AKIA_YOUR_KEY --status Inactive",
]


def publish(subject, message):
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=message)
