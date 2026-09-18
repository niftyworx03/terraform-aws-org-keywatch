"""Immediate alert on sensitive API calls anywhere in the organization.

Fed by a CloudWatch Logs subscription filter on the organization trail's log
group. The filter pre-selects mutating calls; this narrows them to the list of
event names worth waking up for.

Sends one mail per invocation, never one per event. Subscription filters deliver
in batches, so a fifty-resource terraform apply arrives as a handful of
invocations rather than fifty emails, which is what keeps the stack inside the
SNS free tier.
"""

import base64
import gzip
import io
import json
import os

import common

DANGEROUS = {n.strip() for n in os.environ.get("DANGEROUS_EVENTS", "").split(",") if n.strip()}

MAX_LISTED = 40


def _decode(event):
    """Subscription filter payloads arrive gzipped and base64 encoded."""
    raw = base64.b64decode(event["awslogs"]["data"])
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as handle:
        return json.loads(handle.read().decode("utf-8"))


def render(calls, accounts):
    lines = [
        "Sensitive API calls detected in your AWS organization",
        "",
        "Matched  : {}".format(len(calls)),
        "Accounts : {}".format(", ".join(accounts)),
        "",
    ]

    lines += [common.format_call(call) for call in calls[:MAX_LISTED]]
    if len(calls) > MAX_LISTED:
        lines.append("  ... and {} more".format(len(calls) - MAX_LISTED))

    lines.append("")
    lines += common.REMEDIATION
    return "\n".join(lines)


def subject_for(calls, accounts):
    if len(calls) == 1:
        return "AWS alert: {} in {}".format(calls[0]["name"], accounts[0])

    names = sorted({call["name"] for call in calls})
    if len(names) == 1:
        return "AWS alert: {} x {} in {}".format(len(calls), names[0], ", ".join(accounts))

    return "AWS alert: {} sensitive calls in {}".format(len(calls), ", ".join(accounts))


def lambda_handler(event, context):
    payload = _decode(event)
    entries = payload.get("logEvents", [])

    calls = []
    seen = []
    for entry in entries:
        call = common.parse(entry["message"])
        seen.append(call["name"])
        if call["name"] in DANGEROUS and common.relevant(call):
            calls.append(call)

    result = {"received": len(entries), "matched": len(calls)}

    if not calls:
        # The names that arrived but did not match are the whole diagnostic for
        # a silent alerter: they distinguish "the filter is delivering the wrong
        # events" from "DANGEROUS_EVENTS is missing one".
        result["ignored"] = sorted(set(seen))[:MAX_LISTED]
        print(json.dumps(result))
        return result

    calls.sort(key=lambda call: call["time"])
    accounts = sorted({common.account_label(call["account"]) for call in calls})

    common.publish(subject_for(calls, accounts), render(calls, accounts))
    result["accounts"] = len(accounts)
    print(json.dumps(result))
    return result
