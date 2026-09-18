"""Hourly digest of access key activity across every account in the organization.

Sent every hour whether or not anything happened. On accounts this quiet the
normal answer is "nothing", which is what makes the empty message useful: an
hour that arrives is a positive statement that the pipeline still works, and an
hour that never arrives is itself the alert.

Reads the organization trail's CloudWatch Logs group, so one function covers
every member account, including accounts added later. Uses FilterLogEvents
rather than Logs Insights on purpose: Insights bills against the same 5 GB
allowance as ingestion, and plain filtering does not.
"""

import datetime as dt
import json
import os

import boto3

import common

logs = boto3.client("logs")

LOG_GROUP = os.environ["LOG_GROUP_NAME"]
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "1"))
LAG_MINUTES = int(os.environ.get("LAG_MINUTES", "15"))
ALWAYS_SEND = os.environ.get("ALWAYS_SEND", "true").lower() == "true"

MAX_EVENTS = 400
MAX_LISTED = 40


def collect(start, end):
    paginator = logs.get_paginator("filter_log_events")
    pages = paginator.paginate(
        logGroupName=LOG_GROUP,
        startTime=int(start.timestamp() * 1000),
        endTime=int(end.timestamp() * 1000),
    )

    calls = []
    for page in pages:
        for entry in page.get("events", []):
            call = common.parse(entry["message"])
            if not common.relevant(call):
                continue
            calls.append(call)
            # Pages arrive oldest first, so hitting the cap drops the newest
            # calls in the window. The caller has to say so rather than report
            # the ceiling as if it were the total.
            if len(calls) >= MAX_EVENTS:
                return calls, True
    return calls, False


def _per_account(calls):
    grouped = {}
    for call in calls:
        grouped.setdefault(call["account"], []).append(call)
    return grouped


def render(calls, start, end, truncated=False):
    mutating = [c for c in calls if not c["readonly"]]
    readonly = [c for c in calls if c["readonly"]]
    failures = [c for c in calls if c["error"]]
    denials = [c for c in calls if common.is_denial(c)]
    grouped = _per_account(calls)
    scope = ", ".join(common.MONITORED_KEY_IDS) or "all principals in the organization"

    lines = [
        "AWS organization access key heartbeat",
        "",
        "Window       : {:%Y-%m-%d %H:%M} to {:%Y-%m-%d %H:%M} UTC".format(start, end),
        "Scope        : {}".format(scope),
        "Accounts     : {} with activity".format(len(grouped)),
        "API calls    : {}{} ({} mutating, {} read-only)".format(
            len(calls), "+" if truncated else "", len(mutating), len(readonly)
        ),
        "Failed calls : {} ({} authorization denials)".format(len(failures), len(denials)),
        "",
    ]

    if truncated:
        lines += [
            "Counts stopped at the {} event cap, so the newest calls in this".format(MAX_EVENTS),
            "window are missing and every figure above is a floor, not a total.",
            "",
        ]

    if not calls:
        lines += [
            "No activity in any account in this window.",
            "",
            "This message is a heartbeat, not noise. If an hour passes with no mail",
            "at all, either this function stopped running or someone disabled the",
            "logging it depends on. Silence is the thing to react to.",
        ]
        return "\n".join(lines)

    lines.append("By account:")
    for account_id, account_calls in sorted(
        grouped.items(), key=lambda item: common.account_label(item[0])
    ):
        account_mutating = sum(1 for c in account_calls if not c["readonly"])
        lines.append(
            "  {:<40} {} calls, {} mutating".format(
                common.account_label(account_id), len(account_calls), account_mutating
            )
        )
    lines.append("")

    # Only authorization failures, not every errorCode. A run of AccessDenied is
    # what enumeration looks like; NoSuchCORSConfiguration is what Terraform
    # looks like, and mixing them is how the section stops being read.
    if denials:
        lines.append("Authorization denials:")
        lines += [common.format_call(c) for c in denials[:MAX_LISTED]]
        lines.append("")

    shown = mutating or readonly
    lines.append("Mutating calls:" if mutating else "Read-only calls:")
    lines += [common.format_call(c) for c in shown[:MAX_LISTED]]
    if len(shown) > MAX_LISTED:
        lines.append("  ... and {} more".format(len(shown) - MAX_LISTED))

    lines.append("")
    lines += common.REMEDIATION
    return "\n".join(lines)


def lambda_handler(event, context):
    # The window trails real time because CloudTrail takes a few minutes to
    # deliver into CloudWatch Logs. Ending at "now" would drop the newest calls,
    # and the next run's window starts after them, so they would never appear.
    end = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=LAG_MINUTES)
    start = end - dt.timedelta(hours=LOOKBACK_HOURS)

    calls, truncated = collect(start, end)
    mutating = sum(1 for c in calls if not c["readonly"])
    accounts = len(_per_account(calls))

    # Logged with the window because an empty digest is ambiguous otherwise:
    # a quiet hour and a window that predates the trail's first delivery both
    # return zero events.
    def log(result):
        print(json.dumps(dict(result, window="{:%Y-%m-%d %H:%M} to {:%H:%M} UTC".format(start, end))))
        return result

    if not calls and not ALWAYS_SEND:
        return log({"sent": False, "events": 0})

    if mutating:
        subject = "AWS org heartbeat: {} mutating call(s) across {} account(s)".format(
            mutating, accounts
        )
    elif calls:
        subject = "AWS org heartbeat: {} read-only call(s)".format(len(calls))
    else:
        subject = "AWS org heartbeat: quiet hour"

    common.publish(subject, render(calls, start, end, truncated))
    return log({
        "sent": True,
        "events": len(calls),
        "mutating": mutating,
        "accounts": accounts,
        "truncated": truncated,
    })
