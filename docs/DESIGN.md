# Design notes

Author: GASAE Student I

Why this module is shaped the way it is, what it was built against, and what was
learned running it. The [README](../README.md) covers how to use it; this covers
why it exists in this form.

## The problem

A small AWS Organization with segregated accounts for development, production,
and sandbox work. Each account holds a long-lived IAM access key so it can be
driven from the CLI and from Terraform.

Long-lived keys are the credential type that leaks: committed to a repository,
pasted into a terminal, left in a dotfile, scraped from a public bucket.
Automated scanners find exposed keys within minutes, and the first thing an
attacker does with one is create persistence and spin up compute.

Two things make this hard to solve naively.

**A leaked key and a legitimate one look identical if you only ask whether the
key was used.** "The key was used" carries no signal, because most of the time
the answer is "yes, by the owner." Any control built on that premise produces
alerts nobody can triage, and a control nobody triages is decoration.

**It is a multi-account problem.** A control deployed into one account leaves
the others blind, and the production account is usually the one that matters
most. Deploying the same control five times means five things to maintain, plus
a sixth thing to remember every time an account is created.

There was also a hard constraint: this runs on personal money, in accounts that
are barely used. It has to cost nothing. A security control switched off because
of the bill is not a control.

## Requirements

| | Requirement |
|---|---|
| R1 | Alert within minutes when a sensitive API call is made in **any** account in the organization — identity persistence, privilege escalation, disabling logging, or creating compute — not merely when a key is used. |
| R2 | Cover every account from one deployment, and pick up newly created accounts with no code change. |
| R3 | Report hourly on what each account did, and make the **absence** of that message meaningful, so a broken or sabotaged control is itself visible. |
| R4 | Detect the case where the monitoring is deliberately blinded, since that is the first move of an attacker who understands the environment. |
| R5 | Express the whole control as infrastructure as code: declarative, idempotent, reviewable, removable in one command. |
| R6 | Stay inside AWS always-free tiers. |
| R7 | Do not report the monitoring's own activity, and do not turn a burst of legitimate activity into a burst of mail. |

R1 is the reframe that makes the whole thing tractable: from "was the key used"
to "was something dangerous done." The second question is answerable and has a
low false positive rate. R3 covers the remaining space at a cadence a human can
actually read, and its dead-man's-switch property closes the gap R4 describes.
R2 is what makes the control durable rather than something deployed once and
never extended.

## How the design meets them

### R1 — Near-real-time sensitive-call alerting

`cloudtrail.tf` delivers the organization trail into a CloudWatch Logs group.
`detect.tf` attaches a subscription filter, pre-filtered to mutating calls, which
invokes `lambda/alerter.py`. That function matches against 37 event names in four
families:

- **Privilege escalation** — `CreateAccessKey`, `AttachUserPolicy`, `CreateLoginProfile`
- **Anti-forensics** — `StopLogging`, `DeleteTrail`, `DeleteSubscriptionFilter`
- **Organization-level change** — `LeaveOrganization`, `RemoveAccountFromOrganization`, `DetachPolicy`
- **Cost or exposure** — `RunInstances`, `PutBucketPolicy`, `DeletePublicAccessBlock`

The organization family exists only because this is a multi-account deployment.
Detaching a service control policy or removing an account from the organization
is how an attacker escapes centralized guardrails, and neither is visible to a
control that watches a single account.

The event-name list deliberately lives in the function rather than in the filter
pattern, because CloudWatch Logs caps filter patterns at 1024 characters and this
list would consume an unreasonable share of that budget.

### R2 — One deployment, whole organization, future-proof

`is_organization_trail = true`. Every member account's management events land in
one log group, each record tagged with `recipientAccountId`. Accounts created
later are covered with no Terraform change. The `covered_account_count` output
reports how many accounts are in scope today.

This was a deliberate revision, not the first design. The first version deployed
per account and would have required N trails, N functions, and an apply per new
account. Moving to an organization trail forced two mechanism swaps, because both
originals are scoped to the calling account only:

| Per-account mechanism | Replaced by | Why |
|---|---|---|
| CloudTrail to EventBridge | CloudWatch Logs subscription filter | CloudTrail events reach EventBridge only in the account that generated them |
| `cloudtrail:LookupEvents` | `logs:FilterLogEvents` | LookupEvents only ever returns the calling account's history |

### R3 — Hourly heartbeat with meaningful silence

`heartbeat.tf` schedules `lambda/heartbeat.py` at `cron(0 * * * ? *)`. It queries
the trail log group for the previous hour, groups results by account, resolves
account IDs to names via `organizations:ListAccounts`, and separates mutating
calls, read-only calls, and denied calls. Denied calls get their own section
because a run of `AccessDenied` is what enumeration looks like.

It sends even when every account was quiet. That is the design, not an oversight:
silence then means the control is broken rather than that nothing happened.

One implementation detail worth stating plainly. The query window trails real
time by 15 minutes, because CloudTrail takes a few minutes to deliver into
CloudWatch Logs. A window ending at "now" would miss the newest calls, and the
following run's window begins after them — so those calls would never be reported
at all, by either run.

### R4 — Detecting a blinded control

Three mechanisms, because the failure modes are different:

1. `StopLogging`, `DeleteTrail`, `PutEventSelectors`, and
   `DeleteSubscriptionFilter` are on the immediate-alert list, so tampering
   alerts rather than going quiet.
2. A CloudWatch alarm on the heartbeat's `Invocations` metric with
   `treat_missing_data = "breaching"` fires if the digest has not run for two
   hours. Missing data *is* the condition here, which is why the default
   treatment would be wrong.
3. Alarms on both functions' `Errors` metrics catch a function that runs but
   fails, which is otherwise invisible — a silently failing alerter is worse than
   a noisy one.

### R5 — Infrastructure as code

Terraform 1.x with `hashicorp/aws ~> 5.0`. `plan` and `apply` are idempotent; a
second apply creates nothing. `destroy` removes everything including the trail
bucket, which is `force_destroy` so teardown actually completes rather than
stalling on a non-empty bucket.

### R6 — Zero cost

The organization trail is the free first copy of management events for every
account. CloudWatch Logs ingestion of a few megabytes a month sits against a
5 GB always-free allowance, roughly 3.3 million CloudTrail records. Both
functions run inside the 1M request and 400,000 GB-second free tier. Three alarms
sit inside the free ten. SNS covers 1,000 emails a month and the heartbeat uses
730.

Three choices protect that, and reversing any of them costs real money:

1. The trail bucket uses `AES256` rather than SSE-KMS. A customer managed key at
   $1/month would be the single largest cost in the stack.
2. No data events and no CloudTrail Insights. S3 data events in particular can
   produce orders of magnitude more volume than management events.
3. GuardDuty defaults to off. It is the only genuinely billable component, and
   enabling it organization-wide bills per member account rather than once.

### R7 — Not reporting on itself, and not flooding

Both functions apply one shared filter that drops three things: calls outside
scope, calls by **any** role this module creates, and calls AWS made itself.

Two of those need spelling out, because each was originally wrong and each
failure was invisible from the code alone.

**All three roles, not just the two Lambda ones.** The module creates a third
role that CloudTrail assumes to write log streams into the group the digest
reads. Omitting it means the monitoring reports its own plumbing, and the
management account can never report an idle hour.

**AWS service principals, in the digest as well as in alerts.** No access key
exists in a service call, so it is out of scope for a key-misuse monitor by
definition. The volume argument is the stronger one: CloudTrail polls the trail
bucket's ACL roughly once a minute.

These have to be two separate checks rather than one, because the noise arrives
under two different identity shapes. Bucket polling is `type: AWSService`. The
delivery role writing log streams is `type: AssumedRole`, with the service named
only in `invokedBy` — so an AWS-service check alone does not catch it, and a
role check alone does not catch the other.

The alerter sends one email per invocation summarising the whole batch rather
than one per event. Subscription filters deliver in batches, so a Terraform apply
creating fifty IAM resources produces a handful of messages instead of fifty.
This is both an alert-fatigue control and the specific thing that keeps the stack
inside the SNS free tier.

## Testing

`tests/smoke_test.py` stubs boto3 so it needs no AWS account, then exercises both
functions against realistic payloads: a genuine gzipped, base64-encoded
subscription-filter batch for the alerter, and a synthetic `FilterLogEvents` page
spanning two accounts for the heartbeat.

It asserts that calls from all three of the module's roles are filtered,
including the trail delivery role; that AWS service principals neither alert nor
reach the digest; that non-dangerous calls do not alert; that account IDs resolve
to names; that genuine authorization denials surface while benign "no such
configuration" errors do not; and that hitting the event cap is reported as a
floor rather than a total.

**The quiet-hour case deliberately does not use an empty window.** It feeds the
three things a real idle hour actually carries — CloudTrail polling the bucket
ACL, the delivery role creating a log stream, and the heartbeat's own
`FilterLogEvents` — and asserts the digest still reports zero events and a
"quiet hour" subject. An empty fixture passes whether or not the filtering works,
which is exactly how both filtering bugs reached a running deployment. A test
that cannot fail proves nothing, so each of these was checked by reintroducing
the bug and confirming the assertion fires.

## Verification against a live organization

The stack was deployed, not merely written. Applied to a management account with
four member accounts; `covered_account_count` reported 4.

It was then **torn down and rebuilt from this module**, rather than only ever
existing as the hand-written original. The destroy removed 28 resources and the
rebuild created 28, with no drift in either direction. That equivalence is the
thing worth verifying before asking anyone else to apply it: the module stands
up the whole control from nothing.

**R2 is confirmed by the log group's stream names.** One group in the management
account holds a stream per member account, each prefixed with the organization ID
and containing that account's own ID. The set of account IDs appearing as streams
matches the organization's account list exactly. That is the central claim of the
design: member-account events reaching one place without anything being deployed
into the member accounts.

**R1 was proved with a canary rather than an assertion, and from a member
account rather than the management account.** That distinction is the point — a
canary in the management account would have proved the alerter works, but not
that it works for the accounts a per-account deployment would have left blind. A
throwaway IAM user was created in a sandbox member account and deleted
immediately:

```
09:51:47 UTC  CreateUser in the member account, recorded by the organization
              trail with readOnly=false and the originating account id
09:51:50 UTC  DeleteUser, same principal
09:54:02 UTC  alerter logged {"received": 2, "matched": 1, "accounts": 1}
              and published
same minute   SNS reported 1 published, 1 delivered, 0 failed; the mail
              arrived naming the member account, not the management account
```

`matched: 1` out of two events is correct rather than a miss: `CreateUser` is on
the list and `DeleteUser` is not, because the list covers creation, privilege
escalation, and defense evasion rather than cleanup.

Roughly two and a quarter minutes end to end, against a trail created minutes
earlier. The same canary on a warmed-up trail completed in under thirty seconds,
so treat the cold number as a floor on freshness rather than the steady state.

### Three things the design documentation would not have predicted

**First delivery lags far behind steady state, and by an inconsistent amount.**
CloudTrail's first delivery into CloudWatch Logs lagged roughly 17 minutes behind
trail creation on one deployment and about 3 minutes on the rebuild, against a
steady state of roughly 30 seconds. Plan for the slow case; you do not get to
predict which one you will get. The early lag is a one-time warm-up,
not the ongoing latency. It matters only in that a digest run scheduled inside
that window legitimately reports nothing — and distinguishing that from a broken
control is precisely why both functions now log their result and their query
window. That logging exists because, from the deployed stack alone, there was no
way to tell whether a silent alerter had matched nothing or failed to run.

**The logging paid off immediately.** Re-deploying the functions produced this
line from the alerter:

```json
{"received": 2, "matched": 0, "ignored": ["UpdateFunctionCode20150331v2"]}
```

The stack observed its own code being updated and correctly declined to alert.
That is R7 and the precision of the event-name list demonstrated in a single
record, and it is exactly the distinction that was invisible before.

**R7 was wrong twice, and only reading a digest revealed it.** The filter was
written to drop the monitoring's own calls, the tests asserted it did, and the
tests passed. Both statements were true and the requirement was still not met.

An hour of a four-account organization with nobody working in it was measured
directly:

| Source | Events | |
|---|---|---|
| AWS service principals | 76 | 67 of them CloudTrail polling the trail bucket's ACL |
| The module's own roles | 10 | including the delivery role, which was not being filtered |
| Real principals | 17 | the only rows worth a human's attention |
| **Total** | **103** | |

Two separate defects. The digest reported the trail delivery role's
`CreateLogStream` calls as organization activity, so one digest announced five
mutating calls when two were real. And it counted AWS's own calls, so an idle
hour would still have reported dozens and the subject line could never have read
"quiet hour" — the single signal R3 exists to produce.

Neither was visible in code review, in `terraform plan`, or in a passing test
suite. Both were obvious within seconds of reading an actual email. The root
cause in the tests was the same in both cases: the quiet-hour fixture used an
empty window, and a real quiet hour is never empty. That fixture is now
deliberately full of exactly this noise.

All three CloudWatch alarms reported OK, so the dead-man's switch of R4 was armed
rather than merely configured. On a fresh deployment the `heartbeat-missing`
alarm goes straight from `INSUFFICIENT_DATA` to `OK` if the digest is invoked
manually before its first scheduled run, which is worth doing: otherwise
`treat_missing_data = "breaching"` produces one spurious alarm mail and a
recovery notice in the first couple of hours.

## What this is not

**It does not prevent anything.** A stolen key still works until it is
deactivated; this tells you to deactivate it. The honest fix is to stop holding
long-lived keys and use IAM Identity Center for short-lived credentials. Treat
this as the safety net underneath that, built because the keys exist today.

**It cannot see data-plane activity, only management events.** Reading objects
out of a bucket with a stolen key would not appear here without enabling S3 data
events, which are deliberately left off on cost grounds.

**It is not a compliance control.** There is no evidence retention story beyond
the S3 lifecycle rule, and no tamper-evident archive of alerts.
