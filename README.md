# terraform-aws-org-keywatch

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Terraform](https://img.shields.io/badge/terraform-%3E%3D%201.0-blueviolet.svg)](https://developer.hashicorp.com/terraform)
[![AWS Provider](https://img.shields.io/badge/aws%20provider-~%3E%205.0-orange.svg)](https://registry.terraform.io/providers/hashicorp/aws/latest)

Detect access key misuse across an entire AWS Organization from a single
deployment in the management account — including accounts created after you
deploy.

The question this answers is not "was my access key used," which is unanswerable
noise when the answer is usually "yes, by me." It is **"was something dangerous
done, anywhere in the organization, and is my monitoring still alive."**

## What it does

Three layers, two of which cost nothing:

| Layer | What it answers | Latency | Optional |
|---|---|---|---|
| Dangerous-action alerter | Did anyone escalate privilege, blind the logs, change the organization, or spin up resources — in any account? | ~1 minute | No |
| Hourly heartbeat | What did each account do this hour, and is the monitoring itself still running? | Top of every hour | No |
| GuardDuty findings | Was a key used by someone whose behaviour doesn't match the baseline? | Minutes | Yes, **off by default** |

The heartbeat mails you even when nothing happened. That is deliberate: it makes
silence meaningful. An hour that never arrives means the function died or someone
disabled the logging it depends on, and a CloudWatch alarm with
`treat_missing_data = "breaching"` catches that directly.

## Read this before you apply

**This module must be applied from the AWS Organizations management account.**
The `aws_organizations_organization` data source fails anywhere else. That is a
deliberate guard, not a limitation — an organization trail cannot be created from
a member account.

**The blast radius is the whole organization.** Applying this creates an
organization CloudTrail, which begins logging management events for every member
account, present and future. Two consequences worth understanding before you run
it:

- **Member accounts with their own trail start paying.** Each AWS account gets
  one free copy of management events. This trail becomes that copy, so any
  pre-existing trail in a member account turns into a billable *second* copy for
  that account. Audit first:

  ```bash
  for p in <each-member-profile>; do
    echo -n "$p -> "
    AWS_PROFILE=$p aws cloudtrail describe-trails --query 'length(trailList)'
  done
  ```

- **Setting `guardduty_auto_enable_members = true` enables GuardDuty in every
  member account and bills per account.** Cost then scales with the size of your
  organization rather than staying flat.

**CloudTrail needs trusted access in Organizations first.** This is a one-time
CLI call, deliberately not managed by Terraform:

```bash
# Check
aws organizations list-aws-service-access-for-organization \
  --query 'EnabledServicePrincipals[].ServicePrincipal'

# Enable
aws organizations enable-aws-service-access \
  --service-principal cloudtrail.amazonaws.com
```

The only Terraform resource that could set it is
`aws_organizations_organization`, which would place your entire organization
under Terraform's control — and a misconfigured apply there can detach accounts.
A one-time CLI call is the safer trade.

## Usage

```hcl
module "keywatch" {
  source  = "niftyworx03/org-keywatch/aws"
  version = "~> 1.0"

  alert_email = "security@example.com"
  tags        = { owner = "security" }
}
```

AWS mails a subscription confirmation to `alert_email`. Nothing is delivered
until you click it, and Terraform reports the subscription as pending until then.

See [`examples/complete`](examples/complete) for a deployable root module,
including the `provider` block this module intentionally does not declare.

### Narrowing the scope

By default every principal in every account is in scope, which is the right
default when you own all the accounts. To watch specific long-lived keys only:

```hcl
module "keywatch" {
  source  = "niftyworx03/org-keywatch/aws"
  version = "~> 1.0"

  alert_email              = "security@example.com"
  monitored_access_key_ids = ["AKIAEXAMPLE1", "AKIAEXAMPLE2"]
}
```

### Adding behavioural detection

GuardDuty answers the question a hand-written list of event names cannot: was
this key used by someone who does not behave like its owner. It is the only
billable component, so it is off by default. Enable all three together:

```hcl
module "keywatch" {
  source  = "niftyworx03/org-keywatch/aws"
  version = "~> 1.0"

  alert_email = "security@example.com"

  create_guardduty_detector     = true
  enable_guardduty_alerts       = true
  guardduty_auto_enable_members = true # bills per member account
  min_guardduty_severity        = 4    # 4 is MEDIUM, 7 is HIGH
}
```

## Requirements

| Name | Version |
|---|---|
| terraform | >= 1.0 |
| aws | ~> 5.0 |
| archive | ~> 2.4 |

The provider must be configured with credentials for the organization management
account. This module declares no `provider` block, so it composes with provider
aliases and assume-role configurations.

<!-- BEGIN_TF_DOCS -->

## Inputs

| Name | Description | Type | Default | Required |
|---|---|---|---|:---:|
| alert\_email | Inbox that receives sensitive-call alerts and the hourly digest. Do not commit this. | `string` | n/a | **yes** |
| monitored\_access\_key\_ids | Long-lived access key IDs to narrow alerting to, across any account in the organization. Empty covers every principal. | `list(string)` | `[]` | no |
| dangerous\_event\_names | CloudTrail eventNames that alert immediately rather than waiting for the hourly digest. | `list(string)` | 37 names, see [variables.tf](variables.tf) | no |
| subscription\_filter\_pattern | Pre-filter applied by CloudWatch Logs before the alerter runs, keeping invocations off the read-only majority of volume. | `string` | `"{ $.readOnly IS FALSE \|\| $.readOnly NOT EXISTS }"` | no |
| create\_guardduty\_detector | Create a GuardDuty detector in this account. Set false if one already exists. | `bool` | `false` | no |
| enable\_guardduty\_alerts | Create the rule that mails GuardDuty findings. | `bool` | `false` | no |
| guardduty\_auto\_enable\_members | Become the organization's GuardDuty delegated administrator and auto-enable members. Multiplies cost by account count. | `bool` | `false` | no |
| min\_guardduty\_severity | Lowest GuardDuty severity that emails you. 4 is MEDIUM, 7 is HIGH. | `number` | `4` | no |
| heartbeat\_schedule | When the digest runs. | `string` | `"cron(0 * * * ? *)"` | no |
| heartbeat\_always\_send | Send the digest even when no account had activity. This is what makes silence meaningful. | `bool` | `true` | no |
| heartbeat\_lookback\_hours | Width of each digest window. Should match the schedule interval. | `number` | `1` | no |
| heartbeat\_lag\_minutes | How far the digest window trails real time, absorbing CloudTrail delivery delay. | `number` | `15` | no |
| trail\_retention\_days | How long trail objects live in S3 before expiring. | `number` | `90` | no |
| log\_retention\_days | Retention on the trail's CloudWatch Logs group. Bounds how far back the digest can look. | `number` | `30` | no |
| lambda\_log\_retention\_days | Retention for the two functions' own execution logs. | `number` | `14` | no |
| tags | Tags applied to every taggable resource. Merges with provider `default_tags`. | `map(string)` | `{}` | no |
| name\_prefix | Prefix for every resource name. | `string` | `"org-keywatch"` | no |

## Outputs

| Name | Description |
|---|---|
| organization\_id | The organization this trail covers. |
| covered\_account\_count | Accounts the organization trail logs today. New accounts are picked up automatically. |
| alert\_topic\_arn | Topic both functions and all alarms publish to. The email subscription needs manual confirmation. |
| trail\_log\_group | CloudWatch Logs group receiving every account's management events. |
| heartbeat\_function\_name | Invoke this manually to test without waiting for the top of the hour. |
| alerter\_function\_name | Triggered by the subscription filter, not directly. |
| guardduty\_detector\_id | Null unless `create_guardduty_detector` is true. |
| billable\_components | What in this stack can actually cost money. |

<!-- END_TF_DOCS -->

## Cost

Everything sits inside always-free tiers except S3, which CloudTrail requires:

| Component | Monthly cost | Basis |
|---|---|---|
| Organization CloudTrail | $0 | First copy of management events, per account |
| CloudWatch Logs ingestion | $0 | 5 GB/month, roughly 3.3M CloudTrail records |
| CloudWatch Logs API calls | $0 | 1M requests/month |
| Both Lambda functions | $0 | 1M requests and 400,000 GB-seconds |
| Scheduled EventBridge rule | $0 | Schedules are not billed |
| Three CloudWatch alarms | $0 | 10 alarms included |
| SNS email | $0 up to 1,000/month | The heartbeat uses 730 |
| S3 trail storage | Fractions of a cent | Bounded by `trail_retention_days` |
| GuardDuty | $0 while disabled | Bills **per member account** when enabled |

Three design choices keep that true, and changing any of them costs real money:

1. **The bucket uses `AES256`, not SSE-KMS.** A customer managed key is
   $1/month, which would be the largest single line item in the stack.
2. **The alerter sends one email per invocation, not per event.** Subscription
   filters arrive in batches, so a fifty-resource `terraform apply` becomes a
   handful of messages instead of fifty. This is what keeps SNS inside its
   1,000/month tier.
3. **No data events and no CloudTrail Insights.** Both are genuinely expensive;
   S3 data events in particular can produce orders of magnitude more volume than
   management events.

## Limitations

- **Detection, not prevention.** Nothing here stops a stolen key; it tells you
  to deactivate one. The real fix is to not hold long-lived keys at all — use IAM
  Identity Center and `aws sso login` for short-lived credentials. Treat this as
  the safety net underneath that.
- **Management events only.** Reading objects out of a bucket with a stolen key
  does not appear here without S3 data events, which are deliberately off on cost
  grounds.
- **The digest window trails real time by 15 minutes.** CloudTrail takes a few
  minutes to deliver into CloudWatch Logs, so a window ending at `now` would drop
  the newest calls and the next run would start after them. See
  `heartbeat_lag_minutes`.
- **`log_retention_days` bounds what the digest can see.** Keep it comfortably
  above `heartbeat_lookback_hours`.
- **The heartbeat caps each window at 400 events.** Past that, counts are
  reported as a floor with an explicit truncation notice rather than silently
  presenting the cap as a total.
- **Single region for the stack itself.** The trail is multi-region, but the log
  group, functions, and alarms live wherever your provider points.
- **No tamper-evident alert archive.** This is not a compliance control.

## Gotchas worth knowing if you fork this

- **The trail bucket policy needs two paths.** Organization trails write member
  logs under `AWSLogs/<org-id>/`, not `AWSLogs/<account-id>/`. A single-path
  policy looks correct and silently drops every member account.
- **The subscription filter must tolerate a missing `readOnly` field.** It is
  documented as optional, so `{ $.readOnly IS FALSE }` alone would never deliver
  such an event. Hence the `|| $.readOnly NOT EXISTS` clause.
- **Both functions filter out all three roles the module creates, not just their
  own two.** The trail delivery role is the one that catches people out: it is
  not intuitively "the function's own call", but CloudTrail assumes it to create
  log streams in the very group the digest reads, so leaving it in means the
  management account reports stack plumbing as activity every single hour.
- **AWS service principals are excluded from the digest as well as from
  alerting.** Two separate reasons. On deploy day, organization trail rollout
  shows up as `cloudtrail.amazonaws.com` issuing `PutEventSelectors` and
  `StartLogging` in every member account, which would match the anti-forensics
  rules. Forever after, CloudTrail polls the trail bucket's ACL about once a
  minute, which on a quiet organization dwarfs real activity and makes a genuine
  "quiet hour" impossible to ever report.
- **The two exclusions above are genuinely separate checks.** Bucket polling
  arrives as `type: AWSService`, while the delivery role arrives as
  `type: AssumedRole` with the service named only in `invokedBy` — so an
  AWS-service check alone silently misses half the noise.

## Development

The Lambda logic has offline tests that stub boto3, so they need no AWS account
and no credentials:

```bash
python3 tests/smoke_test.py
```

Validate the Terraform:

```bash
terraform init -backend=false && terraform validate
cd examples/complete && terraform init -backend=false && terraform validate
```

## Documentation

- [Design notes](docs/DESIGN.md) — why it is built this way, the per-account
  design that was abandoned, and what live verification revealed
- [Complete example](examples/complete) — deployable root module
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
