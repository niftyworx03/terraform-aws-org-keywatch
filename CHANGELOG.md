# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For a Terraform module, the semver contract is the module's interface: variables,
outputs, and the set of resources it manages. A change that forces replacement of
an existing resource is breaking even if no variable changed, because it destroys
state a consumer already has.

## [Unreleased]

## [1.0.0] - 2026-09-18

Initial release.

### Added

- Organization-wide CloudTrail delivering management events from every member
  account into a single CloudWatch Logs group in the management account. New
  accounts are covered automatically with no Terraform change.
- Near-real-time alerter invoked by a CloudWatch Logs subscription filter,
  matching 37 CloudTrail event names across four families: privilege escalation,
  anti-forensics, organization-level change, and cost or data exposure.
- Hourly heartbeat digest grouped by account, with account IDs resolved to names,
  and mutating, read-only, and denied calls reported separately. Sends even when
  every account was quiet, so silence becomes meaningful.
- Dead-man's-switch alarm on the heartbeat's `Invocations` metric using
  `treat_missing_data = "breaching"`, plus `Errors` alarms on both functions.
- Optional GuardDuty integration with organization-wide delegated administration
  and member auto-enablement, off by default because it is the only billable
  component and bills per member account.
- Single SNS topic carrying alerts, the digest, and alarm notifications.
- Offline test suite that stubs `boto3`, requiring no AWS account.
- `tags` variable applied to every taggable resource, merging with provider-level
  `default_tags`.
- `examples/complete` as a deployable root module.

### Design notes

Documented in full in [docs/DESIGN.md](docs/DESIGN.md). The decisions most likely
to surprise:

- **Alerting is on dangerous actions, not on key usage.** "The key was used"
  carries no signal when the answer is usually "yes, by me."
- **Event names are matched in the Lambda, not the subscription filter.**
  CloudWatch Logs caps filter patterns at 1024 characters.
- **The digest window trails real time by 15 minutes.** CloudTrail takes minutes
  to reach CloudWatch Logs, so a window ending at `now` would drop the newest
  calls permanently — the next run starts after them.
- **The trail bucket policy carries two prefixes.** Organization trails write
  member logs under `AWSLogs/<org-id>/`, so a single-prefix policy silently drops
  every member account.
- **The subscription filter tolerates a missing `readOnly` field**, which is
  documented as optional and would otherwise never be delivered.
- **Both functions apply the same filter, and it excludes three things: calls
  outside scope, calls by any role this module creates, and calls AWS made
  itself.** A quiet hour is the signal this design is built on, and on a real
  organization an idle hour is far from empty. Measured over one hour on a
  four-account organization doing nothing: 103 events, of which 76 were AWS
  service principals — 67 of those CloudTrail polling its own trail bucket's
  ACL about once a minute — and 10 were the stack's own roles. Only 17 came
  from a principal. Two distinct exclusions are needed because the noise
  arrives under two different identity shapes: bucket polling is
  `type: AWSService`, while the trail's delivery role writing log streams is
  `type: AssumedRole` with the service only in `invokedBy`, so the
  AWS-service check alone does not catch it.
- **The alerter batches one email per invocation.** This is both an alert-fatigue
  control and what keeps the stack inside the SNS free tier.
- **Zero cost at default settings** is a constraint, not a coincidence. AES256
  rather than SSE-KMS, no data events, no CloudTrail Insights, GuardDuty off.

[Unreleased]: https://github.com/niftyworx03/terraform-aws-org-keywatch/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/niftyworx03/terraform-aws-org-keywatch/releases/tag/v1.0.0
