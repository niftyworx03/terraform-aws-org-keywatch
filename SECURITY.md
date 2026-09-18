# Security policy

## Reporting a vulnerability

**Please do not report security issues in public issues, pull requests, or
discussions.**

Use GitHub's private vulnerability reporting instead:

1. Go to the [Security tab](https://github.com/niftyworx03/terraform-aws-org-keywatch/security)
2. Click **Report a vulnerability**
3. Describe the issue, the impact, and how to reproduce it

That channel is private between you and the maintainers, and it is the only
private channel this project exposes. There is deliberately no email address
here — one fewer address to harvest, and reports stay attached to the repository
where they can be tracked and credited.

If you cannot use it for any reason, open a public issue that says only "I need
to report a security issue privately, please advise," with no details.

## What to expect

This is a volunteer-maintained project, so these are intentions rather than
contractual commitments:

| Stage | Target |
|---|---|
| Acknowledgement | Within 7 days |
| Initial assessment | Within 14 days |
| Fix or documented mitigation | Depends on severity; critical issues first |

You will be credited in the advisory and the changelog unless you ask not to be.

## Supported versions

The latest minor release receives security fixes. Older versions do not.

| Version | Supported |
|---|---|
| 1.x | Yes |
| < 1.0 | No |

## In scope

Issues in the code in this repository:

- Overly broad IAM policies in the roles this module creates
- The trail S3 bucket policy permitting writes it should not
- The SNS topic policy permitting publishes from unintended principals
- Detection bypasses — a way to perform an action on the
  `dangerous_event_names` list without the alerter firing
- A way to suppress or blind the heartbeat without the dead-man's-switch alarm
  firing
- Sensitive values written to logs or into Terraform outputs unexpectedly

Detection bypasses are the most interesting class, since the module's entire
value is that an alert arrives.

## Out of scope

- **Vulnerabilities in AWS services, Terraform, or the AWS provider.** Report
  those to the relevant vendor. AWS accepts reports at
  [aws.amazon.com/security/vulnerability-reporting](https://aws.amazon.com/security/vulnerability-reporting/).
- **The module not preventing an attack.** This is a detective control by
  design. A stolen key keeps working until you deactivate it; the module's job is
  to tell you to. See the Limitations section of the [README](README.md).
- **Blind spots that are documented consequences of the cost model.** S3 data
  events are off deliberately, so data-plane activity is invisible. GuardDuty is
  off by default. Both are stated in the README.
- **A misconfigured deployment.** Applying from the wrong account, not confirming
  the SNS subscription, or setting `heartbeat_always_send = false` and then
  expecting the dead-man's switch to work are configuration problems, not
  vulnerabilities. Documentation gaps that make such a mistake likely are welcome
  as ordinary issues.

## A note on your own deployment

If you suspect an access key in your own AWS account is compromised, this
repository is not the place to report it. Deactivate the key first, then contact
AWS Support:

```bash
aws iam update-access-key --access-key-id AKIA_YOUR_KEY --status Inactive
```
