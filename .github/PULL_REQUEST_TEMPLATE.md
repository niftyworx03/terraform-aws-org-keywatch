# What and why

<!--
What changes, and the reasoning behind it. The diff already says what;
explain why. Link the issue if there is one: "Fixes #123".
-->

## Type of change

<!-- Delete what does not apply. -->

- Bug fix
- New feature
- Breaking change
- Documentation only
- CI or tooling

## Checks

<!-- CI runs all of these. Ticking them locally saves a round trip. -->

- [ ] `terraform fmt -check -recursive` is clean
- [ ] `terraform validate` passes at the module root **and** in `examples/complete`
- [ ] `tflint --recursive` is clean
- [ ] `python3 tests/smoke_test.py` passes
- [ ] Detection or reporting logic changes have a new case in `tests/smoke_test.py`
- [ ] New or changed variables are in the README Inputs table
- [ ] User-facing changes are in `CHANGELOG.md` under `Unreleased`
- [ ] Design rationale, if any, is in `docs/DESIGN.md` rather than the README

## Cost impact

<!--
Zero cost at default settings is a design constraint. State the effect
explicitly, even if it is "none".
-->

- [ ] No change to cost at default settings
- [ ] Adds billable behaviour, gated behind a variable defaulting to off

## Blast radius

<!--
This module deploys into an Organizations management account and affects every
member account. Note anything relevant:

- Does it force replacement of the trail, log group, or SNS topic? Replacing
  the topic drops confirmed email subscriptions, which consumers must re-confirm.
- Does it change IAM permissions the module grants?
- Does it change what reaches a member account?
-->

- [ ] No resource replacement for existing deployments
- [ ] No change to the IAM permissions this module grants

## How this was tested

<!--
Be specific. "Applied to a two-account organization, created an IAM user in the
member account, and the alert named that account" is far more useful than
"tested". If you only ran the offline tests, say so — that is a fine answer, it
just tells reviewers what still needs checking.
-->

## Note on pasted output

<!--
If you include logs, plan output, or alert emails, redact account IDs,
organization IDs, ARNs, access key IDs, IAM principal names, and email
addresses first.
-->
