# Complete example

Deploys the full stack — organization trail, central log group, alerter,
hourly heartbeat, and the dead-man's-switch alarms — with GuardDuty left off so
the example costs nothing to run.

This directory is the root module. It owns the `provider` block and the region;
the module itself declares neither, so it can be composed with provider aliases
or an assume-role configuration.

## Before you apply

Two prerequisites are not managed here, both deliberately.

**Credentials must point at the organization management account.** The module's
`aws_organizations_organization` data source fails anywhere else, which is the
intended guard: an organization trail cannot be created from a member account.

**CloudTrail needs trusted access in Organizations.** Check, then enable:

```bash
aws organizations list-aws-service-access-for-organization \
  --query 'EnabledServicePrincipals[].ServicePrincipal'

aws organizations enable-aws-service-access \
  --service-principal cloudtrail.amazonaws.com
```

This stays a one-time CLI call rather than a resource. The only Terraform
resource that could set it is `aws_organizations_organization`, which would put
the whole organization under Terraform's control, where a bad apply can detach
accounts.

Also confirm no member account already has its own trail. Each account gets one
free copy of management events and this trail is that copy, so a pre-existing
trail turns it into a billable second copy for that account:

```bash
for p in <each-member-profile>; do
  echo -n "$p -> "
  AWS_PROFILE=$p aws cloudtrail describe-trails --query 'length(trailList)'
done
```

## Apply

```bash
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars and set alert_email

export AWS_PROFILE=<management account profile>
terraform init
terraform apply
```

Then click the confirmation link AWS mails to `alert_email`. Until you do,
nothing is delivered and Terraform keeps reporting the subscription as pending.

## Verify

Invoke the digest directly instead of waiting for the top of the hour:

```bash
aws lambda invoke \
  --function-name "$(terraform output -raw heartbeat_function_name)" \
  /dev/stdout
```

To prove the central design actually works, trigger the canary from a *member*
account:

```bash
AWS_PROFILE=<member profile> aws iam create-user --user-name keywatch-canary
AWS_PROFILE=<member profile> aws iam delete-user --user-name keywatch-canary
```

Expect **one** email, not two. `CreateUser` is on the alerting list and
`DeleteUser` is deliberately not: the list covers creation and privilege
escalation, plus defense evasion such as `StopLogging` and `DeleteTrail`.
Deleting a user is cleanup and does not earn a page. Add `DeleteUser` to
`dangerous_event_names` if your environment disagrees.

The mail that arrives should name the member account, not the management
account. That is the difference between this and a per-account deployment.

## Cost

Zero as configured, within the always-free tiers, except for fractions of a cent
of S3 storage that CloudTrail requires. Setting the three GuardDuty variables to
`true` makes it billable per member account. See the
[root README](../../README.md#cost) for the full breakdown.

## Destroy

```bash
terraform destroy
```

The trail bucket is `force_destroy = true`, so this finishes without emptying it
by hand.
