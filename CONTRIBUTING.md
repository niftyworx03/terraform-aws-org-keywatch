# Contributing

Thanks for considering a contribution. This is a small, focused module and the
bar for changes is "does it make the control more trustworthy," not "does it add
a feature."

## Before you open a pull request

Please open an issue first for anything beyond a typo or a clearly-scoped bug
fix. It is much cheaper to find out that a design does not fit in an issue than
after you have written it.

Two kinds of change get pushback, so it is worth knowing up front:

- **Anything that makes the module cost money by default.** Zero cost at default
  settings is a design constraint, not an accident. New billable behaviour has to
  be opt-in via a variable defaulting to off, the way GuardDuty is.
- **Anything that increases alert volume without increasing signal.** Adding
  event names to `dangerous_event_names` is easy and usually wrong. A control
  people stop reading is worse than no control. Make the case that the event is
  rare in a normal account.

## Development setup

You need Terraform >= 1.0 and Python 3.12. No AWS account or credentials are
needed for the tests.

```bash
git clone https://github.com/niftyworx03/terraform-aws-org-keywatch.git
cd terraform-aws-org-keywatch
```

Optionally install the pre-commit hooks, which run the same formatting and lint
checks CI does:

```bash
pre-commit install
```

## Checks your change must pass

CI runs all of these. Run them locally to save a round trip:

```bash
# Formatting
terraform fmt -check -recursive

# Validate the module and the example independently
terraform init -backend=false && terraform validate
(cd examples/complete && terraform init -backend=false && terraform validate)

# Lint
tflint --recursive

# Lambda logic, offline, no AWS account required
python3 tests/smoke_test.py
```

Note that CI pins Terraform to a modern version. `terraform fmt` output drifts
between Terraform releases, so if the format check fails on code you did not
touch, check your local Terraform version before assuming CI is wrong.

## Changing the Lambda functions

The functions are plain Python with no dependencies beyond `boto3`, which the
Lambda runtime provides. Keep it that way — the module packages the `lambda/`
directory directly with `archive_file` and there is no build step to install
anything into.

If you change detection or reporting logic, add a case to
`tests/smoke_test.py`. It stubs `boto3` so tests stay offline and fast. Every
false-positive class the module filters out has a test proving it stays
filtered, and regressions there are the expensive kind:

- calls made by the module's own roles
- calls made by AWS service principals
- benign API errors misread as authorization denials
- event-cap truncation reported as a total rather than a floor

## Documenting a change

- User-facing behaviour changes go in `CHANGELOG.md` under `Unreleased`.
- New or changed variables go in the README's Inputs table, between the
  `BEGIN_TF_DOCS` and `END_TF_DOCS` markers. Edit it by hand. The markers are
  there for convention, but nothing regenerates the table: its defaults column
  summarises long values instead of printing them, which a generator cannot do.
- Rationale — *why* a design is the way it is — goes in `docs/DESIGN.md` rather
  than the README.

## Commit and PR style

Small, focused commits with a message explaining why rather than what. The diff
already says what.

In the pull request, say what you tested against. "Applied to a two-account
organization and confirmed the alert named the member account" is far more useful
than "tested."

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under the Apache License 2.0, the same license as the
project. See [LICENSE](LICENSE).
