data "aws_caller_identity" "current" {}

# Region comes from the calling provider configuration rather than a variable.
# A module that takes its own region cannot be composed with provider aliases,
# which is the whole point of leaving provider configuration to the caller.
data "aws_region" "current" {}

# Fails unless this runs in the organization's management account, which is the
# intended guard: an organization trail cannot be created anywhere else.
data "aws_organizations_organization" "current" {}
