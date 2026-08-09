# Local patch notes

This directory is an unmodified clone of
[bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat)
(`terraform/aws`), used to evaluate the PolicyAsCode pipeline against
real, third-party, multi-service Terraform instead of only the
hand-written example under `terraform_examples/aws_test`.

TerraGoat is built to be deployed (or planned) with real AWS
credentials and a real S3 state backend. PolicyAsCode's ingestion path
requires a real `terraform plan` / `terraform show -json` — it does
not parse HCL statically the way Checkov or tfsec do — so a handful of
narrow, disclosed changes were needed purely to make `terraform plan`
runnable offline. **None of TerraGoat's intentionally vulnerable
resource configuration was changed.**

## What was changed

| File | Change | Why |
|---|---|---|
| `terraform/aws/local_override.tf` (new) | Overrides the `terraform { backend "s3" {} }` block to `backend "local" {}`, and the default `aws` provider to use fake credentials with `skip_credentials_validation = true`. | The original backend/provider assume a real AWS account and an existing S3 state bucket. |
| `terraform/aws/consts.tf` | Commented out `data "aws_caller_identity" "current" {}`; `local.resource_prefix` now uses the literal placeholder `123456789012` instead of `data.aws_caller_identity.current.account_id`. | This data source makes a real STS `GetCallerIdentity` call during plan. |
| `terraform/aws/db-app.tf` | Commented out `data "aws_ami" "amazon-linux-2" {}`; `aws_instance.db_app.ami` now uses the repo's own pre-existing `var.ami` placeholder default instead of the data source lookup. | This data source makes a real EC2 `DescribeImages` call during plan. |
| `terraform/aws/consts.tf` | `type = "string"` -> `type = string` on 4 variable declarations. | TerraGoat predates Terraform 0.12's unquoted type constraint syntax; modern Terraform (1.14 here) hard-errors on the old quoted form instead of just warning. Purely a parser-compatibility fix, no behaviour change. |
| `terraform/aws/providers.tf` | Added `required_providers { aws = "~> 3.0" }`. | No version was pinned upstream, so `terraform init` resolved the latest aws provider (6.x). TerraGoat's embedded yor git-trace tags date it to 2020-2022, well before several aws provider schema changes; 6.x hard-errors on arguments this config relies on (e.g. `aws_rds_cluster.engine` became required with no default). |
| `terraform/aws/ecr.tf` | Same `data.aws_caller_identity.current` reference swapped for the literal placeholder, in `local.docker_image` and the `null_resource` provisioner command string. | Same reason as consts.tf; missed on the first pass because it's a second, independent reference to the same disabled data source. |
| `terraform/aws/rds.tf` | Removed `allocated_storage = 10` from all 9 `aws_rds_cluster` blocks. | `allocated_storage` applies to instance-based RDS, not Aurora clusters, and the aws ~> 3.0 schema rejects it outright. These 9 near-identical clusters exist purely to vary `backup_retention_period` (0/1/15/25 days) against a retention-length check; that value is untouched. |

Both data sources were metadata lookups (account id, AMI id), not
security-relevant configuration — none of the resources that
PolicyAsCode's policies actually evaluate (S3, IAM, security groups,
KMS, RDS, CloudTrail, etc.) were edited.

## Known limitation this exposes

Needing to patch a real-world repo just to get a plan at all is itself
a finding: PolicyAsCode's Terraform ingestion is coupled to a
successful, fully-resolved `terraform plan`, which fails on any
configuration containing a live data source (cloud lookups, remote
state, external data) regardless of whether that data source touches
anything security-relevant. Static-HCL scanners don't have this
constraint. See the architecture review for the fuller discussion of
this coupling.
