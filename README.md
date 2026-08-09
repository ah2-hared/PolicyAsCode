# PolicyAsCode - Project Overview

## Current workflow

The current framework works as follows:

GDPR-inspired requirements
        ↓
policies/gdpr.json
        ↓
Policy schema validation
        ↓
Python Policy objects
        ↓
Automatic Rego generation
        ↓
Terraform plan JSON
        ↓
Terraform resource extraction
        ↓
AWS infrastructure normalisation
        ↓
Normalised infrastructure validation
        ↓
Open Policy Agent evaluation
        ↓
Compliance report

---

## Policy side

The selected GDPR-inspired requirements are stored in:

policies/gdpr.json

Each policy contains structured information such as:

- GDPR reference
- resource type
- security control
- comparison operator
- expected value
- severity
- message

The policy schema is stored in:

schemas/policy.schema.json

Before policies are used, policy_validation.py checks that they follow the
expected structure.

policy_loader.py then loads the validated policies into Python Policy objects.

rego_generator.py converts these structured policies into executable Rego
rules for Open Policy Agent.

This means the Rego rules are generated from the structured policy model rather
than being written manually for every policy.

---

## Infrastructure side

The framework currently evaluates Terraform infrastructure before deployment.

Terraform generates a binary execution plan:

terraform plan -out=tfplan

The plan is then exported as JSON:

terraform show -json tfplan

The resulting tfplan.json contains the resources Terraform intends to create.

terraform_plan_loader.py reads this plan and extracts the Terraform resources.

---

## AWS normalisation

Terraform resources use AWS-specific names and structures.

For example:

aws_s3_bucket
aws_s3_bucket_versioning
aws_s3_bucket_public_access_block
aws_db_instance
aws_security_group

The GDPR-inspired policies should not need to understand these AWS-specific
resource names.

aws_adapter.py therefore converts AWS Terraform resources into a normalised
security representation.

For example:

aws_s3_bucket_server_side_encryption_configuration

may become:

encryption_enabled = true

Several Terraform resources can also be combined when they describe different
parts of the same logical infrastructure resource.

The output is stored as:

infrastructure/normalised_infrastructure.json

---

## Policy evaluation

The normalised infrastructure is validated using:

schemas/infrastructure.schema.json

Open Policy Agent then evaluates:

output/gdpr.rego

against:

infrastructure/normalised_infrastructure.json

If the actual infrastructure does not meet the expected policy condition, OPA
returns a violation.

The results are then converted into:

- JSON report
- text report
- HTML report

The HTML report provides a readable summary of the detected policy violations.

---

## Current implementation scope

The implementation currently focuses on AWS Terraform infrastructure.

Supported areas include examples of:

- S3 storage
- encryption
- versioning
- logging
- public access
- backups
- KMS
- IAM
- security groups
- load balancers / TLS
- RDS
- monitoring
- resilience controls

AWS is being used as the implementation case study.

Support for other cloud providers is considered future work rather than part
of the current dissertation implementation.

---

## Current project status

The following parts of the framework are implemented:

- structured GDPR-inspired policies
- policy JSON Schema validation
- Python policy model
- automatic Rego generation
- Terraform plan JSON loading
- Terraform resource extraction
- AWS infrastructure normalisation
- infrastructure schema validation
- OPA evaluation
- JSON, text and HTML reporting

The current focus is on:

1. finalising the technical policy set
2. making sure each policy has meaningful infrastructure evidence
3. creating controlled Terraform test cases
4. evaluating detection accuracy and limitations
5. documenting the results for the dissertation

---

## Important limitation

This framework does not claim that passing the technical checks proves complete
GDPR compliance.

The framework verifies selected technical controls inspired by GDPR
requirements.

Some regulatory requirements depend on organisational, legal or contextual
information that is not visible in Terraform infrastructure.

---

## How to run the current pipeline

From the project root:

```powershell
python src\policy_validation.py
python src\rego_generator.py
python src\terraform_plan_loader.py
python src\infrastructure_validation.py
python src\opa_runner.py
python src\report_generator.py