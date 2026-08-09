# Run commands

## Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Full pipeline (policies -> Rego -> Terraform plan -> normalised infrastructure -> OPA -> report)

```powershell
python src/policy_validation.py
python src/rego_generator.py
python src/terraform_plan_loader.py
python src/infrastructure_validation.py
python src/opa_runner.py
python src/report_generator.py
```

`report_generator.py` writes `output/compliance_report.{json,txt,html}` and opens the HTML
report in your default browser.

## Regenerating the example Terraform plan

The AWS adapter reads `terraform_examples/aws_test/tfplan.json`, a static export. If you
change `terraform_examples/aws_test/main.tf`, regenerate it before re-running the pipeline:

```powershell
cd terraform_examples/aws_test
terraform init      # first time only
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
cd ../..
```

## Rego syntax only

```powershell
opa check "output\gdpr.rego"
```
