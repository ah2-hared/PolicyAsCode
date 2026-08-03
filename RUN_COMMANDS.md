# Run commands

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python src/policy_validation.py
python src/policy_loader.py
python src/rego_generator.py
opa check "output\gdpr.rego"
```
