import json
from pathlib import Path
from policy import Policy
from policy_validation import validate_policy_file

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY_PATH = PROJECT_ROOT / "policies" / "gdpr.json"
DEFAULT_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "policy.schema.json"

def load_policies(
    policy_path: Path = DEFAULT_POLICY_PATH,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
) -> list[Policy]:
    if not validate_policy_file(policy_path, schema_path):
        raise ValueError("Policy loading stopped because validation failed.")

    with policy_path.open("r", encoding="utf-8") as file:
        policy_data = json.load(file)

    return [Policy(**item) for item in policy_data]

if __name__ == "__main__":
    try:
        policies = load_policies()
        print("\nPolicy loading successful.")
        print(f"Loaded {len(policies)} policies.")
        first = policies[0]
        print("\nFirst loaded policy:")
        print(f"ID: {first.id}")
        print(f"Title: {first.title}")
        print(f"Control: {first.control}")
        print(f"Operator: {first.operator}")
        print(f"Expected value: {first.expected_value}")
    except (ValueError, FileNotFoundError) as error:
        print(f"\nPolicy loading failed:\n{error}")
        raise SystemExit(1)
