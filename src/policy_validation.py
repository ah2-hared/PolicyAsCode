import json
from pathlib import Path
from typing import Any
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY_PATH = PROJECT_ROOT / "policies" / "gdpr.json"
DEFAULT_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "policy.schema.json"

def load_json(file_path: Path) -> Any:
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    try:
        with file_path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in {file_path}\n"
            f"Line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error

def format_error_path(error_path: list[Any]) -> str:
    if not error_path:
        return "policy file"
    parts = []
    for item in error_path:
        parts.append(f"policy[{item}]" if isinstance(item, int) else str(item))
    return " -> ".join(parts)

def check_duplicate_policy_ids(policies: list[dict[str, Any]]) -> list[str]:
    seen_ids, duplicate_ids = set(), set()
    for policy in policies:
        policy_id = policy.get("id")
        if not isinstance(policy_id, str):
            continue
        if policy_id in seen_ids:
            duplicate_ids.add(policy_id)
        else:
            seen_ids.add(policy_id)
    return sorted(duplicate_ids)

def validate_policy_file(
    policy_path: Path = DEFAULT_POLICY_PATH,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
) -> bool:
    try:
        policies = load_json(policy_path)
        schema = load_json(schema_path)
        Draft202012Validator.check_schema(schema)
    except (FileNotFoundError, ValueError, SchemaError) as error:
        print(f"\nValidation could not start:\n{error}")
        return False

    validator = Draft202012Validator(schema)
    validation_errors = sorted(
        validator.iter_errors(policies),
        key=lambda error: list(error.absolute_path),
    )
    duplicate_ids = check_duplicate_policy_ids(policies) if isinstance(policies, list) else []

    if validation_errors or duplicate_ids:
        print("\nPolicy validation failed.")
        for number, error in enumerate(validation_errors, start=1):
            error_path = format_error_path(list(error.absolute_path))
            policy_id = "Unknown"
            if (
                isinstance(policies, list)
                and error.absolute_path
                and isinstance(error.absolute_path[0], int)
            ):
                index = error.absolute_path[0]
                if 0 <= index < len(policies) and isinstance(policies[index], dict):
                    policy_id = policies[index].get("id", "Unknown")
            print(f"\nError {number}")
            print(f"Policy ID: {policy_id}")
            print(f"Location: {error_path}")
            print(f"Problem: {error.message}")

        if duplicate_ids:
            print("\nDuplicate policy IDs found:")
            for policy_id in duplicate_ids:
                print(f"- {policy_id}")
        return False

    print("\nPolicy validation successful.")
    print(f"Validated file: {policy_path}")
    print(f"Schema used: {schema_path}")
    print(f"Number of policies: {len(policies)}")

    counts = {"full": 0, "partial": 0, "manual": 0}
    for policy in policies:
        level = policy.get("automation_level")
        if level in counts:
            counts[level] += 1

    print("\nAutomation levels:")
    print(f"Fully automated: {counts['full']}")
    print(f"Partially automated: {counts['partial']}")
    print(f"Manual review: {counts['manual']}")
    return True

if __name__ == "__main__":
    if not validate_policy_file():
        raise SystemExit(1)
