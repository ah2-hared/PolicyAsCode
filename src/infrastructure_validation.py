import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_INFRASTRUCTURE_PATH = (
    PROJECT_ROOT
    / "infrastructure"
    / "normalised_infrastructure.json"
)

DEFAULT_SCHEMA_PATH = (
    PROJECT_ROOT / "schemas" / "infrastructure.schema.json"
)


def load_json(file_path: Path) -> Any:
    """
    Load data from a JSON file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file contains invalid JSON.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        with file_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in {file_path}\n"
            f"Line {error.lineno}, column {error.colno}: "
            f"{error.msg}"
        ) from error


def format_error_path(error_path: list[Any]) -> str:
    """
    Convert a JSON Schema error path into a readable location.

    Example:
        resources -> resource[0] -> controls
    """
    if not error_path:
        return "infrastructure file"

    parts: list[str] = []

    for item in error_path:
        if isinstance(item, int):
            parts.append(f"resource[{item}]")
        else:
            parts.append(str(item))

    return " -> ".join(parts)


def check_duplicate_resource_ids(
    resources: list[dict[str, Any]],
) -> list[str]:
    """
    Find resource IDs that appear more than once.
    """
    seen_ids: set[str] = set()
    duplicate_ids: set[str] = set()

    for resource in resources:
        resource_id = resource.get("id")

        if not isinstance(resource_id, str):
            continue

        if resource_id in seen_ids:
            duplicate_ids.add(resource_id)
        else:
            seen_ids.add(resource_id)

    return sorted(duplicate_ids)


def validate_infrastructure_file(
    infrastructure_path: Path = DEFAULT_INFRASTRUCTURE_PATH,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
) -> bool:
    """
    Validate normalised infrastructure JSON against the
    infrastructure schema.

    Returns:
        True when validation succeeds.
        False when validation fails.
    """
    try:
        infrastructure = load_json(infrastructure_path)
        schema = load_json(schema_path)

        Draft202012Validator.check_schema(schema)

    except (FileNotFoundError, ValueError, SchemaError) as error:
        print(f"\nInfrastructure validation could not start:\n{error}")
        return False

    validator = Draft202012Validator(schema)

    validation_errors = sorted(
        validator.iter_errors(infrastructure),
        key=lambda error: list(error.absolute_path),
    )

    duplicate_resource_ids: list[str] = []

    if isinstance(infrastructure, dict):
        resources = infrastructure.get("resources", [])

        if isinstance(resources, list):
            duplicate_resource_ids = check_duplicate_resource_ids(
                resources
            )

    if validation_errors or duplicate_resource_ids:
        print("\nInfrastructure validation failed.")

        for number, error in enumerate(
            validation_errors,
            start=1,
        ):
            error_path = format_error_path(
                list(error.absolute_path)
            )

            print(f"\nError {number}")
            print(f"Location: {error_path}")
            print(f"Problem: {error.message}")

        if duplicate_resource_ids:
            print("\nDuplicate resource IDs found:")

            for resource_id in duplicate_resource_ids:
                print(f"- {resource_id}")

        return False

    resources = infrastructure["resources"]

    print("\nInfrastructure validation successful.")
    print(f"Validated file: {infrastructure_path}")
    print(f"Schema used: {schema_path}")
    print(f"Number of resources: {len(resources)}")

    resource_type_counts: dict[str, int] = {}
    provider_counts: dict[str, int] = {}

    for resource in resources:
        resource_type = resource["resource_type"]
        provider = resource["provider"]

        resource_type_counts[resource_type] = (
            resource_type_counts.get(resource_type, 0) + 1
        )

        provider_counts[provider] = (
            provider_counts.get(provider, 0) + 1
        )

    print("\nResources by type:")

    for resource_type, count in sorted(
        resource_type_counts.items()
    ):
        print(f"{resource_type}: {count}")

    print("\nResources by provider:")

    for provider, count in sorted(provider_counts.items()):
        print(f"{provider}: {count}")

    return True


if __name__ == "__main__":
    validation_successful = validate_infrastructure_file()

    if not validation_successful:
        raise SystemExit(1)