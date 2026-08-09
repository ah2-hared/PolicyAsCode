import json
from pathlib import Path
from typing import Any
from aws_adapter import normalise_aws_resources


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_TERRAFORM_PLAN_PATH = (
    PROJECT_ROOT
    / "terraform_examples"
    / "aws_test"
    / "tfplan.json"
)

DEFAULT_NORMALISED_OUTPUT_PATH = (
    PROJECT_ROOT
    / "infrastructure"
    / "normalised_infrastructure.json"
)

def normalise_terraform_resources(
    resources: list[dict[str, Any]],
    references: dict[str, dict[str, list[str]]] | None = None,
) -> list[dict[str, Any]]:
    """
    Send Terraform resources to provider-specific adapters.
    """
    aws_resources = [
        resource
        for resource in resources
        if get_provider_short_name(
            str(resource.get("provider_name", ""))
        ) == "aws"
    ]

    normalised_resources: list[dict[str, Any]] = []

    normalised_resources.extend(
        normalise_aws_resources(
            aws_resources,
            references,
        )
    )

    return normalised_resources


def extract_configuration_references(
    terraform_plan: dict[str, Any],
) -> dict[str, dict[str, list[str]]]:
    """
    Build a map of resource address -> {argument_name: [referenced
    addresses]} from the plan's `configuration` block.

    planned_values only has resolved values, so if an attribute isn't
    known yet (like an ID that AWS generates), it's just missing. But
    `configuration` still records what each argument was set to point
    at, e.g. `role = aws_iam_role.example.id`, even though we don't
    know the actual ID yet. That lets the adapter link a role to its
    policy by following this reference instead of assuming they share
    a Terraform name - which isn't always true (found this with
    TerraGoat, where the role and its policy have different names).
    """
    configuration = terraform_plan.get("configuration")

    if not isinstance(configuration, dict):
        return {}

    root_module = configuration.get("root_module")

    if not isinstance(root_module, dict):
        return {}

    references: dict[str, dict[str, list[str]]] = {}

    def walk_module(module: dict[str, Any]) -> None:
        module_resources = module.get("resources", [])

        if isinstance(module_resources, list):
            for resource in module_resources:
                if not isinstance(resource, dict):
                    continue

                address = resource.get("address")
                expressions = resource.get("expressions")

                if not isinstance(address, str):
                    continue

                if not isinstance(expressions, dict):
                    continue

                attribute_references: dict[str, list[str]] = {}

                for argument_name, expression in expressions.items():
                    if not isinstance(expression, dict):
                        continue

                    referenced_addresses = expression.get("references")

                    if isinstance(referenced_addresses, list):
                        attribute_references[argument_name] = [
                            reference
                            for reference in referenced_addresses
                            if isinstance(reference, str)
                        ]

                if attribute_references:
                    references[address] = attribute_references

        module_calls = module.get("module_calls", {})

        if isinstance(module_calls, dict):
            for module_call in module_calls.values():
                if not isinstance(module_call, dict):
                    continue

                nested_module = module_call.get("module")

                if isinstance(nested_module, dict):
                    walk_module(nested_module)

    walk_module(root_module)

    return references


def save_normalised_infrastructure(
    resources: list[dict[str, Any]],
    output_path: Path = DEFAULT_NORMALISED_OUTPUT_PATH,
) -> Path:
    """
    Save normalised infrastructure in the format expected by OPA.
    """
    infrastructure = {
        "resources": resources
    }

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            infrastructure,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        f"\nNormalised infrastructure saved to: "
        f"{output_path}"
    )

    return output_path

def load_json(file_path: Path) -> dict[str, Any]:
    """
    Load a Terraform plan JSON file.
    """
    if not file_path.exists():
        raise FileNotFoundError(
            f"Terraform plan JSON not found: {file_path}"
        )

    try:
        with file_path.open("r", encoding="utf-8-sig") as file:
            data = json.load(file)

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in {file_path}\n"
            f"Line {error.lineno}, column {error.colno}: "
            f"{error.msg}"
        ) from error

    if not isinstance(data, dict):
        raise ValueError(
            "Terraform plan JSON must contain a top-level object."
        )

    return data


def extract_module_resources(
    module: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Recursively extract resources from a Terraform module.

    Terraform plans may contain:
    - root_module.resources
    - root_module.child_modules
    - nested child modules
    """
    resources: list[dict[str, Any]] = []

    module_resources = module.get("resources", [])

    if isinstance(module_resources, list):
        for resource in module_resources:
            if isinstance(resource, dict):
                resources.append(resource)

    child_modules = module.get("child_modules", [])

    if isinstance(child_modules, list):
        for child_module in child_modules:
            if isinstance(child_module, dict):
                resources.extend(
                    extract_module_resources(child_module)
                )

    return resources


def extract_planned_resources(
    terraform_plan: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Extract all resources from planned_values.
    """
    planned_values = terraform_plan.get("planned_values")

    if not isinstance(planned_values, dict):
        raise ValueError(
            "Terraform plan does not contain planned_values."
        )

    root_module = planned_values.get("root_module")

    if not isinstance(root_module, dict):
        raise ValueError(
            "Terraform plan does not contain "
            "planned_values.root_module."
        )

    return extract_module_resources(root_module)


def get_provider_short_name(
    provider_name: str,
) -> str:
    """
    Convert a full Terraform provider path into a short provider name.

    Example:
        registry.terraform.io/hashicorp/aws
        becomes
        aws
    """
    if not provider_name:
        return "unknown"

    return provider_name.split("/")[-1]


def print_resource_summary(
    resources: list[dict[str, Any]],
) -> None:
    """
    Print a readable summary of extracted Terraform resources.
    """
    print("\nTerraform resources found:")
    print("-" * 72)

    for number, resource in enumerate(
        resources,
        start=1,
    ):
        address = resource.get("address", "Unknown")
        resource_type = resource.get("type", "Unknown")
        provider_name = resource.get(
            "provider_name",
            "Unknown",
        )

        provider = get_provider_short_name(
            str(provider_name)
        )

        values = resource.get("values", {})

        print(f"\nResource {number}")
        print(f"Address: {address}")
        print(f"Type: {resource_type}")
        print(f"Provider: {provider}")
        print("Values:")

        print(
            json.dumps(
                values,
                indent=2,
                ensure_ascii=False,
            )
        )


def load_terraform_plan_resources(
    plan_path: Path = DEFAULT_TERRAFORM_PLAN_PATH,
) -> list[dict[str, Any]]:
    """
    Load a Terraform plan and return all planned resources.
    """
    terraform_plan = load_json(plan_path)
    resources = extract_planned_resources(
        terraform_plan
    )

    print("\nTerraform plan loaded successfully.")
    print(f"Plan file: {plan_path}")
    print(f"Resources found: {len(resources)}")

    return resources


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Load a Terraform plan JSON file, normalise its "
            "resources, and save the result."
        ),
    )

    parser.add_argument(
        "--plan",
        type=Path,
        default=DEFAULT_TERRAFORM_PLAN_PATH,
        help=(
            "Path to a tfplan.json file. Defaults to the aws_test "
            "example: "
            f"{DEFAULT_TERRAFORM_PLAN_PATH}"
        ),
    )

    args = parser.parse_args()

    try:
        terraform_plan = load_json(args.plan)

        planned_resources = extract_planned_resources(
            terraform_plan
        )

        print("\nTerraform plan loaded successfully.")
        print(f"Plan file: {args.plan}")
        print(f"Resources found: {len(planned_resources)}")

        configuration_references = extract_configuration_references(
            terraform_plan
        )

        print_resource_summary(
            planned_resources
        )

        normalised_resources = (
            normalise_terraform_resources(
                planned_resources,
                configuration_references,
            )
        )

        print(
            "\nNormalised resources created: "
            f"{len(normalised_resources)}"
        )

        save_normalised_infrastructure(
            normalised_resources
        )

    except (
        FileNotFoundError,
        ValueError,
        TypeError,
        KeyError,
    ) as error:
        print(
            f"\nTerraform plan loading failed:\n{error}"
        )

        raise SystemExit(1)