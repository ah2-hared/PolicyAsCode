import json
import subprocess
from pathlib import Path
from typing import Any

from infrastructure_validation import validate_infrastructure_file


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_OPA_PATH = PROJECT_ROOT / "opa.exe"
DEFAULT_REGO_PATH = PROJECT_ROOT / "output" / "gdpr.rego"
DEFAULT_INFRASTRUCTURE_PATH = (
    PROJECT_ROOT
    / "infrastructure"
    / "normalised_infrastructure.json"
)
DEFAULT_INFRASTRUCTURE_SCHEMA_PATH = (
    PROJECT_ROOT / "schemas" / "infrastructure.schema.json"
)


def run_opa_query(
    query: str,
    infrastructure_path: Path,
    rego_path: Path,
    opa_path: Path,
) -> list[dict[str, Any]]:
    """
    Run one OPA query and return its result as Python data.

    Examples of queries:
        data.gdpr.deny
        data.gdpr.manual_reviews
    """
    if not opa_path.exists():
        raise FileNotFoundError(
            f"OPA executable not found: {opa_path}"
        )

    if not rego_path.exists():
        raise FileNotFoundError(
            f"Generated Rego file not found: {rego_path}"
        )

    if not infrastructure_path.exists():
        raise FileNotFoundError(
            f"Infrastructure file not found: {infrastructure_path}"
        )

    command = [
        str(opa_path),
        "eval",
        "--format",
        "json",
        "--input",
        str(infrastructure_path),
        "--data",
        str(rego_path),
        query,
    ]

    completed_process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )

    if completed_process.returncode != 0:
        error_message = completed_process.stderr.strip()

        if not error_message:
            error_message = completed_process.stdout.strip()

        raise RuntimeError(
            f"OPA evaluation failed for query '{query}'.\n"
            f"{error_message}"
        )

    try:
        opa_output = json.loads(completed_process.stdout)
    except json.JSONDecodeError as error:
        raise ValueError(
            "OPA returned output that was not valid JSON.\n"
            f"{completed_process.stdout}"
        ) from error

    return extract_expression_value(opa_output)


def extract_expression_value(
    opa_output: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Extract the useful result list from OPA's JSON response.

    OPA normally returns:

    {
        "result": [
            {
                "expressions": [
                    {
                        "value": [...]
                    }
                ]
            }
        ]
    }
    """
    results = opa_output.get("result", [])

    if not results:
        return []

    first_result = results[0]

    expressions = first_result.get("expressions", [])

    if not expressions:
        return []

    value = expressions[0].get("value", [])

    if value is None:
        return []

    if not isinstance(value, list):
        raise ValueError(
            "OPA query did not return the expected list format."
        )

    return value


def check_rego_syntax(
    rego_path: Path = DEFAULT_REGO_PATH,
    opa_path: Path = DEFAULT_OPA_PATH,
) -> bool:
    """
    Ask OPA to check the generated Rego file for syntax errors.
    """
    if not opa_path.exists():
        raise FileNotFoundError(
            f"OPA executable not found: {opa_path}"
        )

    if not rego_path.exists():
        raise FileNotFoundError(
            f"Generated Rego file not found: {rego_path}"
        )

    command = [
        str(opa_path),
        "check",
        str(rego_path),
    ]

    completed_process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )

    if completed_process.returncode != 0:
        error_message = completed_process.stderr.strip()

        if not error_message:
            error_message = completed_process.stdout.strip()

        print("\nRego syntax check failed.")
        print(error_message)

        return False

    print("\nRego syntax check successful.")

    return True


def evaluate_infrastructure(
    infrastructure_path: Path = DEFAULT_INFRASTRUCTURE_PATH,
    rego_path: Path = DEFAULT_REGO_PATH,
    opa_path: Path = DEFAULT_OPA_PATH,
    infrastructure_schema_path: Path = (
        DEFAULT_INFRASTRUCTURE_SCHEMA_PATH
    ),
) -> dict[str, Any]:
    """
    Run the complete OPA evaluation process.

    Steps:
        1. Validate the normalised infrastructure.
        2. Check the generated Rego syntax.
        3. Retrieve technical policy violations.
        4. Retrieve manual-review policies.
        5. Return the results as Python data.
    """
    print("\nStarting infrastructure evaluation.")

    infrastructure_valid = validate_infrastructure_file(
        infrastructure_path=infrastructure_path,
        schema_path=infrastructure_schema_path,
    )

    if not infrastructure_valid:
        raise ValueError(
            "OPA evaluation stopped because infrastructure "
            "validation failed."
        )

    if not check_rego_syntax(
        rego_path=rego_path,
        opa_path=opa_path,
    ):
        raise ValueError(
            "OPA evaluation stopped because the generated "
            "Rego file is invalid."
        )

    violations = run_opa_query(
        query="data.gdpr.deny",
        infrastructure_path=infrastructure_path,
        rego_path=rego_path,
        opa_path=opa_path,
    )

    manual_reviews = run_opa_query(
        query="data.gdpr.manual_reviews",
        infrastructure_path=infrastructure_path,
        rego_path=rego_path,
        opa_path=opa_path,
    )

    result = {
        "infrastructure_file": str(infrastructure_path),
        "rego_file": str(rego_path),
        "violation_count": len(violations),
        "manual_review_count": len(manual_reviews),
        "violations": violations,
        "manual_reviews": manual_reviews,
    }

    print("\nOPA evaluation successful.")
    print(f"Technical violations: {len(violations)}")
    print(f"Manual reviews required: {len(manual_reviews)}")

    return result


def save_raw_results(
    results: dict[str, Any],
    output_path: Path,
) -> Path:
    """
    Save the raw OPA evaluation result as formatted JSON.
    """
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            results,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(f"Raw results saved to: {output_path}")

    return output_path


if __name__ == "__main__":
    try:
        evaluation_results = evaluate_infrastructure()

        raw_output_path = (
            PROJECT_ROOT
            / "output"
            / "evaluation_results.json"
        )

        save_raw_results(
            results=evaluation_results,
            output_path=raw_output_path,
        )

        print("\nViolation summary:")

        if evaluation_results["violations"]:
            for violation in evaluation_results["violations"]:
                print(
                    f"- [{violation['severity']}] "
                    f"{violation['resource_id']}: "
                    f"{violation['message']}"
                )
        else:
            print("- No technical violations found.")

        print("\nManual-review summary:")

        if evaluation_results["manual_reviews"]:
            for review in evaluation_results["manual_reviews"]:
                print(
                    f"- [{review['severity']}] "
                    f"{review['title']}: "
                    f"{review['message']}"
                )
        else:
            print("- No manual reviews required.")

    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
        KeyError,
    ) as error:
        print(f"\nOPA runner failed:\n{error}")
        raise SystemExit(1)