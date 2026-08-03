import json
from pathlib import Path
from typing import Any

from policy import Policy
from policy_loader import load_policies


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "output" / "gdpr.rego"


EXECUTABLE_OPERATORS = {
    "equals",
    "not_equals",
    "greater_than",
    "greater_than_or_equal",
    "less_than",
    "less_than_or_equal",
    "contains",
    "not_contains",
    "all_of",
    "required_if",
}

MANUAL_OPERATORS = {
    "manual_review",
}


def to_rego_value(value: Any) -> str:
    """
    Convert a Python value into valid Rego syntax.

    Examples:
        True        -> true
        False       -> false
        365         -> 365
        "private"   -> "private"
        ["a", "b"]  -> ["a", "b"]
    """
    return json.dumps(value)


def escape_rego_string(value: str) -> str:
    """
    Convert a Python string into a safely quoted Rego string.
    """
    return json.dumps(value)


def generate_rule_name(policy: Policy) -> str:
    """
    Convert a policy ID into a valid Rego rule name.

    Example:
        GDPR-32-ENC-001
        becomes
        gdpr_32_enc_001
    """
    return (
        policy.id
        .lower()
        .replace("-", "_")
        .replace(".", "_")
        .replace(" ", "_")
    )


def build_resource_match(policy: Policy) -> str:
    """
    Generate the Rego lines used to select matching resources.

    Every policy checks resources whose normalised resource_type
    matches the resource_type stored in the policy.
    """
    resource_type = escape_rego_string(policy.resource_type)

    return (
        "some resource in input.resources\n"
        f"    resource.resource_type == {resource_type}"
    )


def build_control_lookup(
    control_name: str,
    default_value: Any = None,
) -> str:
    """
    Build a safe Rego lookup for a resource control.

    object.get prevents the rule from becoming undefined when a
    control is missing.

    Example:
        object.get(
            resource.controls,
            "encryption_enabled",
            null
        )
    """
    control = escape_rego_string(control_name)
    default = to_rego_value(default_value)

    return (
        f"object.get(resource.controls, {control}, {default})"
    )


def build_violation_object(policy: Policy) -> str:
    """
    Build the violation object returned by an executable rule.

    Resource details are included so the report can identify the
    exact infrastructure resource that failed.
    """
    return f"""{{
        "policy_id": {escape_rego_string(policy.id)},
        "policy_source": {escape_rego_string(policy.policy_source)},
        "reference": {escape_rego_string(policy.reference)},
        "title": {escape_rego_string(policy.title)},
        "message": {escape_rego_string(policy.message)},
        "severity": {escape_rego_string(policy.severity)},
        "cia_category": {escape_rego_string(policy.cia_category)},
        "automation_level": {escape_rego_string(policy.automation_level)},
        "verification_notes": {escape_rego_string(policy.verification_notes)},
        "resource_id": resource.id,
        "provider": resource.provider,
        "original_type": resource.original_type,
        "resource_type": resource.resource_type,
        "control": {escape_rego_string(policy.control)},
        "operator": {escape_rego_string(policy.operator)},
        "expected_value": {to_rego_value(policy.expected_value)},
        "actual_value": object.get(
            resource.controls,
            {escape_rego_string(policy.control)},
            null
        ),
        "status": "non_compliant"
    }}"""


def build_standard_violation_condition(policy: Policy) -> str:
    """
    Build the Rego condition for a normal comparison policy.

    Missing controls use null as the actual value. This means a
    required control that is absent will usually produce a violation.
    """
    actual = build_control_lookup(policy.control)
    expected = to_rego_value(policy.expected_value)

    conditions = {
        "equals": f"{actual} != {expected}",
        "not_equals": f"{actual} == {expected}",
        "greater_than": f"{actual} <= {expected}",
        "greater_than_or_equal": f"{actual} < {expected}",
        "less_than": f"{actual} >= {expected}",
        "less_than_or_equal": f"{actual} > {expected}",
    }

    if policy.operator in conditions:
        return conditions[policy.operator]

    if policy.operator == "contains":
        return f"not {expected} in {actual}"

    if policy.operator == "not_contains":
        return f"{expected} in {actual}"

    raise ValueError(
        f"Unsupported standard operator '{policy.operator}' "
        f"for policy '{policy.id}'."
    )


def generate_standard_rule(policy: Policy) -> str:
    """
    Generate a rule for equals, numerical comparisons, contains,
    and not_contains.
    """
    rule_name = generate_rule_name(policy)
    resource_match = build_resource_match(policy)
    condition = build_standard_violation_condition(policy)
    violation_object = build_violation_object(policy)

    return f"""# {policy.id}: {policy.title}
{rule_name} contains violation if {{
    {resource_match}
    {condition}

    violation := {violation_object}
}}
"""


def generate_all_of_rule(policy: Policy) -> str:
    """
    Generate a composite rule.

    The policy's expected_value must contain a list of control names.
    The rule produces a violation when any listed control is missing
    or is not equal to true.

    Example expected_value:
        [
            "encryption_enabled",
            "logging_enabled",
            "backup_enabled"
        ]
    """
    if not isinstance(policy.expected_value, list):
        raise ValueError(
            f"Policy '{policy.id}' must use an array as expected_value "
            "when the operator is 'all_of'."
        )

    rule_name = generate_rule_name(policy)
    resource_match = build_resource_match(policy)
    expected_controls = to_rego_value(policy.expected_value)

    violation_object = f"""{{
        "policy_id": {escape_rego_string(policy.id)},
        "policy_source": {escape_rego_string(policy.policy_source)},
        "reference": {escape_rego_string(policy.reference)},
        "title": {escape_rego_string(policy.title)},
        "message": {escape_rego_string(policy.message)},
        "severity": {escape_rego_string(policy.severity)},
        "cia_category": {escape_rego_string(policy.cia_category)},
        "automation_level": {escape_rego_string(policy.automation_level)},
        "verification_notes": {escape_rego_string(policy.verification_notes)},
        "resource_id": resource.id,
        "provider": resource.provider,
        "original_type": resource.original_type,
        "resource_type": resource.resource_type,
        "control": {escape_rego_string(policy.control)},
        "operator": "all_of",
        "missing_or_disabled_control": expected_control,
        "expected_value": true,
        "actual_value": object.get(
            resource.controls,
            expected_control,
            null
        ),
        "status": "non_compliant"
    }}"""

    return f"""# {policy.id}: {policy.title}
{rule_name} contains violation if {{
    {resource_match}
    some expected_control in {expected_controls}

    object.get(
        resource.controls,
        expected_control,
        null
    ) != true

    violation := {violation_object}
}}
"""


def validate_required_if_configuration(
    policy: Policy,
) -> dict[str, Any]:
    """
    Validate the expected_value object used by required_if.

    Required format:

    {
        "if_control": "high_risk_processing",
        "if_value": true,
        "required_control": "dpia_completed",
        "required_value": true
    }
    """
    config = policy.expected_value

    if not isinstance(config, dict):
        raise ValueError(
            f"Policy '{policy.id}' must use an object as expected_value "
            "when the operator is 'required_if'."
        )

    required_fields = {
        "if_control",
        "if_value",
        "required_control",
        "required_value",
    }

    missing_fields = required_fields - config.keys()

    if missing_fields:
        missing = ", ".join(sorted(missing_fields))

        raise ValueError(
            f"Policy '{policy.id}' is missing required_if fields: "
            f"{missing}"
        )

    if not isinstance(config["if_control"], str):
        raise ValueError(
            f"Policy '{policy.id}' field 'if_control' must be a string."
        )

    if not isinstance(config["required_control"], str):
        raise ValueError(
            f"Policy '{policy.id}' field 'required_control' "
            "must be a string."
        )

    return config


def generate_required_if_rule(policy: Policy) -> str:
    """
    Generate a conditional rule.

    A violation is returned when:

    1. The trigger control has the trigger value.
    2. The required control does not have the required value.
    """
    config = validate_required_if_configuration(policy)

    rule_name = generate_rule_name(policy)
    resource_match = build_resource_match(policy)

    if_control = config["if_control"]
    if_value = to_rego_value(config["if_value"])

    required_control = config["required_control"]
    required_value = to_rego_value(
        config["required_value"]
    )

    trigger_lookup = build_control_lookup(if_control)
    required_lookup = build_control_lookup(required_control)

    violation_object = f"""{{
        "policy_id": {escape_rego_string(policy.id)},
        "policy_source": {escape_rego_string(policy.policy_source)},
        "reference": {escape_rego_string(policy.reference)},
        "title": {escape_rego_string(policy.title)},
        "message": {escape_rego_string(policy.message)},
        "severity": {escape_rego_string(policy.severity)},
        "cia_category": {escape_rego_string(policy.cia_category)},
        "automation_level": {escape_rego_string(policy.automation_level)},
        "verification_notes": {escape_rego_string(policy.verification_notes)},
        "resource_id": resource.id,
        "provider": resource.provider,
        "original_type": resource.original_type,
        "resource_type": resource.resource_type,
        "control": {escape_rego_string(required_control)},
        "operator": "required_if",
        "trigger_control": {escape_rego_string(if_control)},
        "trigger_value": {to_rego_value(config["if_value"])},
        "expected_value": {required_value},
        "actual_value": object.get(
            resource.controls,
            {escape_rego_string(required_control)},
            null
        ),
        "status": "non_compliant"
    }}"""

    return f"""# {policy.id}: {policy.title}
{rule_name} contains violation if {{
    {resource_match}
    {trigger_lookup} == {if_value}
    {required_lookup} != {required_value}

    violation := {violation_object}
}}
"""


def generate_executable_rule(policy: Policy) -> str:
    """
    Send a policy to the correct rule generator.
    """
    if policy.operator == "all_of":
        return generate_all_of_rule(policy)

    if policy.operator == "required_if":
        return generate_required_if_rule(policy)

    return generate_standard_rule(policy)


def generate_combined_deny_rule(policy: Policy) -> str:
    """
    Add a policy-specific violation to the main deny collection.
    """
    rule_name = generate_rule_name(policy)

    return f"""deny contains violation if {{
    violation := {rule_name}[_]
}}
"""


def generate_manual_review_rule(policy: Policy) -> str:
    """
    Generate a static manual-review entry.

    Manual policies are not marked compliant or non-compliant because
    they cannot be judged from Terraform configuration alone.
    """
    return f"""# {policy.id}: {policy.title}
manual_reviews contains review if {{
    review := {{
        "policy_id": {escape_rego_string(policy.id)},
        "policy_source": {escape_rego_string(policy.policy_source)},
        "reference": {escape_rego_string(policy.reference)},
        "title": {escape_rego_string(policy.title)},
        "description": {escape_rego_string(policy.description)},
        "message": {escape_rego_string(policy.message)},
        "severity": {escape_rego_string(policy.severity)},
        "cia_category": {escape_rego_string(policy.cia_category)},
        "automation_level": {escape_rego_string(policy.automation_level)},
        "verification_notes": {escape_rego_string(policy.verification_notes)},
        "resource_type": {escape_rego_string(policy.resource_type)},
        "control": {escape_rego_string(policy.control)},
        "operator": {escape_rego_string(policy.operator)},
        "status": "manual_review_required"
    }}
}}
"""


def generate_rego(
    policies: list[Policy],
    output_path: Path = DEFAULT_OUTPUT_PATH,
) -> Path:
    """
    Generate a complete Rego file.

    Handling rules:

    - Fully and partially automated policies become executable rules.
    - Manual policies become manual-review entries.
    - Unknown operators are reported as unsupported.
    """
    executable_rules: list[str] = []
    combined_deny_rules: list[str] = []
    manual_review_rules: list[str] = []
    unsupported_policies: list[Policy] = []

    for policy in policies:
        is_manual = (
            policy.automation_level == "manual"
            or policy.operator in MANUAL_OPERATORS
        )

        if is_manual:
            manual_review_rules.append(
                generate_manual_review_rule(policy)
            )
            continue

        if policy.operator not in EXECUTABLE_OPERATORS:
            unsupported_policies.append(policy)
            continue

        executable_rules.append(
            generate_executable_rule(policy)
        )

        combined_deny_rules.append(
            generate_combined_deny_rule(policy)
        )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    header = """package gdpr

# This file was generated automatically.
# Do not edit it manually.

# The infrastructure input must use this structure:
#
# {
#   "resources": [
#     {
#       "id": "resource-name",
#       "provider": "aws",
#       "original_type": "aws_s3_bucket",
#       "resource_type": "storage",
#       "controls": {
#         "encryption_enabled": true
#       }
#     }
#   ]
# }
#
# Executable violations:
# data.gdpr.deny
#
# Manual-review policies:
# data.gdpr.manual_reviews

"""

    sections: list[str] = [header]

    if executable_rules:
        sections.append(
            "# ============================================================\n"
            "# EXECUTABLE POLICY RULES\n"
            "# ============================================================\n\n"
            + "\n".join(executable_rules)
        )

    if combined_deny_rules:
        sections.append(
            "# ============================================================\n"
            "# COMBINED POLICY VIOLATIONS\n"
            "# ============================================================\n\n"
            + "\n".join(combined_deny_rules)
        )

    if manual_review_rules:
        sections.append(
            "# ============================================================\n"
            "# MANUAL REVIEW POLICIES\n"
            "# ============================================================\n\n"
            + "\n".join(manual_review_rules)
        )

    if unsupported_policies:
        unsupported_lines = [
            "# ============================================================",
            "# UNSUPPORTED POLICIES",
            "# ============================================================",
        ]

        for policy in unsupported_policies:
            unsupported_lines.append(
                f"# {policy.id}: {policy.title} "
                f"(operator={policy.operator})"
            )

        sections.append(
            "\n".join(unsupported_lines) + "\n"
        )

    rego_content = "\n".join(sections)

    output_path.write_text(
        rego_content,
        encoding="utf-8",
    )

    print("\nRego generation successful.")
    print(f"Policies received: {len(policies)}")
    print(f"Executable policies: {len(executable_rules)}")
    print(
        f"Manual-review policies: "
        f"{len(manual_review_rules)}"
    )
    print(
        f"Unsupported policies: "
        f"{len(unsupported_policies)}"
    )
    print(f"Output file: {output_path}")

    if unsupported_policies:
        print("\nUnsupported policies:")

        for policy in unsupported_policies:
            print(
                f"- {policy.id}: "
                f"operator={policy.operator}, "
                f"automation={policy.automation_level}"
            )

    return output_path


if __name__ == "__main__":
    try:
        loaded_policies = load_policies()
        generated_file = generate_rego(
            loaded_policies
        )

        print(
            "\nRun this command to check "
            "the generated Rego:"
        )
        print(
            f'.\\opa.exe check "{generated_file}"'
        )

    except (
        ValueError,
        FileNotFoundError,
        KeyError,
        TypeError,
    ) as error:
        print(f"\nRego generation failed:\n{error}")
        raise SystemExit(1)
        