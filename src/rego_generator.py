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
    """
    control = escape_rego_string(control_name)
    default = to_rego_value(default_value)

    return (
        f"object.get(resource.controls, {control}, {default})"
    )


def build_result_object(
    policy: Policy,
    status: str,
    actual_value_expr: str,
    control_expr: str | None = None,
) -> str:
    """
    Build one policy-evaluation result.

    Every policy now resolves to exactly one of four statuses for each
    resource it applies to:

        pass            the control was observed and satisfies the
                         policy
        fail            the control was observed and violates the
                         policy
        unknown         the control could not be determined from the
                         infrastructure -- never silently treated as
                         pass or fail
        not_applicable  the policy's underlying question does not
                         apply to this resource (a required_if trigger
                         that was not met)

    control_expr lets composite rules (all_of) report which specific
    control produced this result, since they check several at once;
    it defaults to the policy's own declared control.
    """
    control_field = control_expr or escape_rego_string(policy.control)

    return f"""{{
        "policy_id": {escape_rego_string(policy.id)},
        "policy_source": {escape_rego_string(policy.policy_source)},
        "reference": {escape_rego_string(policy.reference)},
        "title": {escape_rego_string(policy.title)},
        "message": {escape_rego_string(policy.message)},
        "severity": {escape_rego_string(policy.severity)},
        "cia_category": {escape_rego_string(policy.cia_category)},
        "verification_notes": {escape_rego_string(policy.verification_notes)},
        "resource_id": resource.id,
        "provider": resource.provider,
        "original_type": resource.original_type,
        "resource_type": resource.resource_type,
        "control": {control_field},
        "operator": {escape_rego_string(policy.operator)},
        "expected_value": {to_rego_value(policy.expected_value)},
        "actual_value": {actual_value_expr},
        "status": {escape_rego_string(status)}
    }}"""


def build_operator_condition(
    operator: str,
    actual_var: str,
    expected: str,
    policy_id: str,
) -> str:
    """
    The Rego condition that decides whether a *known* control value
    violates the policy.

    Only ever evaluated once the caller has already proven actual_var
    is not null, so numeric and membership comparisons never have to
    compare against null here.
    """
    conditions = {
        "equals": f"{actual_var} != {expected}",
        "not_equals": f"{actual_var} == {expected}",
        "greater_than": f"{actual_var} <= {expected}",
        "greater_than_or_equal": f"{actual_var} < {expected}",
        "less_than": f"{actual_var} >= {expected}",
        "less_than_or_equal": f"{actual_var} > {expected}",
    }

    if operator in conditions:
        return conditions[operator]

    if operator == "contains":
        return f"not {expected} in {actual_var}"

    if operator == "not_contains":
        return f"{expected} in {actual_var}"

    raise ValueError(
        f"Unsupported standard operator '{operator}' "
        f"for policy '{policy_id}'."
    )


def build_pass_condition(
    operator: str,
    actual_var: str,
    expected: str,
    policy_id: str,
) -> str:
    """
    The opposite of build_operator_condition: the condition for when a
    known value passes the policy instead of failing it. Written out
    separately instead of just wrapping the fail condition in Rego's
    `not`, so it's easy to read the pass/fail pair side by side.
    """
    conditions = {
        "equals": f"{actual_var} == {expected}",
        "not_equals": f"{actual_var} != {expected}",
        "greater_than": f"{actual_var} > {expected}",
        "greater_than_or_equal": f"{actual_var} >= {expected}",
        "less_than": f"{actual_var} < {expected}",
        "less_than_or_equal": f"{actual_var} <= {expected}",
    }

    if operator in conditions:
        return conditions[operator]

    if operator == "contains":
        return f"{expected} in {actual_var}"

    if operator == "not_contains":
        return f"not {expected} in {actual_var}"

    raise ValueError(
        f"Unsupported standard operator '{operator}' "
        f"for policy '{policy_id}'."
    )


def generate_standard_rule(policy: Policy) -> str:
    """
    Generate a rule for equals, numerical comparisons, contains, and
    not_contains.

    Every standard rule is four alternative bodies for the same rule
    name, one per possible status:

    1. not_applicable -- the control is missing AND the resource
       explicitly marks it not applicable (see
       resource.metadata.not_applicable_controls).
    2. unknown -- the control is missing and nothing marks it
       not-applicable. This is the framework's fail-closed default: an
       unknown control is never assumed to be pass or fail.
    3. fail -- the control is present and violates the policy.
    4. pass -- the control is present and satisfies the policy.
    """
    rule_name = generate_rule_name(policy)
    resource_match = build_resource_match(policy)
    control = escape_rego_string(policy.control)
    expected = to_rego_value(policy.expected_value)

    fail_condition = build_operator_condition(
        policy.operator, "actual", expected, policy.id,
    )
    pass_condition = build_pass_condition(
        policy.operator, "actual", expected, policy.id,
    )

    not_applicable_result = build_result_object(policy, "not_applicable", "null")
    unknown_result = build_result_object(policy, "unknown", "null")
    fail_result = build_result_object(policy, "fail", "actual")
    pass_result = build_result_object(policy, "pass", "actual")

    return f"""# {policy.id}: {policy.title}
{rule_name} contains result if {{
    {resource_match}
    actual := object.get(resource.controls, {control}, null)
    actual == null
    not_applicable_controls := object.get(resource.metadata, "not_applicable_controls", [])
    {control} in not_applicable_controls

    result := {not_applicable_result}
}}

{rule_name} contains result if {{
    {resource_match}
    actual := object.get(resource.controls, {control}, null)
    actual == null
    not_applicable_controls := object.get(resource.metadata, "not_applicable_controls", [])
    not {control} in not_applicable_controls

    result := {unknown_result}
}}

{rule_name} contains result if {{
    {resource_match}
    actual := object.get(resource.controls, {control}, null)
    actual != null
    {fail_condition}

    result := {fail_result}
}}

{rule_name} contains result if {{
    {resource_match}
    actual := object.get(resource.controls, {control}, null)
    actual != null
    {pass_condition}

    result := {pass_result}
}}
"""


def generate_all_of_rule(policy: Policy) -> str:
    """
    Generate a composite rule.

    The policy's expected_value must contain a list of control names.
    Gives one result per control that isn't confirmed true, so you can
    see exactly which one is the problem, plus a single pass result
    when every listed control is true. A resource can't get both a
    pass and a fail for the same policy, since pass only fires when
    every control is true.

    Example expected_value:
        ["encryption_enabled", "access_control_enabled", "backup_enabled"]
    """
    if not isinstance(policy.expected_value, list):
        raise ValueError(
            f"Policy '{policy.id}' must use an array as expected_value "
            "when the operator is 'all_of'."
        )

    rule_name = generate_rule_name(policy)
    resource_match = build_resource_match(policy)
    expected_controls = to_rego_value(policy.expected_value)

    fail_result = build_result_object(
        policy, "fail", "actual", control_expr="expected_control",
    )
    unknown_result = build_result_object(
        policy, "unknown", "null", control_expr="expected_control",
    )
    pass_result = build_result_object(
        policy, "pass", "true", control_expr=escape_rego_string(policy.control),
    )

    return f"""# {policy.id}: {policy.title}
{rule_name} contains result if {{
    {resource_match}
    some expected_control in {expected_controls}
    actual := object.get(resource.controls, expected_control, null)
    actual == false

    result := {fail_result}
}}

{rule_name} contains result if {{
    {resource_match}
    some expected_control in {expected_controls}
    actual := object.get(resource.controls, expected_control, null)
    actual == null

    result := {unknown_result}
}}

{rule_name} contains result if {{
    {resource_match}
    every expected_control in {expected_controls} {{
        object.get(resource.controls, expected_control, null) == true
    }}

    result := {pass_result}
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

    Five bodies cover every combination:

    1. unknown       -- the trigger control itself could not be
                         determined, so whether the requirement even
                         applies is unknown.
    2. not_applicable -- the trigger control is known and does not
                         equal the trigger value: the requirement
                         genuinely does not apply to this resource.
    3. unknown       -- the trigger fired, but the required control
                         could not be determined.
    4. fail          -- the trigger fired and the required control is
                         known but does not meet the required value.
    5. pass          -- the trigger fired and the required control
                         meets the required value.
    """
    config = validate_required_if_configuration(policy)

    rule_name = generate_rule_name(policy)
    resource_match = build_resource_match(policy)

    if_control = config["if_control"]
    if_value = to_rego_value(config["if_value"])

    required_control = config["required_control"]
    required_value = to_rego_value(config["required_value"])

    trigger_lookup = build_control_lookup(if_control)
    required_lookup = build_control_lookup(required_control)

    unknown_trigger_result = build_result_object(policy, "unknown", "null")
    not_applicable_result = build_result_object(policy, "not_applicable", "null")
    unknown_required_result = build_result_object(policy, "unknown", "null")
    fail_result = build_result_object(policy, "fail", "required")
    pass_result = build_result_object(policy, "pass", "required")

    return f"""# {policy.id}: {policy.title}
{rule_name} contains result if {{
    {resource_match}
    trigger := {trigger_lookup}
    trigger == null

    result := {unknown_trigger_result}
}}

{rule_name} contains result if {{
    {resource_match}
    trigger := {trigger_lookup}
    trigger != null
    trigger != {if_value}

    result := {not_applicable_result}
}}

{rule_name} contains result if {{
    {resource_match}
    trigger := {trigger_lookup}
    trigger == {if_value}
    required := {required_lookup}
    required == null

    result := {unknown_required_result}
}}

{rule_name} contains result if {{
    {resource_match}
    trigger := {trigger_lookup}
    trigger == {if_value}
    required := {required_lookup}
    required != null
    required != {required_value}

    result := {fail_result}
}}

{rule_name} contains result if {{
    {resource_match}
    trigger := {trigger_lookup}
    trigger == {if_value}
    required := {required_lookup}
    required == {required_value}

    result := {pass_result}
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


def generate_combined_results_rule(policy: Policy) -> str:
    """
    Add a policy's results (whatever mix of pass/fail/unknown/
    not_applicable it produced) to the single combined results set.
    """
    rule_name = generate_rule_name(policy)

    return f"""all_results contains result if {{
    result := {rule_name}[_]
}}
"""


def generate_rego(
    policies: list[Policy],
    output_path: Path = DEFAULT_OUTPUT_PATH,
) -> Path:
    """
    Generate a complete Rego file.

    Every policy in the input is expected to be technically
    verifiable from infrastructure evidence -- there is no manual-
    review category. A policy whose operator this generator does not
    recognise is reported as unsupported rather than silently dropped.
    """
    executable_rules: list[str] = []
    combined_result_rules: list[str] = []
    unsupported_policies: list[Policy] = []

    for policy in policies:
        if policy.operator not in EXECUTABLE_OPERATORS:
            unsupported_policies.append(policy)
            continue

        executable_rules.append(
            generate_executable_rule(policy)
        )

        combined_result_rules.append(
            generate_combined_results_rule(policy)
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
#       },
#       "metadata": {
#         "not_applicable_controls": ["some_control"]
#       }
#     }
#   ]
# }
#
# Every policy result has a status of exactly one of:
#   pass            observed, satisfies the policy
#   fail            observed, violates the policy
#   unknown         could not be determined -- never assumed compliant
#   not_applicable  the policy's question does not apply to this resource
#
# Query: data.gdpr.all_results

"""

    sections: list[str] = [header]

    if executable_rules:
        sections.append(
            "# ============================================================\n"
            "# POLICY RULES\n"
            "# ============================================================\n\n"
            + "\n".join(executable_rules)
        )

    if combined_result_rules:
        sections.append(
            "# ============================================================\n"
            "# COMBINED RESULTS\n"
            "# ============================================================\n\n"
            + "\n".join(combined_result_rules)
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
        f"Unsupported policies: "
        f"{len(unsupported_policies)}"
    )
    print(f"Output file: {output_path}")

    if unsupported_policies:
        print("\nUnsupported policies:")

        for policy in unsupported_policies:
            print(
                f"- {policy.id}: "
                f"operator={policy.operator}"
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
