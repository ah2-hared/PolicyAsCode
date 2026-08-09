import html
import json
import webbrowser
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_EVALUATION_PATH = (
    PROJECT_ROOT / "output" / "evaluation_results.json"
)

DEFAULT_JSON_REPORT_PATH = (
    PROJECT_ROOT / "output" / "compliance_report.json"
)

DEFAULT_TEXT_REPORT_PATH = (
    PROJECT_ROOT / "output" / "compliance_report.txt"
)

DEFAULT_HTML_REPORT_PATH = (
    PROJECT_ROOT / "output" / "compliance_report.html"
)


SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}


def load_evaluation_results(
    evaluation_path: Path = DEFAULT_EVALUATION_PATH,
) -> dict[str, Any]:
    """
    Load the raw evaluation results produced by opa_runner.py.
    """
    if not evaluation_path.exists():
        raise FileNotFoundError(
            f"Evaluation results not found: {evaluation_path}"
        )

    try:
        with evaluation_path.open("r", encoding="utf-8") as file:
            data = json.load(file)

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in {evaluation_path}\n"
            f"Line {error.lineno}, column {error.colno}: "
            f"{error.msg}"
        ) from error

    required_fields = {
        "infrastructure_file",
        "rego_file",
        "fail",
        "unknown",
        "not_applicable",
        "pass",
    }

    missing_fields = required_fields - data.keys()

    if missing_fields:
        missing = ", ".join(sorted(missing_fields))

        raise ValueError(
            "Evaluation results are missing required fields: "
            f"{missing}"
        )

    for field_name in ("fail", "unknown", "not_applicable", "pass"):
        if not isinstance(data[field_name], list):
            raise ValueError(
                f"The '{field_name}' field must contain a list."
            )

    return data


def load_infrastructure_resource_count(
    infrastructure_path: str,
) -> int:
    """
    Count resources in the infrastructure file used during evaluation.
    """
    path = Path(infrastructure_path)

    if not path.exists():
        return 0

    try:
        with path.open("r", encoding="utf-8") as file:
            infrastructure = json.load(file)

    except (json.JSONDecodeError, OSError):
        return 0

    resources = infrastructure.get("resources", [])

    if not isinstance(resources, list):
        return 0

    return len(resources)


def sort_by_severity(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Sort findings from Critical to Low.
    """
    return sorted(
        items,
        key=lambda item: (
            -SEVERITY_ORDER.get(
                item.get("severity", "Low"),
                0,
            ),
            item.get("policy_id", ""),
            item.get("resource_id", ""),
        ),
    )


def build_recommendation(
    item: dict[str, Any],
) -> str:
    """
    Generate a basic recommendation based on a failed control.
    """
    control = item.get(
        "control",
        "unknown_control",
    )

    expected = item.get("expected_value")
    operator = item.get("operator", "equals")

    readable_control = control.replace("_", " ")

    if operator == "equals":
        return (
            f"Configure {readable_control} so that its value is "
            f"{format_value(expected)}."
        )

    if operator == "not_equals":
        return (
            f"Change {readable_control} so that it is not "
            f"{format_value(expected)}."
        )

    if operator == "greater_than_or_equal":
        return (
            f"Increase {readable_control} so that it is at least "
            f"{format_value(expected)}."
        )

    if operator == "less_than_or_equal":
        return (
            f"Reduce {readable_control} so that it is no more than "
            f"{format_value(expected)}."
        )

    if operator == "greater_than":
        return (
            f"Increase {readable_control} so that it is greater than "
            f"{format_value(expected)}."
        )

    if operator == "less_than":
        return (
            f"Reduce {readable_control} so that it is less than "
            f"{format_value(expected)}."
        )

    if operator == "contains":
        return (
            f"Add the required value "
            f"{format_value(expected)} to {readable_control}."
        )

    if operator == "not_contains":
        return (
            f"Remove the prohibited value "
            f"{format_value(expected)} from {readable_control}."
        )

    if operator == "all_of":
        return (
            "Enable or configure the required control: "
            f"{readable_control}."
        )

    if operator == "required_if":
        return (
            "Provide the required control because the triggering "
            "condition is present."
        )

    return (
        f"Review and correct the configuration for "
        f"{readable_control}."
    )


def build_report_data(
    evaluation_results: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert raw OPA results into a structured report.

    Every policy result is exactly one of four statuses:

        fail            observed, violates the policy
        unknown         could not be determined from the
                         infrastructure -- never assumed compliant
        not_applicable  the policy's question does not apply to this
                         resource
        pass            observed, satisfies the policy

    Overall status is NON_COMPLIANT if anything failed,
    REVIEW_REQUIRED if nothing failed but something is unknown (the
    framework cannot claim compliance for a control it could not
    observe), otherwise COMPLIANT.
    """
    fail = sort_by_severity(evaluation_results["fail"])
    unknown = sort_by_severity(evaluation_results["unknown"])
    not_applicable = sort_by_severity(evaluation_results["not_applicable"])
    passed = evaluation_results["pass"]

    infrastructure_file = evaluation_results["infrastructure_file"]
    resource_count = load_infrastructure_resource_count(infrastructure_file)

    fail_severity_counts = Counter(
        item.get("severity", "Unknown") for item in fail
    )

    unknown_severity_counts = Counter(
        item.get("severity", "Unknown") for item in unknown
    )

    affected_resources = sorted(
        {
            item.get("resource_id")
            for item in fail
            if item.get("resource_id")
        }
    )

    enriched_fail: list[dict[str, Any]] = []

    for item in fail:
        enriched = dict(item)
        enriched["recommendation"] = build_recommendation(item)
        enriched_fail.append(enriched)

    if fail:
        overall_status = "NON_COMPLIANT"
    elif unknown:
        overall_status = "REVIEW_REQUIRED"
    else:
        overall_status = "COMPLIANT"

    return {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "infrastructure_file": infrastructure_file,
            "rego_file": evaluation_results["rego_file"],
            "report_type": (
                "GDPR-inspired infrastructure policy report"
            ),
        },
        "summary": {
            "overall_status": overall_status,
            "resources_analysed": resource_count,
            "fail_count": len(fail),
            "unknown_count": len(unknown),
            "not_applicable_count": len(not_applicable),
            "pass_count": len(passed),
            "affected_resource_count": len(affected_resources),
            "affected_resources": affected_resources,
            "fail_by_severity": dict(
                sorted(
                    fail_severity_counts.items(),
                    key=lambda item: -SEVERITY_ORDER.get(item[0], 0),
                )
            ),
            "unknown_by_severity": dict(
                sorted(
                    unknown_severity_counts.items(),
                    key=lambda item: -SEVERITY_ORDER.get(item[0], 0),
                )
            ),
        },
        "fail": enriched_fail,
        "unknown": unknown,
        "not_applicable": not_applicable,
        "pass_count": len(passed),
        "limitations": [
            (
                "This report checks specific technical controls based "
                "on GDPR requirements. Passing these controls is "
                "evidence towards compliance, but it does not prove "
                "full legal GDPR compliance on its own."
            ),
            (
                "The policy set only covers requirements that can "
                "actually be checked from the infrastructure config. "
                "Things that need legal, organisational or business "
                "judgement (for example purpose limitation or "
                "processor contracts) are out of scope for automatic "
                "checking."
            ),
            (
                "If a control can't be worked out from the "
                "infrastructure, it's marked UNKNOWN - never assumed "
                "to be compliant or non-compliant."
            ),
            (
                "NOT_APPLICABLE means the policy doesn't apply to this "
                "resource (for example, a conditional requirement "
                "whose trigger wasn't met)."
            ),
        ],
    }


def save_json_report(
    report_data: dict[str, Any],
    output_path: Path = DEFAULT_JSON_REPORT_PATH,
) -> Path:
    """
    Save the structured report as JSON.
    """
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            report_data,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return output_path


def format_value(value: Any) -> str:
    """
    Convert a value into readable text.
    """
    if value is None:
        return "Missing"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, (dict, list)):
        return json.dumps(
            value,
            ensure_ascii=False,
        )

    return str(value)


def escape_html(value: Any) -> str:
    """
    Convert a value into safe HTML.
    """
    return html.escape(
        format_value(value),
        quote=True,
    )


def severity_class(severity: str) -> str:
    """
    Return the CSS class for a severity.
    """
    classes = {
        "Critical": "severity-critical",
        "High": "severity-high",
        "Medium": "severity-medium",
        "Low": "severity-low",
    }

    return classes.get(
        severity,
        "severity-unknown",
    )


def status_class(status: str) -> str:
    """
    Return the CSS class for the overall report status.
    """
    classes = {
        "NON_COMPLIANT": "overall-non-compliant",
        "REVIEW_REQUIRED": "overall-manual",
        "COMPLIANT": "overall-compliant",
    }

    return classes.get(
        status,
        "overall-unknown",
    )


def build_text_report(
    report_data: dict[str, Any],
) -> str:
    """
    Build a plain-text compliance report.
    """
    metadata = report_data["report_metadata"]
    summary = report_data["summary"]
    fail = report_data["fail"]
    unknown = report_data["unknown"]
    not_applicable = report_data["not_applicable"]

    lines: list[str] = []

    lines.extend(
        [
            "=" * 72,
            "GDPR-INSPIRED INFRASTRUCTURE COMPLIANCE REPORT",
            "=" * 72,
            "",
            f"Generated at: {metadata['generated_at']}",
            (
                "Infrastructure file: "
                f"{metadata['infrastructure_file']}"
            ),
            f"Rego file: {metadata['rego_file']}",
            "",
            "-" * 72,
            "SUMMARY",
            "-" * 72,
            "",
            f"Overall status: {summary['overall_status']}",
            f"Resources analysed: {summary['resources_analysed']}",
            f"Fail: {summary['fail_count']}",
            f"Unknown: {summary['unknown_count']}",
            f"Not applicable: {summary['not_applicable_count']}",
            f"Pass: {summary['pass_count']}",
            f"Affected resources: {summary['affected_resource_count']}",
            "",
        ]
    )

    if fail:
        lines.extend(
            [
                "-" * 72,
                "FAIL",
                "-" * 72,
                "",
            ]
        )

        for number, item in enumerate(fail, start=1):
            lines.extend(
                [
                    (
                        f"{number}. "
                        f"[{item.get('severity', 'Unknown')}] "
                        f"{item.get('title', 'Unknown policy')}"
                    ),
                    "",
                    f"   Policy ID: {item.get('policy_id', 'Unknown')}",
                    f"   Reference: {item.get('reference', 'Unknown')}",
                    f"   Resource: {item.get('resource_id', 'Unknown')}",
                    f"   Provider: {item.get('provider', 'Unknown')}",
                    f"   Original type: {item.get('original_type', 'Unknown')}",
                    f"   Resource type: {item.get('resource_type', 'Unknown')}",
                    f"   Control: {item.get('control', 'Unknown')}",
                    f"   Expected: {format_value(item.get('expected_value'))}",
                    f"   Actual: {format_value(item.get('actual_value'))}",
                    f"   Finding: {item.get('message', 'No message')}",
                    f"   Recommendation: {item.get('recommendation', '')}",
                    "",
                    "   Verification notes:",
                    f"   {item.get('verification_notes', '')}",
                    "",
                    "." * 72,
                    "",
                ]
            )
    else:
        lines.extend(
            [
                "-" * 72,
                "FAIL",
                "-" * 72,
                "",
                "No policies failed.",
                "",
            ]
        )

    if unknown:
        lines.extend(
            [
                "-" * 72,
                "UNKNOWN",
                "-" * 72,
                "",
            ]
        )

        for number, item in enumerate(unknown, start=1):
            lines.extend(
                [
                    (
                        f"{number}. "
                        f"[{item.get('severity', 'Unknown')}] "
                        f"{item.get('title', 'Unknown policy')}"
                    ),
                    f"   Resource: {item.get('resource_id', 'Unknown')}",
                    f"   Control: {item.get('control', 'Unknown')}",
                    (
                        "   Why it's unknown: the infrastructure did not "
                        "provide evidence for this control."
                    ),
                    "",
                ]
            )
    else:
        lines.extend(
            [
                "-" * 72,
                "UNKNOWN",
                "-" * 72,
                "",
                "No unknown results.",
                "",
            ]
        )

    if not_applicable:
        lines.extend(
            [
                "-" * 72,
                "NOT APPLICABLE",
                "-" * 72,
                "",
            ]
        )

        for item in not_applicable:
            lines.append(
                f"- {item.get('resource_id', 'Unknown')}: "
                f"{item.get('title', 'Unknown policy')}"
            )

        lines.append("")

    lines.extend(
        [
            "-" * 72,
            "LIMITATIONS",
            "-" * 72,
            "",
        ]
    )

    for limitation in report_data["limitations"]:
        lines.append(f"- {limitation}")

    lines.extend(
        [
            "",
            "=" * 72,
            "END OF REPORT",
            "=" * 72,
            "",
        ]
    )

    return "\n".join(lines)


def save_text_report(
    report_data: dict[str, Any],
    output_path: Path = DEFAULT_TEXT_REPORT_PATH,
) -> Path:
    """
    Save the plain-text report.
    """
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        build_text_report(report_data),
        encoding="utf-8",
    )

    return output_path


def build_fail_cards(
    fail: list[dict[str, Any]],
) -> str:
    """
    Build HTML cards for failing policies.
    """
    if not fail:
        return """
        <div class="empty-state success-state">
            <h3>No policies failed</h3>
            <p>
                The evaluated infrastructure did not produce any
                policy failures.
            </p>
        </div>
        """

    cards: list[str] = []

    for item in fail:
        severity = item.get("severity", "Unknown")

        cards.append(
            f"""
            <article class="finding">
                <div class="finding-header">
                    <div>
                        <span class="badge {severity_class(severity)}">
                            {escape_html(severity)}
                        </span>

                        <h3>
                            {escape_html(item.get("title", "Unknown policy"))}
                        </h3>
                    </div>

                    <span class="status non-compliant">Fail</span>
                </div>

                <div class="finding-grid">
                    <div>
                        <span class="label">Policy ID</span>
                        <span class="value">{escape_html(item.get("policy_id", "Unknown"))}</span>
                    </div>

                    <div>
                        <span class="label">GDPR reference</span>
                        <span class="value">{escape_html(item.get("reference", "Unknown"))}</span>
                    </div>

                    <div>
                        <span class="label">Resource</span>
                        <span class="value">{escape_html(item.get("resource_id", "Unknown"))}</span>
                    </div>

                    <div>
                        <span class="label">Provider</span>
                        <span class="value">{escape_html(item.get("provider", "Unknown"))}</span>
                    </div>

                    <div>
                        <span class="label">Terraform type</span>
                        <span class="value">{escape_html(item.get("original_type", "Unknown"))}</span>
                    </div>

                    <div>
                        <span class="label">Generic resource type</span>
                        <span class="value">{escape_html(item.get("resource_type", "Unknown"))}</span>
                    </div>

                    <div>
                        <span class="label">Control</span>
                        <span class="value">{escape_html(item.get("control", "Unknown"))}</span>
                    </div>

                    <div>
                        <span class="label">Expected value</span>
                        <span class="value">{escape_html(item.get("expected_value"))}</span>
                    </div>

                    <div>
                        <span class="label">Actual value</span>
                        <span class="value">{escape_html(item.get("actual_value"))}</span>
                    </div>
                </div>

                <div class="message-box">
                    <strong>Finding</strong>
                    <p>{escape_html(item.get("message", "No message available."))}</p>
                </div>

                <div class="recommendation-box">
                    <strong>Recommendation</strong>
                    <p>{escape_html(item.get("recommendation", "Review the infrastructure configuration."))}</p>
                </div>

                <details>
                    <summary>How the framework checked this policy</summary>
                    <p>{escape_html(item.get("verification_notes", "No verification notes available."))}</p>
                </details>
            </article>
            """
        )

    return "\n".join(cards)


def build_unknown_cards(
    unknown: list[dict[str, Any]],
) -> str:
    """
    Build HTML cards for policies whose controls could not be
    determined.
    """
    if not unknown:
        return """
        <div class="empty-state">
            <h3>No unknown results</h3>
            <p>
                Every applicable policy could be resolved to pass or
                fail from the available infrastructure evidence.
            </p>
        </div>
        """

    cards: list[str] = []

    for item in unknown:
        severity = item.get("severity", "Unknown")

        cards.append(
            f"""
            <article class="finding manual-finding">
                <div class="finding-header">
                    <div>
                        <span class="badge {severity_class(severity)}">
                            {escape_html(severity)}
                        </span>

                        <h3>{escape_html(item.get("title", "Unknown policy"))}</h3>
                    </div>

                    <span class="status manual">Unknown</span>
                </div>

                <div class="finding-grid">
                    <div>
                        <span class="label">Policy ID</span>
                        <span class="value">{escape_html(item.get("policy_id", "Unknown"))}</span>
                    </div>

                    <div>
                        <span class="label">GDPR reference</span>
                        <span class="value">{escape_html(item.get("reference", "Unknown"))}</span>
                    </div>

                    <div>
                        <span class="label">Resource</span>
                        <span class="value">{escape_html(item.get("resource_id", "Unknown"))}</span>
                    </div>

                    <div>
                        <span class="label">Control</span>
                        <span class="value">{escape_html(item.get("control", "Unknown"))}</span>
                    </div>
                </div>

                <div class="manual-box">
                    <strong>Why this is unknown</strong>
                    <p>
                        {escape_html(item.get("message", "The infrastructure did not provide evidence for this control."))}
                    </p>
                </div>

                <details>
                    <summary>How the framework checks this policy</summary>
                    <p>{escape_html(item.get("verification_notes", "No verification notes available."))}</p>
                </details>
            </article>
            """
        )

    return "\n".join(cards)


def build_not_applicable_list(
    not_applicable: list[dict[str, Any]],
) -> str:
    """
    Build a compact list for not-applicable results -- these are not
    findings that need attention, so they get a list, not full detail
    cards.
    """
    if not not_applicable:
        return "<p>No not-applicable results.</p>"

    items = "\n".join(
        (
            "<li>"
            f"<strong>{escape_html(item.get('resource_id', 'Unknown'))}</strong>"
            f" &mdash; {escape_html(item.get('title', 'Unknown policy'))}"
            "</li>"
        )
        for item in not_applicable
    )

    return f"<ul class='not-applicable-list'>{items}</ul>"


def build_html_report(
    report_data: dict[str, Any],
) -> str:
    """
    Build the browser-based HTML compliance report.
    """
    metadata = report_data["report_metadata"]
    summary = report_data["summary"]
    fail = report_data["fail"]
    unknown = report_data["unknown"]
    not_applicable = report_data["not_applicable"]
    limitations = report_data["limitations"]

    overall_status = summary["overall_status"]

    affected_resources = summary.get("affected_resources", [])

    if affected_resources:
        affected_resource_text = ", ".join(
            escape_html(resource) for resource in affected_resources
        )
    else:
        affected_resource_text = "None"

    limitation_items = "\n".join(
        f"<li>{escape_html(item)}</li>" for item in limitations
    )

    fail_cards = build_fail_cards(fail)
    unknown_cards = build_unknown_cards(unknown)
    not_applicable_list = build_not_applicable_list(not_applicable)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>
        GDPR-Inspired Infrastructure Compliance Report
    </title>

    <style>
        :root {{
            --background: #f3f4f6;
            --surface: #ffffff;
            --text: #171717;
            --muted: #626262;
            --border: #d9d9d9;
            --header: #111827;

            --critical-background: #fee2e2;
            --critical-text: #7f1d1d;

            --high-background: #ffedd5;
            --high-text: #9a3412;

            --medium-background: #fef9c3;
            --medium-text: #854d0e;

            --low-background: #dcfce7;
            --low-text: #166534;

            --manual-background: #e0e7ff;
            --manual-text: #3730a3;

            --info-background: #eff6ff;
            --info-border: #bfdbfe;

            --warning-background: #fff7ed;
            --warning-border: #fed7aa;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            background: var(--background);
            color: var(--text);
            font-family:
                Inter,
                Arial,
                Helvetica,
                sans-serif;
            line-height: 1.5;
        }}

        header {{
            background: var(--header);
            color: white;
            padding: 34px 20px;
        }}

        header .container {{
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 24px;
        }}

        header h1 {{
            margin: 0 0 8px;
            font-size: 29px;
        }}

        header p {{
            margin: 0;
            color: #d1d5db;
        }}

        .container {{
            width: min(
                1180px,
                calc(100% - 32px)
            );
            margin: 0 auto;
        }}

        main {{
            padding: 28px 0 48px;
        }}

        .overall-status {{
            display: inline-block;
            padding: 8px 14px;
            border-radius: 999px;
            font-weight: bold;
            white-space: nowrap;
        }}

        .overall-non-compliant {{
            background: var(--critical-background);
            color: var(--critical-text);
        }}

        .overall-manual {{
            background: var(--manual-background);
            color: var(--manual-text);
        }}

        .overall-compliant {{
            background: var(--low-background);
            color: var(--low-text);
        }}

        .overall-unknown {{
            background: #e5e7eb;
            color: #374151;
        }}

        .metrics {{
            display: grid;
            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(190px, 1fr)
                );
            gap: 16px;
            margin-bottom: 28px;
        }}

        .metric {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px;
        }}

        .metric-label {{
            display: block;
            color: var(--muted);
            font-size: 14px;
            margin-bottom: 6px;
        }}

        .metric-value {{
            display: block;
            font-size: 28px;
            font-weight: bold;
        }}

        section {{
            margin-top: 34px;
        }}

        section > h2 {{
            margin-bottom: 15px;
        }}

        .finding {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-left: 5px solid var(--critical-text);
            border-radius: 12px;
            margin-bottom: 17px;
            padding: 20px;
        }}

        .manual-finding {{
            border-left-color: var(--manual-text);
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 16px;
            margin-bottom: 18px;
        }}

        .finding-header h3 {{
            margin: 10px 0 0;
            font-size: 20px;
        }}

        .badge,
        .status {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: bold;
        }}

        .severity-critical {{
            background: var(--critical-background);
            color: var(--critical-text);
        }}

        .severity-high {{
            background: var(--high-background);
            color: var(--high-text);
        }}

        .severity-medium {{
            background: var(--medium-background);
            color: var(--medium-text);
        }}

        .severity-low {{
            background: var(--low-background);
            color: var(--low-text);
        }}

        .severity-unknown {{
            background: #e5e7eb;
            color: #374151;
        }}

        .status.non-compliant {{
            background: var(--critical-background);
            color: var(--critical-text);
        }}

        .status.manual {{
            background: var(--manual-background);
            color: var(--manual-text);
        }}

        .finding-grid {{
            display: grid;
            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(210px, 1fr)
                );
            gap: 14px;
            margin-bottom: 18px;
        }}

        .finding-grid > div {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
        }}

        .label {{
            display: block;
            color: var(--muted);
            font-size: 13px;
            margin-bottom: 3px;
        }}

        .value {{
            display: block;
            overflow-wrap: anywhere;
        }}

        .message-box,
        .recommendation-box,
        .requirement-box,
        .manual-box {{
            border-radius: 9px;
            padding: 14px;
            margin: 12px 0;
        }}

        .message-box {{
            background: #fef2f2;
            border: 1px solid #fecaca;
        }}

        .recommendation-box {{
            background: var(--info-background);
            border: 1px solid var(--info-border);
        }}

        .requirement-box {{
            background: #f9fafb;
            border: 1px solid var(--border);
        }}

        .manual-box {{
            background: var(--manual-background);
            border: 1px solid #c7d2fe;
        }}

        .message-box p,
        .recommendation-box p,
        .requirement-box p,
        .manual-box p {{
            margin: 4px 0 0;
        }}

        details {{
            margin-top: 14px;
        }}

        summary {{
            cursor: pointer;
            font-weight: bold;
        }}

        .information-panel {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }}

        .information-panel dl {{
            display: grid;
            grid-template-columns:
                max-content 1fr;
            gap: 8px 20px;
        }}

        .information-panel dt {{
            font-weight: bold;
        }}

        .information-panel dd {{
            margin: 0;
            overflow-wrap: anywhere;
        }}

        .limitations {{
            background: var(--warning-background);
            border: 1px solid var(--warning-border);
            border-radius: 12px;
            padding: 20px;
        }}

        .limitations li + li {{
            margin-top: 8px;
        }}

        .empty-state {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
        }}

        .empty-state h3 {{
            margin-top: 0;
        }}

        .success-state {{
            border-left: 5px solid var(--low-text);
        }}

        .not-applicable-list {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 20px 20px 40px;
            margin: 0;
        }}

        .not-applicable-list li + li {{
            margin-top: 8px;
        }}

        footer {{
            color: var(--muted);
            font-size: 13px;
            padding: 24px 0;
            text-align: center;
        }}

        @media (max-width: 650px) {{
            header .container,
            .finding-header {{
                flex-direction: column;
            }}

            .information-panel dl {{
                grid-template-columns: 1fr;
            }}

            .information-panel dd {{
                margin-bottom: 10px;
            }}
        }}
    </style>
</head>

<body>
    <header>
        <div class="container">
            <div>
                <h1>
                    GDPR-Inspired Infrastructure Compliance Report
                </h1>

                <p>
                    Automated Policy-as-Code infrastructure assessment
                </p>
            </div>

            <span
                class="
                    overall-status
                    {status_class(overall_status)}
                "
            >
                {escape_html(overall_status)}
            </span>
        </div>
    </header>

    <main class="container">
        <div class="metrics">
            <div class="metric">
                <span class="metric-label">Resources analysed</span>
                <span class="metric-value">{summary["resources_analysed"]}</span>
            </div>

            <div class="metric">
                <span class="metric-label">Fail</span>
                <span class="metric-value">{summary["fail_count"]}</span>
            </div>

            <div class="metric">
                <span class="metric-label">Unknown</span>
                <span class="metric-value">{summary["unknown_count"]}</span>
            </div>

            <div class="metric">
                <span class="metric-label">Not applicable</span>
                <span class="metric-value">{summary["not_applicable_count"]}</span>
            </div>

            <div class="metric">
                <span class="metric-label">Pass</span>
                <span class="metric-value">{summary["pass_count"]}</span>
            </div>
        </div>

        <section>
            <h2>Assessment details</h2>

            <div class="information-panel">
                <dl>
                    <dt>Generated</dt>
                    <dd>{escape_html(metadata["generated_at"])}</dd>

                    <dt>Infrastructure file</dt>
                    <dd>{escape_html(metadata["infrastructure_file"])}</dd>

                    <dt>Generated Rego file</dt>
                    <dd>{escape_html(metadata["rego_file"])}</dd>

                    <dt>Affected resources</dt>
                    <dd>{affected_resource_text}</dd>
                </dl>
            </div>
        </section>

        <section>
            <h2>Fail</h2>
            {fail_cards}
        </section>

        <section>
            <h2>Unknown</h2>
            {unknown_cards}
        </section>

        <section>
            <h2>Not applicable</h2>
            {not_applicable_list}
        </section>

        <section>
            <h2>Assessment limitations</h2>

            <div class="limitations">
                <ul>
                    {limitation_items}
                </ul>
            </div>
        </section>
    </main>

    <footer class="container">
        Generated by the Policy-as-Code verification framework.
    </footer>
</body>
</html>
"""


def save_html_report(
    report_data: dict[str, Any],
    output_path: Path = DEFAULT_HTML_REPORT_PATH,
) -> Path:
    """
    Save the browser-based HTML report.
    """
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        build_html_report(report_data),
        encoding="utf-8",
    )

    return output_path


def open_html_report(
    report_path: Path,
) -> None:
    """
    Open the generated HTML report in the default browser.
    """
    opened = webbrowser.open(
        report_path.resolve().as_uri()
    )

    if not opened:
        print(
            "The browser could not be opened automatically."
        )

        print(
            "Open this file manually:"
        )

        print(report_path)


def generate_reports(
    evaluation_path: Path = DEFAULT_EVALUATION_PATH,
    json_output_path: Path = DEFAULT_JSON_REPORT_PATH,
    text_output_path: Path = DEFAULT_TEXT_REPORT_PATH,
    html_output_path: Path = DEFAULT_HTML_REPORT_PATH,
    open_browser: bool = True,
) -> dict[str, Path]:
    """
    Generate JSON, text and browser-based HTML reports.
    """
    evaluation_results = load_evaluation_results(evaluation_path)

    report_data = build_report_data(evaluation_results)

    json_path = save_json_report(report_data, json_output_path)
    text_path = save_text_report(report_data, text_output_path)
    html_path = save_html_report(report_data, html_output_path)

    print("\nCompliance report generation successful.")
    print(f"Overall status: {report_data['summary']['overall_status']}")
    print(f"Fail: {report_data['summary']['fail_count']}")
    print(f"Unknown: {report_data['summary']['unknown_count']}")
    print(f"Not applicable: {report_data['summary']['not_applicable_count']}")
    print(f"Pass: {report_data['summary']['pass_count']}")

    print(f"JSON report: {json_path}")
    print(f"Text report: {text_path}")
    print(f"HTML report: {html_path}")

    if open_browser:
        open_html_report(html_path)
        print("The HTML report was sent to your default browser.")

    return {
        "json_report": json_path,
        "text_report": text_path,
        "html_report": html_path,
    }


if __name__ == "__main__":
    try:
        generate_reports()

    except (
        FileNotFoundError,
        ValueError,
        KeyError,
        TypeError,
        OSError,
    ) as error:
        print(
            f"\nReport generation failed:\n{error}"
        )

        raise SystemExit(1)
