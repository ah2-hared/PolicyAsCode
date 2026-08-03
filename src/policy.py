from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class Policy:
    id: str
    policy_source: str
    reference: str
    title: str
    description: str
    subject: str
    action: str
    resource_type: str
    control: str
    operator: str
    expected_value: Any
    cia_category: str
    severity: str
    automation_level: str
    verification_notes: str
    message: str
    tags: list[str]
