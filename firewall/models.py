from dataclasses import dataclass
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


@dataclass(frozen=True)
class Flow:
    """One proposed disclosure, expressed as a CI-style information flow."""

    context: str
    sender: str
    recipient: str
    subject: str
    attribute: str
    purpose: str
    condition: str = "user_requested"


@dataclass(frozen=True)
class ToolCall:
    tool: str
    recipient: str
    context: str
    purpose: str
    arguments: dict[str, Any]
