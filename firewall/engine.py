from dataclasses import dataclass
from typing import Any

from .models import Decision, Flow, ToolCall
from .policy import PrivacyPolicy


@dataclass
class FieldResult:
    field: str
    decision: Decision
    reason: str
    flow: Flow


@dataclass
class InterceptionResult:
    decision: Decision
    approved_arguments: dict[str, Any]
    field_results: list[FieldResult]


class PrivacyFirewall:
    """External gatekeeper for an agent's proposed tool arguments."""

    def __init__(self, policy: PrivacyPolicy, attribute_map: dict[str, str]):
        self.policy = policy
        self.attribute_map = attribute_map

    def flow_for(self, call: ToolCall, field: str) -> Flow:
        return Flow(
            context=call.context,
            sender="personal_agent",
            recipient=call.recipient,
            subject="user",
            attribute=self.attribute_map.get(field, field),
            purpose=call.purpose,
        )

    def intercept(self, call: ToolCall) -> InterceptionResult:
        approved: dict[str, Any] = {}
        results: list[FieldResult] = []

        for field, value in call.arguments.items():
            flow = self.flow_for(call, field)
            decision, reason = self.policy.decision_for(flow)
            results.append(FieldResult(field, decision, reason, flow))
            if decision == Decision.ALLOW:
                approved[field] = value

        decisions = {result.decision for result in results}
        overall = (
            Decision.DENY if Decision.DENY in decisions else
            Decision.ESCALATE if Decision.ESCALATE in decisions else
            Decision.REDACT if Decision.REDACT in decisions else
            Decision.ALLOW
        )
        return InterceptionResult(overall, approved, results)
