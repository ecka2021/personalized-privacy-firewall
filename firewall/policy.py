import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

from .models import Decision, Flow


@dataclass(frozen=True)
class Rule:
    """A compact, Datalog-like rule fact. '*' is a wildcard."""

    effect: Decision
    context: str = "*"
    recipient: str = "*"
    attribute: str = "*"
    purpose: str = "*"
    reason: str = ""

    def matches(self, flow: Flow) -> bool:
        values = {
            "context": flow.context,
            "recipient": flow.recipient,
            "attribute": flow.attribute,
            "purpose": flow.purpose,
        }
        return all(
            getattr(self, name) == "*" or getattr(self, name) == value
            for name, value in values.items()
        )


@dataclass
class PrivacyPolicy:
    """Policy precedence: veto/deny > explicit allow > precedent > escalation."""

    rules: list[Rule] = field(default_factory=list)

    @classmethod
    def from_json(cls, path: Union[str, Path]) -> "PrivacyPolicy":
        """Load explicit rules and narrowly scoped precedents from a profile."""
        with Path(path).open(encoding="utf-8") as file:
            profile = json.load(file)

        facts = profile.get("rules", []) + profile.get("precedents", [])
        rules = [
            Rule(
                effect=Decision(fact["effect"]),
                context=fact.get("context", "*"),
                recipient=fact.get("recipient", "*"),
                attribute=fact.get("attribute", "*"),
                purpose=fact.get("purpose", "*"),
                reason=fact.get("reason", ""),
            )
            for fact in facts
        ]
        return cls(rules)

    def add(self, rule: Rule) -> None:
        self.rules.append(rule)

    def decision_for(self, flow: Flow) -> tuple[Decision, str]:
        matching = [rule for rule in self.rules if rule.matches(flow)]

        # An explicit veto must remain stronger than a general permission.
        denials = [r for r in matching if r.effect == Decision.DENY]
        if denials:
            return Decision.DENY, denials[0].reason or "An explicit privacy veto applies."

        redactions = [r for r in matching if r.effect == Decision.REDACT]
        if redactions:
            return Decision.REDACT, redactions[0].reason or "This field is unnecessary."

        allows = [r for r in matching if r.effect == Decision.ALLOW]
        if allows:
            return Decision.ALLOW, allows[0].reason or "This flow is permitted."

        return Decision.ESCALATE, "No policy establishes that this disclosure is appropriate."

    def rules_for(self, flow: Flow) -> list[Rule]:
        return [rule for rule in self.rules if rule.matches(flow)]
