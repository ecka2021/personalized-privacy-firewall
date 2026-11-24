from .models import Decision, Flow
from .policy import PrivacyPolicy


def find_conflicts(policy: PrivacyPolicy, flows: list[Flow]) -> list[str]:
    """Find allow/deny conflicts using Z3 when it is installed.

    The function keeps the policy language simple now, while giving the project
    a concrete place to add richer constraint encoding later.
    """
    try:
        from z3 import Bool, Not, Solver
    except ImportError:
        return ["Z3 is not installed. Run: python -m pip install -r requirements.txt"]

    conflicts: list[str] = []
    for flow in flows:
        matching = policy.rules_for(flow)
        allowed = Bool("allowed")
        solver = Solver()
        for rule in matching:
            if rule.effect == Decision.ALLOW:
                solver.add(allowed)
            elif rule.effect == Decision.DENY:
                solver.add(Not(allowed))
        if solver.check().r == -1:  # unsatisfiable
            conflicts.append(
                f"Conflict for {flow.attribute} -> {flow.recipient} ({flow.purpose})."
            )
    return conflicts
