from pathlib import Path

from firewall import PrivacyFirewall, PrivacyPolicy, ToolCall
from firewall.verifier import find_conflicts


def main() -> None:
    project_root = Path(__file__).parent
    policy = PrivacyPolicy.from_json(project_root / "data" / "user_knowledge.json")

    firewall = PrivacyFirewall(
        policy,
        attribute_map={
            "message": "appointment_request",
            "insurance_id": "insurance_id",
            "diagnosis": "diagnosis",
        },
    )
    call = ToolCall(
        tool="send_email",
        recipient="clinic_scheduler",
        context="healthcare",
        purpose="reschedule_appointment",
        arguments={
            "message": "Could I reschedule my appointment for next week?",
            "insurance_id": "ZX-12345",
            "diagnosis": "migraine",
        },
    )

    result = firewall.intercept(call)
    print(f"Overall decision: {result.decision.value}\n")
    for item in result.field_results:
        print(f"{item.field}: {item.decision.value} — {item.reason}")
    print("\nSanitized tool arguments:")
    print(result.approved_arguments)

    conflicts = find_conflicts(policy, [item.flow for item in result.field_results])
    print("\nPolicy conflicts:", conflicts or "None")


if __name__ == "__main__":
    main()
