import unittest
from pathlib import Path

from firewall import Decision, PrivacyFirewall, PrivacyPolicy, ToolCall
from firewall.models import Flow
from firewall.policy import Rule
from firewall.verifier import find_conflicts


PROJECT_ROOT = Path(__file__).parent.parent
PROFILE_PATH = PROJECT_ROOT / "data" / "user_knowledge.json"


class PrivacyFirewallTests(unittest.TestCase):
    def setUp(self):
        self.policy = PrivacyPolicy.from_json(PROFILE_PATH)

        self.firewall = PrivacyFirewall(
            self.policy,
            attribute_map={
                "message": "appointment_request",
                "insurance_id": "insurance_id",
                "diagnosis": "diagnosis",
            },
        )

    def test_explicit_permission_allows_appointment_request(self):
        """A scheduling request to the verified clinic should be allowed."""
        flow = Flow(
            context="healthcare",
            sender="personal_agent",
            recipient="clinic_scheduler",
            subject="user",
            attribute="appointment_request",
            purpose="reschedule_appointment",
        )

        decision, _ = self.policy.decision_for(flow)

        self.assertEqual(decision, Decision.ALLOW)

    def test_explicit_veto_denies_diagnosis_disclosure(self):
        """An explicit veto must block diagnosis disclosure."""
        flow = Flow(
            context="healthcare",
            sender="personal_agent",
            recipient="clinic_scheduler",
            subject="user",
            attribute="diagnosis",
            purpose="reschedule_appointment",
        )

        decision, _ = self.policy.decision_for(flow)

        self.assertEqual(decision, Decision.DENY)

    def test_unnecessary_insurance_id_is_redacted(self):
        """The agent may not send extra insurance information for scheduling."""
        flow = Flow(
            context="healthcare",
            sender="personal_agent",
            recipient="clinic_scheduler",
            subject="user",
            attribute="insurance_id",
            purpose="reschedule_appointment",
        )

        decision, _ = self.policy.decision_for(flow)

        self.assertEqual(decision, Decision.REDACT)

    def test_unknown_recipient_requires_user_decision(self):
        """A new recipient should not inherit clinic permissions."""
        flow = Flow(
            context="healthcare",
            sender="personal_agent",
            recipient="advertising_service",
            subject="user",
            attribute="appointment_request",
            purpose="reschedule_appointment",
        )

        decision, _ = self.policy.decision_for(flow)

        self.assertEqual(decision, Decision.ESCALATE)

    def test_firewall_sanitizes_a_tool_call(self):
        """Only the approved scheduling message should survive interception."""
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

        result = self.firewall.intercept(call)

        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(
            result.approved_arguments,
            {"message": "Could I reschedule my appointment for next week?"},
        )

    def test_conflicting_allow_and_deny_rules_are_detected(self):
        """Z3 should flag a policy that simultaneously allows and denies a flow."""
        conflicting_policy = PrivacyPolicy(
            [
                Rule(
                    effect=Decision.ALLOW,
                    context="healthcare",
                    recipient="clinic_scheduler",
                    attribute="appointment_request",
                    purpose="reschedule_appointment",
                ),
                Rule(
                    effect=Decision.DENY,
                    context="healthcare",
                    recipient="clinic_scheduler",
                    attribute="appointment_request",
                    purpose="reschedule_appointment",
                ),
            ]
        )

        flow = Flow(
            context="healthcare",
            sender="personal_agent",
            recipient="clinic_scheduler",
            subject="user",
            attribute="appointment_request",
            purpose="reschedule_appointment",
        )

        conflicts = find_conflicts(conflicting_policy, [flow])

        self.assertEqual(len(conflicts), 1)
        self.assertIn("Conflict", conflicts[0])


if __name__ == "__main__":
    unittest.main()
