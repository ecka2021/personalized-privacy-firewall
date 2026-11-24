# Personalized Privacy Firewall

A small prototype for checking whether an AI agent may send particular pieces
of information to a tool.  It represents each proposed disclosure as a
Contextual Integrity (CI) flow and produces one of four decisions:

- `ALLOW` — the tool receives the field.
- `REDACT` — the tool call may proceed, but the field is removed.
- `DENY` — the tool call is blocked.
- `ESCALATE` — the user must decide because the policy is unclear or conflicts.

This first version is deliberately small and inspectable. It includes:

- a CI flow model: context, sender, recipient, subject, attribute, purpose,
  and condition;
- a JSON policy profile with explicit permissions, vetoes, and precedent;
- a Z3 consistency check for allow/veto conflicts;
- a mock tool-call interceptor that sanitizes arguments before a tool sees them.

## Quick start

```bash
cd privacy_firewall
python -m pip install -r requirements.txt
python demo.py
```

The demo is about rescheduling a medical appointment. The agent tries to send
an appointment request, insurance ID, and diagnosis to a clinic. The firewall
allows the appointment request, redacts the insurance ID because it is not
needed for rescheduling, and blocks the diagnosis because the user explicitly
vetoed that disclosure.

## Edit the privacy profile

Open `data/user_knowledge.json`. Every rule is deliberately narrow: it names a
context, recipient, attribute, and purpose. `rules` are explicit preferences;
`precedents` are past decisions that may support an identical future flow. A
precedent should never be written with broad wildcards unless the user clearly
intends a standing permission.

## Next research steps

1. Replace hand-written `Flow` objects with an extractor from tool schemas and
   natural-language user requests.
2. Make rules real Datalog predicates (for example, with `pyDatalog`) once the
   initial semantics feel stable.
3. Add roles and hierarchies: a clinic scheduler is a healthcare provider, but
   an advertising tracker is not.
4. Record audit traces and evaluate privacy violations, unnecessary escalation,
   and task completion on mock multi-tool workflows.
5. Add user-specific precedents: a narrow prior approval should not become a
   blanket permission.
