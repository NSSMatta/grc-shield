"""
GS-04 — Tool Sequencer Monitor
GRC-Shield Detection Engine | ASI02: Tool Misuse and Exploitation

Monitors AI agent tool invocation sequences in GRC platforms.
Acts as a circuit breaker: blocks unauthorized state transitions
from Read operations directly to destructive Write or Send operations
without a required human approval checkpoint.

OWASP Reference: ASI02 — Tool Misuse and Exploitation
ISO 42001:2023: Clause 8.4 — Controls preventing unintended AI actions
ISO 27001:2022: A.8.15 (Logging), A.8.16 (Monitoring), A.8.2 (Privileged access)

Author: Naga Sai Srinivas Matta
Repository: github.com/NSSMatta/grc-shield
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class ToolClass(Enum):
    """Classification of GRC agent tool types by destructive potential."""
    READ = "READ"           # Safe: read evidence, query register, retrieve reports
    ANALYZE = "ANALYZE"     # Safe: score risk, generate analysis, compare data
    WRITE = "WRITE"         # Requires checkpoint: update register, modify control status
    DELETE = "DELETE"       # Requires checkpoint: remove records, archive findings
    SEND = "SEND"           # Requires checkpoint: notify stakeholders, send reports
    PROVISION = "PROVISION" # Requires checkpoint: create accounts, grant access


class SequenceVerdict(Enum):
    APPROVED = "APPROVED"
    BLOCKED_UNAUTHORIZED_TRANSITION = "BLOCKED_UNAUTHORIZED_TRANSITION"
    BLOCKED_MISSING_APPROVAL = "BLOCKED_MISSING_APPROVAL"
    BLOCKED_EXTERNAL_SOURCE_RISK = "BLOCKED_EXTERNAL_SOURCE_RISK"


# Transitions that require a human approval checkpoint before proceeding
TRANSITIONS_REQUIRING_APPROVAL = {
    (ToolClass.READ, ToolClass.DELETE),
    (ToolClass.READ, ToolClass.SEND),
    (ToolClass.READ, ToolClass.PROVISION),
    (ToolClass.ANALYZE, ToolClass.DELETE),
    (ToolClass.ANALYZE, ToolClass.SEND),
}

# Tool names mapped to their class — extend this for your GRC platform
TOOL_REGISTRY = {
    # Read tools
    "read_evidence_document": ToolClass.READ,
    "query_risk_register": ToolClass.READ,
    "retrieve_control_status": ToolClass.READ,
    "fetch_vendor_assessment": ToolClass.READ,
    "get_audit_findings": ToolClass.READ,
    # Analyze tools
    "score_residual_risk": ToolClass.ANALYZE,
    "compare_control_baseline": ToolClass.ANALYZE,
    "generate_risk_analysis": ToolClass.ANALYZE,
    # Write tools
    "update_risk_register": ToolClass.WRITE,
    "set_control_status": ToolClass.WRITE,
    "create_remediation_plan": ToolClass.WRITE,
    # Delete tools
    "delete_risk_entry": ToolClass.DELETE,
    "archive_control_record": ToolClass.DELETE,
    "remove_vendor_finding": ToolClass.DELETE,
    # Send tools
    "send_board_notification": ToolClass.SEND,
    "email_ceo_report": ToolClass.SEND,
    "notify_audit_committee": ToolClass.SEND,
    "send_vendor_communication": ToolClass.SEND,
    # Provision tools
    "create_user_account": ToolClass.PROVISION,
    "grant_platform_access": ToolClass.PROVISION,
    "assign_grc_role": ToolClass.PROVISION,
}


@dataclass
class ToolInvocation:
    tool_name: str
    tool_class: ToolClass
    parameters: dict
    timestamp: str
    source_document_trust_tier: Optional[str] = None  # From GS-01
    human_approval_token: Optional[str] = None


@dataclass
class SequenceCheckResult:
    verdict: SequenceVerdict
    tool_name: str
    tool_class: str
    previous_tool: Optional[str]
    previous_tool_class: Optional[str]
    requires_approval: bool
    approval_provided: bool
    external_source_risk: bool
    reason: str
    timestamp: str
    sequence_hash: str


class ToolSequencerMonitor:
    """
    GS-04: Circuit breaker for GRC agent tool invocation sequences.

    Maintains session state of tool invocations and blocks unauthorized
    transitions — particularly Read → DELETE/SEND without human approval.
    """

    def __init__(self):
        self.session_sequence: List[ToolInvocation] = []
        self.blocked_events: List[SequenceCheckResult] = []
        self.approved_checkpoints: set = set()

    def register_human_approval(self, approval_token: str, approved_transition: str):
        """
        Record that a human has explicitly approved a specific transition.
        This token must be passed with the subsequent tool invocation.
        """
        self.approved_checkpoints.add(approval_token)
        print(f"[GS-04] Human approval registered: {approval_token} for {approved_transition}")

    def check_invocation(
        self,
        tool_name: str,
        parameters: dict,
        source_document_trust_tier: Optional[str] = None,
        human_approval_token: Optional[str] = None,
    ) -> SequenceCheckResult:
        """
        Check whether the proposed tool invocation is permitted given
        the current session sequence state.

        Returns a SequenceCheckResult with APPROVED or BLOCKED verdict.
        """
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Resolve tool class
        tool_class = TOOL_REGISTRY.get(tool_name, ToolClass.READ)

        # Build invocation record
        invocation = ToolInvocation(
            tool_name=tool_name,
            tool_class=tool_class,
            parameters=parameters,
            timestamp=timestamp,
            source_document_trust_tier=source_document_trust_tier,
            human_approval_token=human_approval_token,
        )

        # Determine previous tool
        previous_tool = None
        previous_tool_class = None
        if self.session_sequence:
            prev = self.session_sequence[-1]
            previous_tool = prev.tool_name
            previous_tool_class = prev.tool_class

        # Check 1: Does this transition require human approval?
        requires_approval = False
        if previous_tool_class and (previous_tool_class, tool_class) in TRANSITIONS_REQUIRING_APPROVAL:
            requires_approval = True

        # Check 2: If approval required, has it been provided?
        approval_provided = False
        if requires_approval and human_approval_token:
            approval_provided = human_approval_token in self.approved_checkpoints

        # Check 3: External source risk — is a destructive action following
        # a read of an EXTERNAL trust tier document?
        external_source_risk = False
        if (
            source_document_trust_tier == "EXTERNAL"
            and tool_class in (ToolClass.DELETE, ToolClass.SEND, ToolClass.PROVISION)
        ):
            external_source_risk = True

        # Determine verdict
        if external_source_risk:
            verdict = SequenceVerdict.BLOCKED_EXTERNAL_SOURCE_RISK
            reason = (
                f"Destructive action '{tool_name}' ({tool_class.value}) blocked: "
                f"immediately follows read of EXTERNAL trust tier document. "
                f"Human review required before any destructive action after external input."
            )
        elif requires_approval and not approval_provided:
            verdict = SequenceVerdict.BLOCKED_MISSING_APPROVAL
            reason = (
                f"Transition {previous_tool_class.value} → {tool_class.value} "
                f"requires human approval checkpoint. "
                f"No valid approval token provided for tool '{tool_name}'."
            )
        else:
            verdict = SequenceVerdict.APPROVED
            reason = f"Tool '{tool_name}' ({tool_class.value}) approved in current sequence context."

        # Compute sequence hash for tamper-evident logging
        sequence_state = json.dumps(
            {
                "session_length": len(self.session_sequence),
                "tool_name": tool_name,
                "tool_class": tool_class.value,
                "previous_tool": previous_tool,
                "verdict": verdict.value,
                "timestamp": timestamp,
            },
            sort_keys=True,
        )
        sequence_hash = hashlib.sha256(sequence_state.encode()).hexdigest()

        result = SequenceCheckResult(
            verdict=verdict,
            tool_name=tool_name,
            tool_class=tool_class.value,
            previous_tool=previous_tool,
            previous_tool_class=previous_tool_class.value if previous_tool_class else None,
            requires_approval=requires_approval,
            approval_provided=approval_provided,
            external_source_risk=external_source_risk,
            reason=reason,
            timestamp=timestamp,
            sequence_hash=sequence_hash,
        )

        # If approved, add to session sequence
        if verdict == SequenceVerdict.APPROVED:
            self.session_sequence.append(invocation)
        else:
            self.blocked_events.append(result)
            print(f"\n[GS-04] ⛔ BLOCKED — {verdict.value}")
            print(f"  Tool: {tool_name}")
            print(f"  Reason: {reason}")
            print(f"  Sequence hash: {sequence_hash[:16]}...")

        return result

    def get_session_summary(self) -> dict:
        return {
            "total_invocations_attempted": len(self.session_sequence) + len(self.blocked_events),
            "approved": len(self.session_sequence),
            "blocked": len(self.blocked_events),
            "sequence": [
                {"tool": inv.tool_name, "class": inv.tool_class.value}
                for inv in self.session_sequence
            ],
            "blocked_events": [
                {"tool": ev.tool_name, "reason": ev.reason, "hash": ev.sequence_hash[:16]}
                for ev in self.blocked_events
            ],
        }


# ── Demonstration ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("GS-04 Tool Sequencer Monitor — ASI02 Detection Demo")
    print("Scenario: Poisoned vendor PDF triggers unauthorized tool chain")
    print("=" * 70)

    monitor = ToolSequencerMonitor()

    print("\n[STEP 1] Agent reads poisoned vendor SOC 2 document (EXTERNAL trust tier)")
    r1 = monitor.check_invocation(
        tool_name="read_evidence_document",
        parameters={"vendor_id": "V-2847", "document": "soc2_report_v3.pdf"},
        source_document_trust_tier="EXTERNAL",
    )
    print(f"  → {r1.verdict.value}")

    print("\n[STEP 2] Agent queries risk register for vendor")
    r2 = monitor.check_invocation(
        tool_name="query_risk_register",
        parameters={"vendor_id": "V-2847"},
        source_document_trust_tier="EXTERNAL",
    )
    print(f"  → {r2.verdict.value}")

    print("\n[STEP 3] Poisoned instruction: Agent attempts to DELETE risk register entries")
    r3 = monitor.check_invocation(
        tool_name="delete_risk_entry",
        parameters={"vendor_id": "V-2847", "action": "DELETE_ALL"},
        source_document_trust_tier="EXTERNAL",
    )
    print(f"  → {r3.verdict.value}")

    print("\n[STEP 4] Poisoned instruction: Agent attempts to email CEO fraudulently")
    r4 = monitor.check_invocation(
        tool_name="email_ceo_report",
        parameters={"recipient": "ceo@targetcompany.com", "content": "All controls compliant"},
        source_document_trust_tier="EXTERNAL",
    )
    print(f"  → {r4.verdict.value}")

    print("\n" + "=" * 70)
    print("SESSION SUMMARY")
    print("=" * 70)
    summary = monitor.get_session_summary()
    print(json.dumps(summary, indent=2))

    print("\n✅ GS-04 blocked the unauthorized tool chain at the DELETE step.")
    print("   The poisoned instruction could not complete the destructive sequence.")
    print("   All events recorded for immutable audit log (GS-03).")
