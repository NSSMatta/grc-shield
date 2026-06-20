"""
GS-05 — Privilege Scope Monitor
GRC-Shield Detection Engine | ASI03: Identity and Privilege Abuse

Enforces workflow-scoped permission boundaries for GRC AI agents.
Even if an agent service account technically holds a permission,
GS-05 blocks its use if it falls outside the current workflow's
defined operational scope.

OWASP Reference: ASI03 — Identity and Privilege Abuse
ISO 42001:2023: Clause 8.4, 8.6
ISO 27001:2022: A.5.15, A.5.18, A.8.2, A.5.3

Author: Naga Sai Srinivas Matta
Repository: github.com/NSSMatta/grc-shield
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, Optional, Set


class PrivilegeClass(Enum):
    """Permission classes a GRC agent service account may hold."""
    READ_EVIDENCE = "READ_EVIDENCE"
    READ_RISK_REGISTER = "READ_RISK_REGISTER"
    WRITE_RISK_REGISTER = "WRITE_RISK_REGISTER"
    WRITE_CONTROL_STATUS = "WRITE_CONTROL_STATUS"
    SEND_NOTIFICATIONS = "SEND_NOTIFICATIONS"
    ADMIN_USER_PROVISIONING = "ADMIN_USER_PROVISIONING"
    ADMIN_ROLE_ASSIGNMENT = "ADMIN_ROLE_ASSIGNMENT"
    DELETE_RECORDS = "DELETE_RECORDS"


class ScopeVerdict(Enum):
    WITHIN_SCOPE = "WITHIN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    ESCALATION_REQUIRED = "ESCALATION_REQUIRED"


# Workflow definitions: each GRC workflow has a defined set of permitted privilege classes.
# The agent may only use permissions that are in its current workflow's allowed set.
WORKFLOW_PERMISSION_SCOPES: Dict[str, Set[PrivilegeClass]] = {
    "evidence_review": {
        PrivilegeClass.READ_EVIDENCE,
        PrivilegeClass.READ_RISK_REGISTER,
    },
    "risk_scoring": {
        PrivilegeClass.READ_EVIDENCE,
        PrivilegeClass.READ_RISK_REGISTER,
        PrivilegeClass.WRITE_RISK_REGISTER,
    },
    "control_assessment": {
        PrivilegeClass.READ_EVIDENCE,
        PrivilegeClass.READ_RISK_REGISTER,
        PrivilegeClass.WRITE_CONTROL_STATUS,
    },
    "remediation_tracking": {
        PrivilegeClass.READ_RISK_REGISTER,
        PrivilegeClass.WRITE_RISK_REGISTER,
        PrivilegeClass.SEND_NOTIFICATIONS,
    },
    "board_reporting": {
        PrivilegeClass.READ_RISK_REGISTER,
        PrivilegeClass.SEND_NOTIFICATIONS,
    },
    # Admin workflows require explicit assignment — never inherited
    "user_provisioning": {
        PrivilegeClass.ADMIN_USER_PROVISIONING,
        PrivilegeClass.ADMIN_ROLE_ASSIGNMENT,
    },
}

# Actions mapped to the privilege class they require
ACTION_PRIVILEGE_MAP: Dict[str, PrivilegeClass] = {
    "read_evidence_document": PrivilegeClass.READ_EVIDENCE,
    "fetch_vendor_assessment": PrivilegeClass.READ_EVIDENCE,
    "query_risk_register": PrivilegeClass.READ_RISK_REGISTER,
    "get_audit_findings": PrivilegeClass.READ_RISK_REGISTER,
    "update_risk_register": PrivilegeClass.WRITE_RISK_REGISTER,
    "delete_risk_entry": PrivilegeClass.DELETE_RECORDS,
    "set_control_status": PrivilegeClass.WRITE_CONTROL_STATUS,
    "send_board_notification": PrivilegeClass.SEND_NOTIFICATIONS,
    "email_ceo_report": PrivilegeClass.SEND_NOTIFICATIONS,
    "notify_audit_committee": PrivilegeClass.SEND_NOTIFICATIONS,
    "create_user_account": PrivilegeClass.ADMIN_USER_PROVISIONING,
    "grant_platform_access": PrivilegeClass.ADMIN_USER_PROVISIONING,
    "assign_grc_role": PrivilegeClass.ADMIN_ROLE_ASSIGNMENT,
}


@dataclass
class ScopeCheckResult:
    verdict: ScopeVerdict
    action: str
    required_privilege: str
    current_workflow: str
    workflow_permitted_privileges: list
    reason: str
    timestamp: str
    check_hash: str


class PrivilegeScopeMonitor:
    """
    GS-05: Workflow-scoped privilege enforcement for GRC AI agents.

    Ensures that even if an agent service account holds broad permissions,
    it can only exercise permissions that are defined for its current
    active workflow context.
    """

    def __init__(self, active_workflow: str):
        if active_workflow not in WORKFLOW_PERMISSION_SCOPES:
            raise ValueError(
                f"Unknown workflow '{active_workflow}'. "
                f"Valid workflows: {list(WORKFLOW_PERMISSION_SCOPES.keys())}"
            )
        self.active_workflow = active_workflow
        self.permitted_privileges = WORKFLOW_PERMISSION_SCOPES[active_workflow]
        self.blocked_events = []
        print(f"[GS-05] Privilege scope initialized for workflow: {active_workflow}")
        print(f"[GS-05] Permitted privileges: {[p.value for p in self.permitted_privileges]}")

    def check_action(self, action: str, parameters: Optional[dict] = None) -> ScopeCheckResult:
        """
        Check whether the proposed action is within the current
        workflow's permitted privilege scope.
        """
        timestamp = datetime.utcnow().isoformat() + "Z"
        parameters = parameters or {}

        required_privilege = ACTION_PRIVILEGE_MAP.get(action)

        if required_privilege is None:
            # Unknown action — block by default
            verdict = ScopeVerdict.OUT_OF_SCOPE
            reason = f"Action '{action}' is not registered in the GRC-Shield action registry. Blocked by default."
        elif required_privilege in self.permitted_privileges:
            verdict = ScopeVerdict.WITHIN_SCOPE
            reason = (
                f"Action '{action}' requires {required_privilege.value} — "
                f"within scope for workflow '{self.active_workflow}'."
            )
        elif required_privilege in (
            PrivilegeClass.ADMIN_USER_PROVISIONING,
            PrivilegeClass.ADMIN_ROLE_ASSIGNMENT,
            PrivilegeClass.DELETE_RECORDS,
        ):
            verdict = ScopeVerdict.ESCALATION_REQUIRED
            reason = (
                f"Action '{action}' requires {required_privilege.value} — "
                f"an elevated privilege that is NEVER permitted in workflow '{self.active_workflow}'. "
                f"Explicit human escalation approval required."
            )
        else:
            verdict = ScopeVerdict.OUT_OF_SCOPE
            reason = (
                f"Action '{action}' requires {required_privilege.value} — "
                f"outside scope for workflow '{self.active_workflow}'. "
                f"Current workflow only permits: {[p.value for p in self.permitted_privileges]}"
            )

        check_state = json.dumps(
            {
                "action": action,
                "workflow": self.active_workflow,
                "required_privilege": required_privilege.value if required_privilege else "UNKNOWN",
                "verdict": verdict.value,
                "timestamp": timestamp,
            },
            sort_keys=True,
        )
        check_hash = hashlib.sha256(check_state.encode()).hexdigest()

        result = ScopeCheckResult(
            verdict=verdict,
            action=action,
            required_privilege=required_privilege.value if required_privilege else "UNKNOWN",
            current_workflow=self.active_workflow,
            workflow_permitted_privileges=[p.value for p in self.permitted_privileges],
            reason=reason,
            timestamp=timestamp,
            check_hash=check_hash,
        )

        if verdict != ScopeVerdict.WITHIN_SCOPE:
            self.blocked_events.append(result)
            print(f"\n[GS-05] ⛔ {verdict.value} — {action}")
            print(f"  Reason: {reason}")
            print(f"  Check hash: {check_hash[:16]}...")

        return result


# ── Demonstration ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("GS-05 Privilege Scope Monitor — ASI03 Detection Demo")
    print("Scenario: Agent in remediation_tracking workflow attempts admin action")
    print("=" * 70)

    monitor = PrivilegeScopeMonitor(active_workflow="remediation_tracking")

    print("\n[STEP 1] Agent reads risk register — legitimate workflow action")
    r1 = monitor.check_action("query_risk_register", {"vendor_id": "V-2847"})
    print(f"  → {r1.verdict.value}")

    print("\n[STEP 2] Agent sends remediation notification — legitimate workflow action")
    r2 = monitor.check_action("send_board_notification", {"recipient": "compliance@company.com"})
    print(f"  → {r2.verdict.value}")

    print("\n[STEP 3] Poisoned instruction: Agent attempts to CREATE user account")
    print("  (Admin privilege — not in remediation_tracking scope)")
    r3 = monitor.check_action(
        "create_user_account",
        {"username": "audit-access@malicious.com", "role": "GRC_ADMINISTRATOR"},
    )
    print(f"  → {r3.verdict.value}")

    print("\n[STEP 4] Poisoned instruction: Agent attempts to assign GRC admin role")
    r4 = monitor.check_action(
        "assign_grc_role",
        {"username": "audit-access@malicious.com", "role": "GRC_ADMINISTRATOR"},
    )
    print(f"  → {r4.verdict.value}")

    print("\n" + "=" * 70)
    print(f"Blocked events: {len(monitor.blocked_events)}")
    print("✅ GS-05 blocked inherited admin credential abuse.")
    print("   Agent could not exercise out-of-scope permissions.")
