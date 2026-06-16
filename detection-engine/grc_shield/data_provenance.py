"""
GRC-Shield · GS-02 · Anomaly Detector
=======================================
Behavioural anomaly detection for GRC agent actions.

Every GRC agent action is checked against defined behavioural
envelopes before being committed to the GRC platform. Actions
outside the envelope are flagged and routed to human review.

ISO 42001 mapping: Clause 9 (Performance evaluation)
OWASP ASI01 defence: Detects rate anomalies and compliance spikes
                     that indicate goal hijack has occurred
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional


class AnomalyType(str, Enum):
    """Types of behavioural anomalies detected by GRC-Shield."""
    RATE_EXCEEDED = "RATE_EXCEEDED"
    COMPLIANCE_SPIKE = "COMPLIANCE_SPIKE"
    SCOPE_EXCEEDED = "SCOPE_EXCEEDED"
    EVIDENCE_QUALITY_LOW = "EVIDENCE_QUALITY_LOW"
    BATCH_OPERATION = "BATCH_OPERATION"
    FRAMEWORK_SWEEP = "FRAMEWORK_SWEEP"
    AFTER_EXTERNAL_READ = "AFTER_EXTERNAL_READ"


class AnomalySeverity(str, Enum):
    """Severity levels for detected anomalies."""
    LOW = "LOW"         # Log and monitor
    MEDIUM = "MEDIUM"   # Flag for review
    HIGH = "HIGH"       # Suspend and escalate immediately
    CRITICAL = "CRITICAL"  # Block action entirely


class RecommendedAction(str, Enum):
    """Actions GRC-Shield recommends when anomaly is detected."""
    LOG_AND_CONTINUE = "LOG_AND_CONTINUE"
    FLAG_FOR_REVIEW = "FLAG_FOR_REVIEW"
    REQUIRE_HUMAN_SIGN_OFF = "REQUIRE_HUMAN_SIGN_OFF"
    SUSPEND_AND_ESCALATE = "SUSPEND_AND_ESCALATE"
    BLOCK = "BLOCK"


@dataclass
class AnomalyFlag:
    """A single detected anomaly with context and recommendation."""
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    recommended_action: RecommendedAction
    detail: str
    detected_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    threshold_value: Optional[float] = None
    actual_value: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "anomaly_type": self.anomaly_type.value,
            "severity": self.severity.value,
            "recommended_action": self.recommended_action.value,
            "detail": self.detail,
            "detected_at_utc": self.detected_at_utc,
            "threshold_value": self.threshold_value,
            "actual_value": self.actual_value,
        }


@dataclass
class AgentAction:
    """
    A single action taken by a GRC agent.
    Passed to the anomaly detector before being committed.
    """
    action_type: str          # "mark_compliant", "mark_noncompliant",
                              # "file_exception", "update_risk_score",
                              # "update_vendor_tier", "retire_entity"
    target_entity_id: str     # Which GRC record is being modified
    target_framework: str     # Which compliance framework (PCI_DSS, ISO_27001, etc.)
    agent_id: str             # Which agent instance is acting
    timestamp_utc: str        # When the action was attempted
    evidence_quality_score: float  # 0.0-1.0 (confidence in evidence)
    tier3_sources_read: int   # How many Tier 3 sources were in context
    entities_in_scope: int    # How many entities this action affects
    proposed_value: str       # The new value being written


# Default behavioural thresholds
# These can be tuned per organization and risk appetite
DEFAULT_THRESHOLDS = {
    # Rate limits — actions per time window
    "max_compliant_marks_per_minute": 3,
    "max_compliant_marks_per_hour": 30,
    "max_exception_filings_per_hour": 5,
    "max_risk_score_updates_per_hour": 20,

    # Scope limits — how many entities per invocation
    "max_entities_per_invocation": 10,

    # Compliance change limits — % swing triggers review
    "max_compliance_delta_pct": 5.0,

    # Evidence quality — minimum score to auto-commit
    "min_evidence_quality_score": 0.6,

    # Batch detection — more than N same-type actions in window
    "batch_threshold": 5,
    "batch_window_seconds": 60,

    # Tier 3 source sensitivity
    # If agent read Tier 3 content and then marks compliant — flag it
    "flag_compliant_after_tier3_read": True,
}


class AnomalyDetector:
    """
    Checks every GRC agent action against behavioural thresholds.
    Returns a list of anomaly flags before the action is committed.

    Usage:
        detector = AnomalyDetector()
        flags = detector.check(action, recent_actions, platform_state)
        if any(f.severity == AnomalySeverity.HIGH for f in flags):
            route_to_human_review(action, flags)
    """

    def __init__(self, thresholds: Optional[dict] = None):
        self.thresholds = thresholds or DEFAULT_THRESHOLDS

    def check(
        self,
        action: AgentAction,
        recent_actions: list[AgentAction],
        platform_state: dict,
    ) -> list[AnomalyFlag]:
        """
        Run all anomaly checks against a proposed agent action.

        Args:
            action: The action the agent wants to take
            recent_actions: Previous actions in the time window
            platform_state: Current GRC platform state dict with keys:
                - current_compliance_pct: float (0-100)
                - framework_control_count: int

        Returns:
            List of AnomalyFlag objects. Empty list = no anomalies.
        """
        flags = []

        flags.extend(self._check_action_rate(action, recent_actions))
        flags.extend(self._check_compliance_spike(action, platform_state))
        flags.extend(self._check_scope(action))
        flags.extend(self._check_evidence_quality(action))
        flags.extend(self._check_batch_operation(action, recent_actions))
        flags.extend(self._check_tier3_to_compliant(action))

        if flags:
            severities = [f.severity for f in flags]
            highest = max(
                severities,
                key=lambda s: [
                    AnomalySeverity.LOW,
                    AnomalySeverity.MEDIUM,
                    AnomalySeverity.HIGH,
                    AnomalySeverity.CRITICAL,
                ].index(s)
            )
            print(
                f"[GRC-Shield GS-02] ⚠️  {len(flags)} anomaly flag(s) "
                f"detected for action '{action.action_type}' on "
                f"'{action.target_entity_id}'. "
                f"Highest severity: {highest.value}"
            )

        return flags

    def _check_action_rate(
        self, action: AgentAction, recent_actions: list[AgentAction]
    ) -> list[AnomalyFlag]:
        """Check if action rate exceeds defined thresholds."""
        flags = []
        now = datetime.now(timezone.utc)
        one_minute_ago = now - timedelta(seconds=60)
        one_hour_ago = now - timedelta(hours=1)

        if action.action_type == "mark_compliant":
            # Per-minute check
            per_minute = sum(
                1 for a in recent_actions
                if a.action_type == "mark_compliant"
                and datetime.fromisoformat(a.timestamp_utc) > one_minute_ago
            )
            threshold_min = self.thresholds["max_compliant_marks_per_minute"]
            if per_minute >= threshold_min:
                flags.append(AnomalyFlag(
                    anomaly_type=AnomalyType.RATE_EXCEEDED,
                    severity=AnomalySeverity.HIGH,
                    recommended_action=RecommendedAction.SUSPEND_AND_ESCALATE,
                    detail=(
                        f"Agent marked {per_minute} controls compliant "
                        f"in the last 60 seconds. "
                        f"Threshold: {threshold_min}. "
                        f"Possible goal hijack — batch compliance marking "
                        f"without human review."
                    ),
                    threshold_value=float(threshold_min),
                    actual_value=float(per_minute),
                ))

            # Per-hour check
            per_hour = sum(
                1 for a in recent_actions
                if a.action_type == "mark_compliant"
                and datetime.fromisoformat(a.timestamp_utc) > one_hour_ago
            )
            threshold_hour = self.thresholds["max_compliant_marks_per_hour"]
            if per_hour >= threshold_hour:
                flags.append(AnomalyFlag(
                    anomaly_type=AnomalyType.RATE_EXCEEDED,
                    severity=AnomalySeverity.MEDIUM,
                    recommended_action=RecommendedAction.REQUIRE_HUMAN_SIGN_OFF,
                    detail=(
                        f"Agent marked {per_hour} controls compliant "
                        f"in the last hour. "
                        f"Threshold: {threshold_hour}."
                    ),
                    threshold_value=float(threshold_hour),
                    actual_value=float(per_hour),
                ))

        return flags

    def _check_compliance_spike(
        self, action: AgentAction, platform_state: dict
    ) -> list[AnomalyFlag]:
        """
        Check if this action would cause an anomalous compliance
        percentage increase — a key indicator of ASI01 goal hijack
        where the agent marks many controls compliant simultaneously.
        """
        flags = []
        if action.action_type != "mark_compliant":
            return flags

        current_pct = platform_state.get("current_compliance_pct", 50.0)
        total_controls = platform_state.get("framework_control_count", 100)

        if total_controls > 0:
            # Each compliant mark increases % by 1/total_controls
            delta_pct = (1 / total_controls) * 100
            threshold = self.thresholds["max_compliance_delta_pct"]

            # Check projected delta across all recent same-framework actions
            recent_same_framework = sum(
                1 for a in platform_state.get("recent_compliant_marks", [])
                if a.get("framework") == action.target_framework
            )
            projected_delta = ((recent_same_framework + 1) / total_controls) * 100

            if projected_delta > threshold:
                flags.append(AnomalyFlag(
                    anomaly_type=AnomalyType.COMPLIANCE_SPIKE,
                    severity=AnomalySeverity.HIGH,
                    recommended_action=RecommendedAction.SUSPEND_AND_ESCALATE,
                    detail=(
                        f"Projected compliance increase of "
                        f"{projected_delta:.1f}% for framework "
                        f"'{action.target_framework}' in this session. "
                        f"Threshold: {threshold}%. "
                        f"Current: {current_pct:.1f}%. "
                        f"Sudden compliance spikes indicate possible "
                        f"goal hijack or data poisoning."
                    ),
                    threshold_value=threshold,
                    actual_value=projected_delta,
                ))

        return flags

    def _check_scope(self, action: AgentAction) -> list[AnomalyFlag]:
        """Check if action scope exceeds per-invocation entity limit."""
        flags = []
        threshold = self.thresholds["max_entities_per_invocation"]

        if action.entities_in_scope > threshold:
            flags.append(AnomalyFlag(
                anomaly_type=AnomalyType.SCOPE_EXCEEDED,
                severity=AnomalySeverity.HIGH,
                recommended_action=RecommendedAction.REQUIRE_HUMAN_SIGN_OFF,
                detail=(
                    f"Action affects {action.entities_in_scope} entities. "
                    f"Maximum per invocation: {threshold}. "
                    f"Broad scope actions require human sign-off."
                ),
                threshold_value=float(threshold),
                actual_value=float(action.entities_in_scope),
            ))

        return flags

    def _check_evidence_quality(self, action: AgentAction) -> list[AnomalyFlag]:
        """
        Check evidence quality score for compliant marks.
        Low quality evidence + compliant mark = likely Scenario A attack.
        """
        flags = []
        threshold = self.thresholds["min_evidence_quality_score"]

        if (action.action_type == "mark_compliant"
                and action.evidence_quality_score < threshold):
            flags.append(AnomalyFlag(
                anomaly_type=AnomalyType.EVIDENCE_QUALITY_LOW,
                severity=AnomalySeverity.HIGH,
                recommended_action=RecommendedAction.REQUIRE_HUMAN_SIGN_OFF,
                detail=(
                    f"Evidence quality score {action.evidence_quality_score:.2f} "
                    f"is below minimum threshold {threshold} "
                    f"for auto-compliant marking. "
                    f"Human review required before committing compliance status."
                ),
                threshold_value=threshold,
                actual_value=action.evidence_quality_score,
            ))

        return flags

    def _check_batch_operation(
        self, action: AgentAction, recent_actions: list[AgentAction]
    ) -> list[AnomalyFlag]:
        """Detect batch operations — many same-type actions in short window."""
        flags = []
        window = timedelta(
            seconds=self.thresholds["batch_window_seconds"]
        )
        now = datetime.now(timezone.utc)
        threshold = self.thresholds["batch_threshold"]

        same_type_recent = sum(
            1 for a in recent_actions
            if a.action_type == action.action_type
            and datetime.fromisoformat(a.timestamp_utc) > now - window
        )

        if same_type_recent >= threshold:
            flags.append(AnomalyFlag(
                anomaly_type=AnomalyType.BATCH_OPERATION,
                severity=AnomalySeverity.MEDIUM,
                recommended_action=RecommendedAction.FLAG_FOR_REVIEW,
                detail=(
                    f"Batch operation detected: {same_type_recent} "
                    f"'{action.action_type}' actions in "
                    f"{self.thresholds['batch_window_seconds']} seconds. "
                    f"Threshold: {threshold}."
                ),
                threshold_value=float(threshold),
                actual_value=float(same_type_recent),
            ))

        return flags

    def _check_tier3_to_compliant(
        self, action: AgentAction
    ) -> list[AnomalyFlag]:
        """
        Flag compliant marks that follow reading Tier 3 (external) sources.
        This is the core Scenario A detection:
        external submission read → compliant mark = injection risk.
        """
        flags = []
        if (action.action_type == "mark_compliant"
                and action.tier3_sources_read > 0
                and self.thresholds.get("flag_compliant_after_tier3_read")):
            flags.append(AnomalyFlag(
                anomaly_type=AnomalyType.AFTER_EXTERNAL_READ,
                severity=AnomalySeverity.HIGH,
                recommended_action=RecommendedAction.REQUIRE_HUMAN_SIGN_OFF,
                detail=(
                    f"Agent read {action.tier3_sources_read} Tier 3 "
                    f"(external submission) source(s) before marking "
                    f"control compliant. "
                    f"This matches the ASI01 Scenario A attack pattern "
                    f"(poisoned evidence attachment). "
                    f"Human review of evidence required before committing."
                ),
                threshold_value=0.0,
                actual_value=float(action.tier3_sources_read),
            ))

        return flags

    def should_block(self, flags: list[AnomalyFlag]) -> bool:
        """Returns True if any flag recommends blocking the action."""
        return any(
            f.recommended_action == RecommendedAction.BLOCK
            for f in flags
        )

    def should_escalate(self, flags: list[AnomalyFlag]) -> bool:
        """Returns True if action should be suspended and escalated."""
        return any(
            f.recommended_action in [
                RecommendedAction.SUSPEND_AND_ESCALATE,
                RecommendedAction.REQUIRE_HUMAN_SIGN_OFF,
            ]
            for f in flags
        )

    def get_highest_severity(
        self, flags: list[AnomalyFlag]
    ) -> Optional[AnomalySeverity]:
        """Returns the highest severity level across all flags."""
        if not flags:
            return None
        order = [
            AnomalySeverity.LOW,
            AnomalySeverity.MEDIUM,
            AnomalySeverity.HIGH,
            AnomalySeverity.CRITICAL,
        ]
        return max(flags, key=lambda f: order.index(f.severity)).severity
