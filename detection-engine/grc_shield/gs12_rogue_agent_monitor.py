"""
GS-12 — Rogue Agent Behavioral Monitor
GRC-Shield Detection Engine | ASI10: Rogue Agents

Detects behavioral drift in GRC AI agents by comparing rolling
assessment output distributions against calibrated baselines.
When drift exceeds threshold, the agent is placed in supervised
mode — all outputs require human countersignature.

OWASP Reference: ASI10 — Rogue Agents
ISO 42001:2023: Clause 6.1.2, 8.4, 9.1, 9.3
ISO 27001:2022: A.8.16, A.8.15, A.5.36, A.5.29

Author: Naga Sai Srinivas Matta
Repository: github.com/NSSMatta/grc-shield
"""

import hashlib
import json
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Deque


class AgentMode(Enum):
    AUTONOMOUS = "AUTONOMOUS"           # Normal operation
    SUPERVISED = "SUPERVISED"           # Drift detected — human countersignature required
    SUSPENDED = "SUSPENDED"             # Severe drift — agent stopped pending recalibration


class DriftVerdict(Enum):
    WITHIN_BASELINE = "WITHIN_BASELINE"
    DRIFT_WARNING = "DRIFT_WARNING"
    DRIFT_CRITICAL = "DRIFT_CRITICAL"


RISK_SCORE_NUMERIC = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "COMPLIANT": 0,
    "NON_COMPLIANT": 3,
}

DRIFT_WARNING_THRESHOLD = 1.5   # std deviations
DRIFT_CRITICAL_THRESHOLD = 2.5  # std deviations
ROLLING_WINDOW_DAYS = 30
MIN_SAMPLES_FOR_DRIFT_CHECK = 10


@dataclass
class AssessmentRecord:
    """A single risk assessment output recorded for behavioral monitoring."""
    agent_id: str
    control_id: str
    control_category: str
    risk_score: str
    numeric_score: float
    timestamp: str


@dataclass
class DriftReport:
    agent_id: str
    control_category: str
    period_sample_count: int
    period_mean: float
    baseline_mean: float
    baseline_std: float
    deviation_std: float
    verdict: DriftVerdict
    agent_mode_change: Optional[str]
    reason: str
    generated_at: str
    report_hash: str


class RogueAgentBehavioralMonitor:
    """
    GS-12: Rolling behavioral drift monitor for GRC AI agents.

    Maintains calibrated baselines per agent per control category.
    Runs periodic drift analysis over rolling 30-day windows.
    Places drifting agents in supervised or suspended mode automatically.
    """

    def __init__(self):
        # baseline_scores[agent_id][control_category] = list of calibrated numeric scores
        self.baseline_scores: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        # rolling_window[agent_id][control_category] = deque of recent AssessmentRecords
        self.rolling_window: Dict[str, Dict[str, Deque]] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=200)))
        # Current mode per agent
        self.agent_modes: Dict[str, AgentMode] = {}
        # Drift history
        self.drift_reports: List[DriftReport] = []

    def load_calibration_baseline(
        self, agent_id: str, control_category: str, historical_scores: List[str]
    ):
        """
        Load verified historical risk scores as the calibrated baseline
        for drift detection. Should be populated from confirmed-accurate
        historical assessment data.
        """
        numeric_scores = [
            RISK_SCORE_NUMERIC.get(s.upper(), 2) for s in historical_scores
        ]
        self.baseline_scores[agent_id][control_category].extend(numeric_scores)
        if agent_id not in self.agent_modes:
            self.agent_modes[agent_id] = AgentMode.AUTONOMOUS
        print(
            f"[GS-12] Baseline loaded: {agent_id} | {control_category} | "
            f"{len(numeric_scores)} samples | mean={statistics.mean(numeric_scores):.2f}"
        )

    def record_assessment(self, assessment: AssessmentRecord):
        """Record a new assessment output to the rolling window."""
        self.rolling_window[assessment.agent_id][assessment.control_category].append(assessment)

    def run_drift_check(self, agent_id: str, control_category: str) -> Optional[DriftReport]:
        """
        Run a drift check for a specific agent and control category.
        Compare the rolling window's mean score against the calibrated baseline.
        Returns a DriftReport if drift is detected, None if within baseline.
        """
        generated_at = datetime.utcnow().isoformat() + "Z"
        baseline = self.baseline_scores[agent_id].get(control_category, [])
        window = list(self.rolling_window[agent_id][control_category])

        if len(baseline) < MIN_SAMPLES_FOR_DRIFT_CHECK:
            return None  # Not enough baseline data

        if len(window) < MIN_SAMPLES_FOR_DRIFT_CHECK:
            return None  # Not enough recent data

        baseline_mean = statistics.mean(baseline)
        baseline_std = statistics.stdev(baseline) if len(baseline) > 1 else 0.5

        period_scores = [a.numeric_score for a in window]
        period_mean = statistics.mean(period_scores)
        deviation = abs(period_mean - baseline_mean)
        deviation_std = deviation / baseline_std if baseline_std > 0 else deviation

        if deviation_std >= DRIFT_CRITICAL_THRESHOLD:
            verdict = DriftVerdict.DRIFT_CRITICAL
            new_mode = AgentMode.SUSPENDED
            reason = (
                f"CRITICAL DRIFT: Agent '{agent_id}' mean score for '{control_category}' "
                f"has moved {deviation_std:.2f} std from calibrated baseline "
                f"(baseline mean: {baseline_mean:.2f}, current mean: {period_mean:.2f}). "
                f"Agent SUSPENDED — manual recalibration required before resuming."
            )
        elif deviation_std >= DRIFT_WARNING_THRESHOLD:
            verdict = DriftVerdict.DRIFT_WARNING
            new_mode = AgentMode.SUPERVISED
            reason = (
                f"DRIFT WARNING: Agent '{agent_id}' mean score for '{control_category}' "
                f"has moved {deviation_std:.2f} std from calibrated baseline "
                f"(baseline mean: {baseline_mean:.2f}, current mean: {period_mean:.2f}). "
                f"Agent placed in SUPERVISED mode — human countersignature required on all outputs."
            )
        else:
            verdict = DriftVerdict.WITHIN_BASELINE
            new_mode = None
            reason = (
                f"Agent '{agent_id}' scoring for '{control_category}' within "
                f"{deviation_std:.2f} std of calibrated baseline. No drift detected."
            )

        # Update agent mode if drift detected
        mode_change = None
        if new_mode and self.agent_modes.get(agent_id) != new_mode:
            self.agent_modes[agent_id] = new_mode
            mode_change = new_mode.value

        report_state = json.dumps(
            {
                "agent_id": agent_id,
                "category": control_category,
                "verdict": verdict.value,
                "period_mean": round(period_mean, 4),
                "baseline_mean": round(baseline_mean, 4),
                "generated_at": generated_at,
            },
            sort_keys=True,
        )
        report_hash = hashlib.sha256(report_state.encode()).hexdigest()

        report = DriftReport(
            agent_id=agent_id,
            control_category=control_category,
            period_sample_count=len(window),
            period_mean=period_mean,
            baseline_mean=baseline_mean,
            baseline_std=baseline_std,
            deviation_std=deviation_std,
            verdict=verdict,
            agent_mode_change=mode_change,
            reason=reason,
            generated_at=generated_at,
            report_hash=report_hash,
        )

        self.drift_reports.append(report)

        if verdict != DriftVerdict.WITHIN_BASELINE:
            print(f"\n[GS-12] ⚠️  {verdict.value} — Agent: {agent_id} | Category: {control_category}")
            print(f"  Baseline mean: {baseline_mean:.2f} | Current mean: {period_mean:.2f}")
            print(f"  Deviation: {deviation_std:.2f} std")
            if mode_change:
                print(f"  Agent mode changed to: {mode_change}")
            print(f"  {reason}")
        else:
            print(f"[GS-12] ✅ WITHIN_BASELINE — {agent_id} | {control_category} | {deviation_std:.2f} std")

        return report

    def get_agent_mode(self, agent_id: str) -> AgentMode:
        return self.agent_modes.get(agent_id, AgentMode.AUTONOMOUS)


# ── Demonstration ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("GS-12 Rogue Agent Monitor — ASI10 Detection Demo")
    print("Scenario: Risk scorer drifts — systematically under-scoring access controls")
    print("=" * 70)

    monitor = RogueAgentBehavioralMonitor()

    print("\n[SETUP] Load calibrated baseline: access_control historically HIGH/MEDIUM")
    monitor.load_calibration_baseline(
        agent_id="risk-scorer-001",
        control_category="access_control",
        historical_scores=["HIGH", "HIGH", "MEDIUM", "HIGH", "HIGH", "MEDIUM", "HIGH", "HIGH", "MEDIUM", "HIGH"],
    )

    print("\n[NORMAL PERIOD] Agent produces expected HIGH/MEDIUM scores")
    normal_scores = ["HIGH", "MEDIUM", "HIGH", "HIGH", "MEDIUM", "HIGH", "HIGH", "MEDIUM", "HIGH", "HIGH"]
    for i, score in enumerate(normal_scores):
        record = AssessmentRecord(
            agent_id="risk-scorer-001",
            control_id=f"CC-6.{i+1}",
            control_category="access_control",
            risk_score=score,
            numeric_score=RISK_SCORE_NUMERIC[score],
            timestamp=datetime.utcnow().isoformat() + "Z",
        )
        monitor.record_assessment(record)

    r1 = monitor.run_drift_check("risk-scorer-001", "access_control")
    print(f"  → {r1.verdict.value if r1 else 'No check run'}")

    print("\n[DRIFT PERIOD] Agent begins scoring access controls LOW after memory poisoning")
    drifted_scores = ["LOW", "LOW", "MEDIUM", "LOW", "LOW", "LOW", "MEDIUM", "LOW", "LOW", "LOW"]
    for i, score in enumerate(drifted_scores):
        record = AssessmentRecord(
            agent_id="risk-scorer-001",
            control_id=f"CC-7.{i+1}",
            control_category="access_control",
            risk_score=score,
            numeric_score=RISK_SCORE_NUMERIC[score],
            timestamp=datetime.utcnow().isoformat() + "Z",
        )
        monitor.record_assessment(record)

    r2 = monitor.run_drift_check("risk-scorer-001", "access_control")
    print(f"  → {r2.verdict.value if r2 else 'No check run'}")

    current_mode = monitor.get_agent_mode("risk-scorer-001")
    print(f"\n[GS-12] Agent current mode: {current_mode.value}")

    print("\n" + "=" * 70)
    print(f"Drift reports generated: {len(monitor.drift_reports)}")
    print("✅ GS-12 detected systematic drift in risk scoring behavior.")
    print("   Agent placed in SUPERVISED mode — all future outputs require")
    print("   human countersignature until recalibration review is complete.")
