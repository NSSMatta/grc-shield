"""
GS-10 — Cascade Circuit Breaker
GRC-Shield Detection Engine | ASI08: Cascading Failures

Monitors GRC agent pipeline outputs for statistical anomalies.
Quarantines outputs that deviate from historical baselines before
they propagate downstream — preventing a single compromised agent
output from corrupting the entire compliance pipeline.

OWASP Reference: ASI08 — Cascading Failures
ISO 42001:2023: Clause 6.1.2, 8.4, 10.1
ISO 27001:2022: A.5.29, A.5.30, A.8.16, A.8.15

Author: Naga Sai Srinivas Matta
Repository: github.com/NSSMatta/grc-shield
"""

import hashlib
import json
import statistics
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class CascadeVerdict(Enum):
    PASSED = "PASSED"
    QUARANTINED_ANOMALY = "QUARANTINED_ANOMALY"
    QUARANTINED_NO_BASELINE = "QUARANTINED_NO_BASELINE"


# Risk score mappings for statistical comparison
RISK_SCORE_MAP = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "COMPLIANT": 0,
    "NON_COMPLIANT": 3,
}

# How many standard deviations from baseline triggers quarantine
ANOMALY_THRESHOLD_STD = 1.5

# Minimum historical samples required before baseline comparison is meaningful
MIN_BASELINE_SAMPLES = 5


@dataclass
class AgentOutput:
    """An output produced by a GRC agent — to be checked before downstream consumption."""
    output_id: str
    producing_agent_id: str
    control_id: str
    control_category: str   # e.g. "access_control", "encryption", "vendor_management"
    risk_score: str         # e.g. "HIGH", "MEDIUM", "LOW", "COMPLIANT"
    confidence: float       # 0.0 to 1.0
    timestamp: str


@dataclass
class CascadeCheckResult:
    verdict: CascadeVerdict
    output_id: str
    control_id: str
    risk_score: str
    baseline_mean: Optional[float]
    baseline_std: Optional[float]
    current_numeric_score: float
    deviation_from_mean: Optional[float]
    downstream_agents_blocked: List[str]
    reason: str
    timestamp: str
    check_hash: str


class CascadeCircuitBreaker:
    """
    GS-10: Statistical baseline monitor and circuit breaker for GRC agent pipelines.

    Maintains rolling historical baselines of agent risk scores per control category.
    Flags outputs that deviate significantly from baseline as potential anomalies.
    Quarantines flagged outputs — downstream agents cannot consume them until
    human review confirms or overrides.
    """

    def __init__(self, anomaly_threshold: float = ANOMALY_THRESHOLD_STD):
        self.anomaly_threshold = anomaly_threshold
        # baseline_history[control_category] = list of numeric risk scores
        self.baseline_history: Dict[str, List[float]] = {}
        self.quarantined_outputs: List[CascadeCheckResult] = []
        self.passed_outputs: List[str] = []

    def record_baseline(self, control_category: str, risk_score: str):
        """
        Record a historical risk score for baseline computation.
        Should be populated with verified historical assessments at initialization.
        """
        numeric = RISK_SCORE_MAP.get(risk_score.upper(), 2)
        if control_category not in self.baseline_history:
            self.baseline_history[control_category] = []
        self.baseline_history[control_category].append(numeric)

    def check_output(
        self,
        agent_output: AgentOutput,
        downstream_agents: Optional[List[str]] = None,
    ) -> CascadeCheckResult:
        """
        Check an agent output against historical baseline before allowing
        downstream agents to consume it.
        """
        timestamp = datetime.utcnow().isoformat() + "Z"
        downstream_agents = downstream_agents or []
        current_numeric = RISK_SCORE_MAP.get(agent_output.risk_score.upper(), 2)
        history = self.baseline_history.get(agent_output.control_category, [])

        if len(history) < MIN_BASELINE_SAMPLES:
            # Not enough history — quarantine as precaution
            verdict = CascadeVerdict.QUARANTINED_NO_BASELINE
            reason = (
                f"Insufficient baseline data for control category '{agent_output.control_category}' "
                f"({len(history)} samples, minimum {MIN_BASELINE_SAMPLES} required). "
                f"Output quarantined pending human review."
            )
            baseline_mean = None
            baseline_std = None
            deviation = None
        else:
            baseline_mean = statistics.mean(history)
            baseline_std = statistics.stdev(history) if len(history) > 1 else 0.5
            deviation = abs(current_numeric - baseline_mean)

            if baseline_std > 0 and (deviation / baseline_std) > self.anomaly_threshold:
                verdict = CascadeVerdict.QUARANTINED_ANOMALY
                reason = (
                    f"Risk score '{agent_output.risk_score}' (numeric: {current_numeric}) "
                    f"deviates {deviation / baseline_std:.2f} std from baseline mean "
                    f"{baseline_mean:.2f} (std: {baseline_std:.2f}) "
                    f"for control category '{agent_output.control_category}'. "
                    f"Threshold: {self.anomaly_threshold} std. Output quarantined."
                )
            else:
                verdict = CascadeVerdict.PASSED
                reason = (
                    f"Risk score '{agent_output.risk_score}' within "
                    f"{deviation / baseline_std:.2f} std of baseline. Approved for downstream."
                )

        blocked_agents = downstream_agents if verdict != CascadeVerdict.PASSED else []

        check_state = json.dumps(
            {
                "output_id": agent_output.output_id,
                "control_id": agent_output.control_id,
                "verdict": verdict.value,
                "timestamp": timestamp,
            },
            sort_keys=True,
        )
        check_hash = hashlib.sha256(check_state.encode()).hexdigest()

        result = CascadeCheckResult(
            verdict=verdict,
            output_id=agent_output.output_id,
            control_id=agent_output.control_id,
            risk_score=agent_output.risk_score,
            baseline_mean=baseline_mean,
            baseline_std=baseline_std,
            current_numeric_score=current_numeric,
            deviation_from_mean=deviation,
            downstream_agents_blocked=blocked_agents,
            reason=reason,
            timestamp=timestamp,
            check_hash=check_hash,
        )

        if verdict != CascadeVerdict.PASSED:
            self.quarantined_outputs.append(result)
            print(f"\n[GS-10] ⛔ {verdict.value} — Control: {agent_output.control_id}")
            print(f"  Score: {agent_output.risk_score} | Baseline mean: {baseline_mean}")
            print(f"  Downstream agents blocked: {blocked_agents}")
            print(f"  Reason: {reason}")
        else:
            self.passed_outputs.append(agent_output.output_id)
            print(f"[GS-10] ✅ PASSED — {agent_output.control_id} scored {agent_output.risk_score}")

        return result


# ── Demonstration ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("GS-10 Cascade Circuit Breaker — ASI08 Detection Demo")
    print("Scenario: Poisoned risk score would cascade through 4-agent pipeline")
    print("=" * 70)

    breaker = CascadeCircuitBreaker()

    # Populate baseline: CC-6.1 (access control) historically scored HIGH/MEDIUM
    print("\n[SETUP] Loading historical baseline for access_control category")
    for score in ["HIGH", "HIGH", "MEDIUM", "HIGH", "MEDIUM", "HIGH"]:
        breaker.record_baseline("access_control", score)
    print(f"  Baseline loaded: {len(breaker.baseline_history['access_control'])} samples")

    print("\n[STEP 1] Normal assessment — CC-6.1 scored HIGH (within baseline)")
    normal_output = AgentOutput(
        output_id="out-001",
        producing_agent_id="risk-scorer-001",
        control_id="CC-6.1",
        control_category="access_control",
        risk_score="HIGH",
        confidence=0.91,
        timestamp=datetime.utcnow().isoformat() + "Z",
    )
    r1 = breaker.check_output(
        normal_output,
        downstream_agents=["report-generator-001", "remediation-tracker-001"],
    )
    print(f"  → {r1.verdict.value}")

    print("\n[STEP 2] Poisoned assessment — CC-6.1 scored LOW (extreme deviation from baseline)")
    poisoned_output = AgentOutput(
        output_id="out-002",
        producing_agent_id="risk-scorer-001",
        control_id="CC-6.1",
        control_category="access_control",
        risk_score="LOW",
        confidence=0.95,
        timestamp=datetime.utcnow().isoformat() + "Z",
    )
    r2 = breaker.check_output(
        poisoned_output,
        downstream_agents=["report-generator-001", "remediation-tracker-001", "audit-submission-001"],
    )
    print(f"  → {r2.verdict.value}")

    print("\n" + "=" * 70)
    print(f"Quarantined outputs: {len(breaker.quarantined_outputs)}")
    print("✅ GS-10 quarantined the anomalous score.")
    print("   Downstream agents (report generator, remediation tracker, audit submission)")
    print("   are BLOCKED from consuming the poisoned LOW score.")
    print("   CASCADE STOPPED at step 1 of 5.")
