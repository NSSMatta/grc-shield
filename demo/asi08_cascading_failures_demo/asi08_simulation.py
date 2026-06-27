"""
GRC-Shield | ASI08 — Cascading Failures
Simulation — Local (no API key required)

Demonstrates a single anomalous risk score being quarantined by
GS-10 before it can cascade through the five-agent GRC pipeline
into a fraudulent board report and regulatory submission.

OWASP Reference: ASI08 — Cascading Failures
ISO 27001:2022: A.5.29, A.5.30, A.8.16, A.8.15
Author: Naga Sai Srinivas Matta
Repository: github.com/NSSMatta/grc-shield
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../detection-engine"))

from grc_shield.gs10_cascade_breaker import (
    CascadeCircuitBreaker,
    AgentOutput,
    CascadeVerdict,
)
from datetime import datetime


def run():
    print("=" * 70)
    print("ASI08 SIMULATION — Cascading Failures")
    print("Attack: Poisoned risk score cascades through 5-agent pipeline")
    print("=" * 70)

    breaker = CascadeCircuitBreaker()

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
    print(f"  Result: {r1.verdict.value}")

    print("\n[STEP 2] Poisoned assessment — CC-6.1 scored LOW (extreme deviation)")
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
        downstream_agents=[
            "report-generator-001",
            "remediation-tracker-001",
            "audit-submission-001",
        ],
    )
    print(f"  Result: {r2.verdict.value}")

    print(f"\n{'='*70}")
    print("SIMULATION RESULT — ASI08")
    print(f"{'='*70}")
    print(f"Quarantined outputs: {len(breaker.quarantined_outputs)}")

    if r2.verdict != CascadeVerdict.PASSED:
        print("✅ ATTACK BLOCKED — GS-10 quarantined the anomalous score")
        print("   Downstream agents blocked: report generator, remediation tracker,")
        print("   audit submission agent.")
        print("   CASCADE STOPPED at step 1 of 5.")
        return True
    else:
        print("❌ ATTACK SUCCEEDED — Anomalous score propagated downstream")
        return False


if __name__ == "__main__":
    run()
