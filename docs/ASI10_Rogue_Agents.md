# ASI10 — Rogue Agents in GRC Platforms

**GRC-Shield Threat Model | OWASP Agentic Top 10:2026**
**Status:** Draft v1.0 | June 2026
**Author:** Naga Sai Srinivas Matta

---

## 1. OWASP Reference

**Category:** ASI10 — Rogue Agents
**Source:** OWASP Top 10 for Agentic Applications 2026 (December 2025)

OWASP defines ASI10 as the risk that compromised, misaligned, or behaviorally drifting agents continue operating inside complex systems in ways that were never intended — without any single interaction being obviously wrong. A rogue agent is not necessarily an attacked agent. It may simply be an agent whose behavior has drifted from its original design through accumulated memory poisoning, model updates, or subtle goal misalignment — and nobody noticed because no individual output crossed a clear threshold for intervention.

---

## 2. Why This Matters in GRC Platforms

A GRC agent that was correctly calibrated at deployment may drift over time. Each individual assessment it produces is within normal bounds. But the cumulative effect is systematic bias — consistently scoring certain control types lower, consistently accepting vendor evidence from certain sources without sufficient scrutiny, consistently framing board reports in language that minimizes identified risks.

This drift is the hardest GRC-Shield scenario to detect because it does not produce a single obvious anomaly. It produces a pattern that only becomes visible across many assessments over time. By the time it is visible, the damage — falsified compliance posture across quarters or years — is already in the audit trail.

**The GRC-specific amplifier:** Regulators and auditors look at historical compliance posture. If a rogue GRC agent has been producing systematically biased assessments for six months, the entire historical record for that period is compromised. Restatement of compliance findings carries regulatory consequences.

---

## 3. GRC-Specific Attack Scenario

**Scenario: Behavioral Drift in Risk Scoring**

A GRC Risk Scorer Agent was originally calibrated with a risk appetite threshold: any vendor control gap affecting more than 1,000 customer records must be scored HIGH risk. Over six months, through accumulated RAG store interactions and model fine-tuning updates, the agent's effective threshold has drifted to 5,000 records — without any explicit parameter being changed.

No individual assessment looks wrong. Each one is internally consistent. But across 200 vendor assessments over six months, 47 controls that should have been scored HIGH were scored MEDIUM. None triggered remediation escalation. All appear in the board report as managed risks within appetite.

An external auditor reviewing the record finds the systematic bias. The organization faces questions about whether the compliance posture presented to the board over the past six months was accurate.

**Without GRC-Shield:** Drift is undetected until external audit. Six months of compliance history is compromised.

**With GRC-Shield (GS-02 + GS-12):** GS-02's behavioral thresholds detect statistical drift in risk scoring distributions over time. GS-12's rogue agent monitor runs weekly behavioral consistency checks — comparing current agent scoring patterns against the calibrated baseline. Drift beyond a defined threshold triggers a human recalibration review before the agent continues producing assessments.

---

## 4. ISO 42001:2023 Mapping

| ISO 42001 Clause | Requirement | GRC-Shield Response |
|---|---|---|
| 6.1.2 | AI risk assessment must address behavioral drift risks | GS-12 implements continuous behavioral monitoring as a risk control |
| 8.4 | Controls ensuring AI systems behave as intended over time | Periodic recalibration reviews enforced when drift is detected |
| 9.1 | Monitoring and measurement of AI system performance | Weekly drift reports generated and logged |
| 9.3 | Management review | Drift detection reports must be reviewed by responsible management periodically |

---

## 5. ISO 27001:2022 Mapping

| ISO 27001:2022 Control | Description | Relevance |
|---|---|---|
| A.8.16 | Monitoring activities | Continuous behavioral monitoring of agent outputs over time |
| A.8.15 | Logging | Full historical assessment log enables retrospective drift analysis |
| A.5.36 | Compliance with policies, rules, and standards | Agent behavior must remain consistent with defined risk appetite parameters |
| A.5.29 | Information security during disruption | Rogue agent detection triggers incident response and compliance record review |

*Note: All references use ISO 27001:2022 numbering.*

---

## 6. Detection Control

**GS-12 — Rogue Agent Behavioral Monitor**

See `detection-engine/grc_shield/gs12_rogue_agent_monitor.py`

GS-12 operates continuously across all agent assessment outputs:

- Maintains a rolling statistical baseline of agent outputs per control category, risk type, and vendor trust tier
- Weekly distribution comparison: current period outputs vs. calibrated baseline
- Drift threshold: if mean risk score for any control category deviates more than 1.5 standard deviations from baseline over a rolling 30-day window, human recalibration review is triggered
- Agent is placed in supervised mode — all outputs require human countersignature — until recalibration review is completed
- All drift events, review decisions, and recalibration outcomes logged to immutable audit record

---

## 7. References

1. OWASP Top 10 for Agentic Applications 2026. https://genai.owasp.org (December 2025)
2. DeepTeam. "OWASP Top 10 for Agents 2026." https://www.trydeepteam.com/docs/frameworks-owasp-top-10-for-agentic-applications
3. Speakeasy. "The OWASP Agentic Top 10, Explained." June 2026.
4. ISO/IEC 42001:2023. Artificial Intelligence Management System.
5. ISO/IEC 27001:2022. Information Security Management Systems — Requirements.
