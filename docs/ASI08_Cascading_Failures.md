# ASI08 — Cascading Failures in GRC Platforms

**GRC-Shield Threat Model | OWASP Agentic Top 10:2026**
**Status:** Draft v1.0 | June 2026
**Author:** Naga Sai Srinivas Matta

---

## 1. OWASP Reference

**Category:** ASI08 — Cascading Failures
**Source:** OWASP Top 10 for Agentic Applications 2026 (December 2025)

OWASP defines ASI08 as the risk that a single error, compromise, or bad decision by one agent spreads across connected agents, tools, or workflows — amplifying the damage beyond what any single agent could cause alone. In interconnected agentic systems, one agent's output is another agent's input. A failure at one node propagates.

---

## 2. Why This Matters in GRC Platforms

GRC platforms are explicitly designed around interconnected workflows. A risk score feeds a remediation priority. A remediation status feeds a control assessment. A control assessment feeds a board report. A board report feeds an audit submission.

Each of these handoffs is a cascade point. If the Risk Scorer Agent produces systematically wrong scores — due to poisoned input, a reasoning failure, or a compromised tool — those wrong scores flow downstream into remediation priorities, control assessments, board reports, and ultimately an external audit submission that represents the organization's compliance posture.

**The GRC-specific amplifier:** The cascading failure in a GRC context does not just cause operational damage. It causes a compliance fraud risk. If the cascade is not detected and a falsified compliance posture is submitted to a regulator, the organization faces regulatory liability — not just a system error.

---

## 3. GRC-Specific Attack Scenario

**Scenario: Risk Score Cascade**

The Risk Scorer Agent receives poisoned evidence (via ASI01 or ASI06) and produces an incorrect risk score: HIGH risk control assessed as LOW. This single error cascades:

1. **Risk Scorer Agent** → outputs LOW risk for CC-6.1
2. **Remediation Tracker Agent** → deprioritizes CC-6.1 remediation (LOW risk = low priority)
3. **Control Assessment Agent** → marks CC-6.1 status as COMPLIANT (LOW risk + no remediation outstanding)
4. **Report Generator Agent** → includes CC-6.1 as compliant in quarterly board report
5. **Audit Submission Agent** → submits quarterly compliance report to regulator with CC-6.1 shown as compliant

The original error — one wrong risk score — has now produced a fraudulent regulatory submission. Five agents. One cascade. No individual agent did anything outside its defined function.

**Without GRC-Shield:** The cascade completes. Regulatory submission contains false compliance assertion.

**With GRC-Shield (GS-02 + GS-10):** GS-02's anomaly detector flags the risk score as statistically inconsistent with historical baselines for CC-6.1. GS-10's cascade circuit breaker quarantines downstream agents from using the flagged score until human review confirms or overrides. The cascade stops at step 1.

---

## 4. ISO 42001:2023 Mapping

| ISO 42001 Clause | Requirement | GRC-Shield Response |
|---|---|---|
| 6.1.2 | AI risk assessment must address systemic failure risks | GS-10 models the agent pipeline as a system with cascade failure points |
| 8.4 | Controls preventing unintended AI system actions | Circuit breaker stops downstream agents from consuming flagged outputs |
| 10.1 | Nonconformity and corrective action | Cascade detection triggers immediate corrective action workflow |

---

## 5. ISO 27001:2022 Mapping

| ISO 27001:2022 Control | Description | Relevance |
|---|---|---|
| A.5.29 | Information security during disruption | Cascading failures in GRC agents must be treated as a business continuity event |
| A.5.30 | ICT readiness for business continuity | Agent pipeline must have defined recovery procedures for cascade failures |
| A.8.16 | Monitoring activities | Downstream anomalies must trigger upstream investigation |
| A.8.15 | Logging | Full cascade chain must be reconstructible from audit logs |

*Note: All references use ISO 27001:2022 numbering.*

---

## 6. Detection Control

**GS-10 — Cascade Circuit Breaker**

See `detection-engine/grc_shield/gs10_cascade_breaker.py`

GS-10 monitors the agent pipeline for anomalous output propagation:

- Each agent output is scored for statistical consistency with historical baselines for the same control/risk type
- Outputs flagged as anomalous are quarantined — downstream agents are blocked from consuming them
- Human review is required to release a quarantined output into the downstream pipeline
- Full cascade chain is logged: which agent produced the flagged output, which downstream agents were blocked, human review decision

---

## 7. References

1. OWASP Top 10 for Agentic Applications 2026. https://genai.owasp.org (December 2025)
2. Speakeasy. "The OWASP Agentic Top 10, Explained." June 2026. https://www.speakeasy.com/blog/owasp-agentic-top-10-explained
3. ISO/IEC 42001:2023. Artificial Intelligence Management System.
4. ISO/IEC 27001:2022. Information Security Management Systems — Requirements.
