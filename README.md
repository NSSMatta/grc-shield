# GRC-Shield

**Governing the AI Agents That Govern Your Compliance**

[![License: CC0 1.0](https://img.shields.io/badge/License-CC0%201.0-lightgrey.svg)](https://creativecommons.org/publicdomain/zero/1.0/)
[![Framework: OWASP Agentic Top 10](https://img.shields.io/badge/Framework-OWASP%20Agentic%20Top%2010-red)](https://owasp.org)
[![Standard: ISO 42001:2023](https://img.shields.io/badge/Standard-ISO%2042001%3A2023-blue)](https://www.iso.org/standard/81230.html)
[![Status: Open for Review](https://img.shields.io/badge/Status-Open%20for%20Community%20Review-green)]()

---

## The Problem

AI agents are being deployed inside enterprise GRC platforms — ServiceNow IRM/BCM, MetricStream, RSA Archer — to autonomously mark controls compliant, score risks, file policy exceptions, and generate board-level compliance reports.

**Nobody is governing the agents doing this work.**

In June 2025, researchers disclosed **CVE-2025-32711 (EchoLeak)** — a CVSS 9.3 zero-click prompt injection attack on Microsoft 365 Copilot that required no user interaction to exfiltrate sensitive enterprise data. The attack mechanism: the AI agent read a business document containing hidden instructions and acted on them.

Every AI agent operating in a GRC platform that **reads GRC data before acting on it** has the same structural vulnerability. A poisoned evidence attachment. A manipulated regulatory feed. A vendor questionnaire containing injected instructions. The agent reads it. The control gets marked Compliant. The board sees a green dashboard. The auditor finds it six months later.

This is not theoretical. In 2024, banking institutions incurred **$3.2 billion** in compliance-related fees. **73%** of production AI deployments have been found vulnerable to prompt injection during security audits. **42–44%** of organisations deploying compliance AI have no human-in-the-loop oversight in place.

The gap between AI deployment and AI accountability in GRC is real, measurable, and currently unaddressed by any GRC platform vendor.

---

## What GRC-Shield Is

GRC-Shield is an **open-source framework** that does three things no existing tool does together:

1. **Maps OWASP Agentic Top 10 threats (ASI01–ASI10) to specific GRC attack scenarios** — what goal hijacking looks like when the agent is managing your ServiceNow risk register, not generating code
2. **Maps ISO/IEC 42001:2023 controls to each threat** — the AI governance standard already requires most of these controls; organisations just haven't applied them to their GRC agents
3. **Provides a detection engine** — open-source Python middleware that wraps GRC agent actions with data provenance tagging, behavioural anomaly detection, and immutable reasoning chain audit logs

---

## Structure

```
grc-shield/
│
├── docs/
│   ├── ASI01_Goal_Hijack.md          ← Attack taxonomy + ISO 42001 mapping (COMPLETE)
│   ├── ASI02_Tool_Misuse.md          ← Coming
│   ├── ASI03_Identity_Abuse.md       ← Coming
│   └── ...
│
├── detection-engine/
│   ├── grc_shield/
│   │   ├── data_provenance.py        ← GS-01: Trust tier enforcement
│   │   ├── anomaly_detector.py       ← GS-02: Behavioural anomaly detection
│   │   ├── audit_log.py             ← GS-03: Immutable reasoning chain log
│   │   └── __init__.py
│   ├── tests/
│   └── requirements.txt
│
├── demo/
│   └── langgraph_attack_demo/        ← LangGraph agent: attack + detection (Coming)
│
├── iso42001/
│   └── control_mapping_template.md  ← SoA template for GRC AI deployments
│
└── README.md
```

---

## Current Status

| Layer | What | Status |
|-------|------|--------|
| **Layer 1** | ASI01 attack taxonomy + ISO 42001 mapping | ✅ Complete — open for review |
| **Layer 2** | Python detection engine (GS-01 to GS-03) | 🔄 In development |
| **Layer 3** | LangGraph attack + detection demo | 🔄 In development |

---

## Layer 1 — ASI01: Goal Hijack in GRC Platforms

The first complete attack scenario document covers:

- **What OWASP ASI01 actually looks like** inside ServiceNow IRM, MetricStream, and RSA Archer
- **Three specific attack scenarios** with full attack chains:
  - Scenario A: The Poisoned Evidence Attachment
  - Scenario B: The Regulatory Feed Poisoning  
  - Scenario C: The Vendor Questionnaire Escalation
- **Why current GRC platform controls don't stop these attacks** (RBAC, approval workflows, audit trails — all insufficient)
- **ISO 42001 clause-by-clause mapping** — Cl.6.1.2, Cl.6.1.3, Cl.8.4, Annex A.6, Annex A.8, Cl.9 — with current gap assessment for each
- **Three proposed detection controls** (GS-01, GS-02, GS-03) with working Python code

→ **[Read ASI01 — Goal Hijack in GRC Platforms](docs/ASI01_Goal_Hijack.md)**

---

## Layer 2 — Detection Engine (Preview)

Three Python controls that wrap any GRC agent deployment:

```python
from grc_shield import DataProvenanceTagger, AnomalyDetector, GRCAuditLog

# GS-01: Tag every data source with its trust tier
# before it enters the agent's context window
tagger = DataProvenanceTagger()
context = tagger.build_safe_context(evidence_docs, control_record)

# GS-02: Check every agent action against behavioural thresholds
detector = AnomalyDetector(thresholds=THRESHOLDS)
flags = detector.check(agent_action, recent_actions, platform_state)

# GS-03: Write an immutable, signed record of every decision
audit = GRCAuditLog(db_path="grc_shield_audit.db")
audit.record(decision_record)
```

---

## Why This Matters Now

| Regulation | Requirement | GRC Agent Gap |
|------------|-------------|---------------|
| **EU AI Act** (Aug 2026) | Conformity assessment, human oversight, audit trail for high-risk AI systems | GRC compliance agents likely qualify as high-risk. No vendor has published a conformity assessment. |
| **ISO 42001:2023** | AI risk assessment (Cl.6.1) before deployment; operational controls (Cl.8.4); human oversight (Annex A.6); logging (Annex A.8) | Most GRC AI deployments have not conducted an ISO 42001 risk assessment for their agents. |
| **DORA** (enforcing 2025) | ICT risk management framework covering all AI systems in ICT operations | AI agents in GRC platforms are ICT systems. ~50% of financial institutions not fully DORA compliant. |
| **PCI DSS v4.0** | Continuous monitoring; evidence of control effectiveness | An agent falsely marking a PCI DSS control compliant = a compliance failure with no detection mechanism. |

---

## How to Contribute

We are actively looking for:

- **GRC practitioners** who have seen unexpected AI agent behaviour in production GRC platforms
- **ServiceNow IRM/BCM administrators** who can validate whether the attack scenarios are feasible against current platform configurations
- **ISO 42001 implementers** who can review and challenge the control mapping
- **Cybersecurity researchers** who want to extend the taxonomy to ASI02–ASI10 in GRC contexts
- **Regulatory professionals** who can map scenarios to specific EU AI Act, DORA, and PCI DSS clause violations

Open an Issue. Submit a PR. Start a Discussion. All welcome.

---

## References

All claims in this framework are sourced and cited. Key references:

1. AI21 Labs (2025) — $3.2B banking compliance fees in 2024
2. PreMAI / OWASP (2026) — 73% of production AI deployments vulnerable to prompt injection
3. Kiteworks (2026) — 42–44% of compliance AI deployments lack human-in-the-loop oversight
4. Aim Security / arXiv:2509.10540 (2025) — EchoLeak CVE-2025-32711 academic analysis
5. OWASP Foundation (2025) — Top 10 for Agentic Applications 2026
6. Cloud Security Alliance (2026, April) — AI Agent Governance Gap analysis
7. ISO/IEC 42001:2023 — AI Management Systems standard

Full citations in each scenario document.

---

## License

This framework is published under **Creative Commons CC0 1.0 Universal** — cite it, build on it, use it commercially, adapt it. Just attribute the source.

This is not a product. It is not affiliated with OWASP, ISO, ServiceNow, MetricStream, or any GRC platform vendor. All attack scenarios are theoretical threat models for defensive research purposes.

---

*GRC-Shield v0.1 · June 2026 · Open for community review*
