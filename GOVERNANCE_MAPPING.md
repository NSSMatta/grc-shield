# GRC-Shield — Complete Governance Framework Mapping

**Mapping OWASP Agentic Top 10 Detection Controls to ISO 42001:2023, ISO 27001:2022, SOC 2, PCI DSS v4.0, HIPAA, EU AI Act, DORA, and NIST AI RMF**

**Status:** v3.0 | July 2026
**Author:** Naga Sai Srinivas Matta
**Repository:** github.com/NSSMatta/grc-shield

---

## Purpose

GRC-Shield maps all ten OWASP Agentic Top 10:2026 threats to GRC platform attack scenarios and provides twelve Python detection controls. This document maps each control to every major governance framework relevant to GRC platform deployments in 2026.

**Frameworks covered:**
- ISO 42001:2023 — AI Management System
- ISO 27001:2022 — Information Security Management Systems (2022 numbering)
- SOC 2 — AICPA Trust Services Criteria (2017, aligned to COSO 2013)
- PCI DSS v4.0 — Payment Card Industry Data Security Standard
- HIPAA — Health Insurance Portability and Accountability Act Security Rule (45 CFR 164.312)
- EU AI Act — Regulation (EU) 2024/1689
- DORA — Digital Operational Resilience Act
- NIST AI RMF 1.0 — NIST AI Risk Management Framework (January 2023)

**Important note on ISO 27001 numbering:** All references use ISO 27001:2022 control numbers. The 2013 version used different numbering — supplier relationships were A.15, operations logging was A.12. The 2022 version renumbers these completely.

**Important note on SOC 2 and COSO:** SOC 2 Common Criteria CC1 through CC5 are directly derived from the COSO 2013 Internal Control — Integrated Framework. CC1 maps to COSO Control Environment, CC2 to Information and Communication, CC3 to Risk Assessment, CC4 to Monitoring Activities, CC5 to Control Activities.

**Important note on NIST AI RMF:** The framework is voluntary and non-certifiable. ISO 42001 is the certifiable counterpart. Most organizations use NIST AI RMF inside an ISO 42001 AIMS. NIST AI RMF 1.0 (January 2023) remains current as of July 2026 — the Generative AI Profile (AI 600-1, July 2024) extends it but does not replace it.

---

## Master Mapping Table

| OWASP Scenario | GRC-Shield Control | ISO 42001 | ISO 27001:2022 | SOC 2 | PCI DSS v4.0 | HIPAA 164.312 | EU AI Act | DORA | NIST AI RMF |
|---|---|---|---|---|---|---|---|---|---|
| ASI01 Goal Hijack | GS-01 Data Provenance | Cl.6.1.2, 8.4 | A.5.19, A.8.15 | CC3.2, CC6.1 | Req 10.2, 12.3.2 | (a)(1), (b) | Art.9, 15 | Art.8 | MAP, MEASURE |
| ASI01 Goal Hijack | GS-02 Anomaly Detector | Cl.8.4, 9.1 | A.8.16, A.8.15 | CC4.1, CC7.1 | Req 10.4.1, 10.7 | (b) | Art.9, 12 | Art.10 | MEASURE, MANAGE |
| ASI01 Goal Hijack | GS-03 Audit Log | Cl.9.1, 10.1 | A.8.15, A.5.33 | CC4.1, CC4.2 | Req 10.2, 10.3, 10.5 | (b) | Art.12, 14 | Art.10 | GOVERN, MEASURE |
| ASI02 Tool Misuse | GS-04 Tool Sequencer | Cl.8.4, 6.1.2 | A.8.2, A.8.16 | CC5.2, CC6.3 | Req 7.2, 12.3.2 | (a)(1) | Art.9, 14 | Art.8 | MAP, MANAGE |
| ASI03 Identity Abuse | GS-05 Privilege Scope | Cl.8.4, 8.6 | A.5.15, A.5.18, A.8.2 | CC5.3, CC6.2, CC6.3 | Req 7.1, 7.2, 8.2 | (a)(1) | Art.9, 14 | Art.8 | MAP, MANAGE |
| ASI04 Supply Chain | GS-06 Supply Chain Integrity | Cl.6.1.2, 8.5 | A.5.19, A.5.20, A.8.8 | CC3.4, CC8.1, CC9.2 | Req 6.3, 12.3.2 | (c)(1) | Art.9, 15 | Art.8 | MAP, MEASURE |
| ASI05 Code Execution | GS-07 Code Execution Monitor | Cl.6.1.2, 8.4 | A.8.4, A.8.20 | CC5.1, CC6.8 | Req 6.2, 6.4 | (a)(1), (c)(1) | Art.9, 15 | Art.10 | MEASURE, MANAGE |
| ASI06 Memory Poisoning | GS-08 RAG Integrity | Cl.6.1.2, 8.4 | A.5.19, A.8.16 | CC3.2, CC6.1 | Req 10.2, 12.3.2 | (a)(1), (c)(1) | Art.9, 10 | Art.8 | MAP, MEASURE |
| ASI07 Inter-Agent Comms | GS-09 Message Auth | Cl.8.4, 6.1.2 | A.8.20, A.8.24 | CC6.6, CC7.1 | Req 4.2, 10.2 | (e)(1), (c)(1) | Art.9, 15 | Art.8 | MEASURE, MANAGE |
| ASI08 Cascading Failures | GS-10 Cascade Breaker | Cl.6.1.2, 8.4, 10.1 | A.5.29, A.8.16 | CC4.1, CC7.3, CC7.4 | Req 10.4, 10.7 | (b) | Art.9, 12 | Art.10, 11 | MEASURE, MANAGE |
| ASI09 Trust Exploitation | GS-11 Output Integrity | Cl.8.4, 9.1 | A.5.3, A.5.36 | CC2.3, CC4.1 | Req 12.3.2 | (b) | Art.13, 14 | Art.8 | GOVERN, MEASURE |
| ASI10 Rogue Agents | GS-12 Rogue Agent Monitor | Cl.6.1.2, 9.1, 9.3 | A.8.16, A.5.36 | CC4.1, CC4.2, CC7.5 | Req 10.4, 10.7 | (b) | Art.9, 12 | Art.10 | MEASURE, MANAGE |

---

## ISO 42001:2023 Mapping Detail

ISO 42001 is the AI Management System standard published in December 2023. It is the only certifiable AI governance standard and the primary framework for GRC AI agent deployments.

**Clause 6.1.2 — AI Risk Assessment**
Requires identification and assessment of risks from AI system design, development, and use. All ten OWASP scenarios represent risks that must be assessed before deploying GRC AI agents. GS-01 through GS-12 represent implemented risk treatments.

**Clause 8.4 — AI System Operations**
Requires operational controls ensuring AI systems behave as intended and do not take unintended actions. Every GRC-Shield detection control implements an operational gate preventing unintended agent actions.

**Clause 8.5 — AI Supply Chain**
Requires controls over third-party AI system components.
- GS-06 Supply Chain Integrity — hash-based verification of plugin descriptors at installation

**Clause 8.6 — AI System Documentation**
Requires documentation of AI system capabilities, limitations, and access rights.
- GS-05 Privilege Scope — enforces and documents workflow-scoped permissions

**Clause 9.1 — Monitoring and Measurement**
Requires continuous monitoring of AI system performance and behavior.
- GS-02 Anomaly Detector — real-time behavioral threshold monitoring
- GS-12 Rogue Agent Monitor — rolling drift detection over time
- GS-11 Output Integrity — pre-delivery recommendation verification
- GS-03 Audit Log — immutable record of all agent decisions

**Clause 9.3 — Management Review**
Requires periodic management review of AI system performance.
- GS-12 Rogue Agent Monitor — generates drift reports for management review

**Clause 10.1 — Nonconformity and Corrective Action**
Requires documented response when AI systems behave outside parameters.
- GS-10 Cascade Breaker — triggers corrective action on cascade detection
- GS-03 Audit Log — forensic record for corrective action investigation

---

## ISO 27001:2022 Mapping Detail

**A.5.3 — Segregation of Duties**
- GS-05 Privilege Scope — enforces workflow-level separation of duties
- GS-11 Output Integrity — separates recommendation generation from human approval

**A.5.15 — Access Control Policy**
- GS-05 Privilege Scope — enforces minimum privilege per workflow context

**A.5.18 — Access Rights**
- GS-05 Privilege Scope — blocks inherited admin permissions outside workflow scope

**A.5.19 — Information Security in Supplier Relationships**
- GS-01 Data Provenance — tags vendor submissions as EXTERNAL trust tier
- GS-06 Supply Chain Integrity — verifies plugin vendor update integrity
- GS-08 RAG Integrity — isolates external-tier documents from compliance decisions

**A.5.20 — Addressing Security Within Supplier Agreements**
- GS-06 Supply Chain Integrity — establishes hash baseline at first installation

**A.5.29 — Information Security During Disruption**
- GS-10 Cascade Breaker — quarantines anomalous outputs before cascade

**A.5.33 — Protection of Records**
- GS-03 Audit Log — SHA-256 signed immutable audit record

**A.5.36 — Compliance With Policies, Rules, and Standards**
- GS-11 Output Integrity — verifies citations against platform records
- GS-12 Rogue Agent Monitor — detects drift from calibrated behavioral baseline

**A.8.2 — Privileged Access Rights**
- GS-04 Tool Sequencer — blocks destructive tool access without approval checkpoint
- GS-05 Privilege Scope — blocks admin privilege use outside defined workflow

**A.8.4 — Access to Source Code**
- GS-07 Code Execution Monitor — static analysis gate before any code executes

**A.8.8 — Management of Technical Vulnerabilities**
- GS-06 Supply Chain Integrity — blocks plugin updates with changed descriptors

**A.8.15 — Logging**
- GS-03 Audit Log — applied across all twelve GRC-Shield controls

**A.8.16 — Monitoring Activities**
- GS-02 Anomaly Detector — real-time behavioral threshold monitoring
- GS-10 Cascade Breaker — statistical anomaly detection on agent outputs
- GS-12 Rogue Agent Monitor — rolling drift monitoring over time

**A.8.20 — Network Security**
- GS-09 Message Auth — HMAC-SHA256 signing for all inter-agent messages
- GS-07 Code Execution Monitor — blocks external network calls from generated code

**A.8.24 — Use of Cryptography**
- GS-09 Message Auth — HMAC-SHA256 message authentication

---

## SOC 2 Trust Services Criteria Mapping Detail

SOC 2 Common Criteria CC1 through CC5 derive directly from COSO 2013. CC6 through CC9 cover access, operations, change, and vendor risk.

**CC2.3 — Communication of Objectives and Responsibilities**
- GS-11 Output Integrity — ensures recommendations contain verifiable citations before human review

**CC3.2 — Risk Assessment Considers Fraud**
- GS-01 through GS-12 — collectively implement risk treatments for all ten documented AI agent manipulation scenarios

**CC3.4 — Risk Assessment Considers Vendor and Partner Risks**
- GS-06 Supply Chain Integrity — addresses vendor plugin update risk

**CC4.1 — Monitors Controls**
- GS-03 Audit Log — provides evidence controls operated during the assessment period
- GS-12 Rogue Agent Monitor — continuous behavioral monitoring of agent controls
- GS-11 Output Integrity — verifies output controls operate correctly before each recommendation

**CC4.2 — Evaluates and Communicates Deficiencies**
- GS-12 Rogue Agent Monitor — detects drift and triggers supervised mode
- GS-03 Audit Log — provides forensic trail for deficiency investigation

**CC5.1 — Controls Over Technology**
- GS-07 Code Execution Monitor — controls agent code generation infrastructure

**CC5.2 — Controls to Mitigate Risk**
- GS-04 Tool Sequencer — mitigates unauthorized tool chain risk
- GS-09 Message Auth — mitigates inter-agent message spoofing risk

**CC5.3 — Controls Deployed Through Policies**
- GS-05 Privilege Scope — enforces privilege policy at the workflow execution layer

**CC6.1 — Logical Access Security**
- GS-01 Data Provenance — restricts external-tier content from agent context
- GS-08 RAG Integrity — restricts untrusted chunks from influencing compliance decisions

**CC6.2 — Prior to Issuance of System Credentials**
- GS-05 Privilege Scope — blocks credential use outside authorized workflow scope

**CC6.3 — Role-Based Access Controls**
- GS-04 Tool Sequencer — enforces role-based tool access per workflow state
- GS-05 Privilege Scope — enforces role-based privilege scoping per workflow

**CC6.6 — Security Controls over Transmitted Information**
- GS-09 Message Auth — HMAC-SHA256 authentication for all inter-agent messages

**CC6.8 — Controls Prevent or Detect Unauthorized or Malicious Software**
- GS-07 Code Execution Monitor — static analysis prevents malicious code execution

**CC7.1 — Detects and Monitors for New Vulnerabilities**
- GS-02 Anomaly Detector — real-time behavioral anomaly detection
- GS-04 Tool Sequencer — detects unauthorized tool chain patterns
- GS-07 Code Execution Monitor — detects malicious patterns in generated code
- GS-09 Message Auth — detects spoofed inter-agent messages

**CC7.2 — Monitors System Components for Anomalous Behavior**
- GS-01 Data Provenance — monitors data source trust tier at ingestion
- GS-08 RAG Integrity — monitors RAG retrieval for untrusted content

**CC7.3 — Evaluates Security Events**
- GS-02 Anomaly Detector — evaluates agent actions against behavioral thresholds
- GS-03 Audit Log — provides forensic record for security event evaluation
- GS-10 Cascade Breaker — evaluates statistical anomalies before downstream propagation

**CC7.4 — Responds to Security Incidents**
- GS-10 Cascade Breaker — quarantines anomalous outputs and blocks downstream agents

**CC7.5 — Identifies and Addresses Deficiencies**
- GS-12 Rogue Agent Monitor — identifies behavioral drift and triggers supervised mode

**CC8.1 — Manages Changes to System Components**
- GS-06 Supply Chain Integrity — blocks unauthorized plugin descriptor changes

**CC9.2 — Manages Vendor and Business Partner Risks**
- GS-06 Supply Chain Integrity — verifies vendor plugin updates before activation
- GS-01 Data Provenance — tags vendor submissions as untrusted before agent processing
- GS-08 RAG Integrity — prevents vendor documents from influencing compliance decisions unverified

---

## PCI DSS v4.0 Mapping Detail

PCI DSS v4.0 published March 2022, mandatory since March 2024. Applies to GRC platforms processing, storing, or transmitting cardholder data, and to AI agents operating within those platforms.

**Requirement 6.2 — Bespoke and Custom Software Are Protected**
Software developed by or for the organization must be protected from attack.
- GS-07 Code Execution Monitor — static analysis prevents malicious code in agent-generated scripts

**Requirement 6.3 — Security Vulnerabilities Are Identified and Addressed**
Security vulnerabilities in system components must be identified and managed.
- GS-06 Supply Chain Integrity — identifies tampered plugin descriptors before agent loads them

**Requirement 6.4 — Public-Facing Web Applications Are Protected From Attacks**
Applies to agent API surfaces exposed to external inputs.
- GS-01 Data Provenance — tags all external inputs before they reach the agent
- GS-08 RAG Integrity — blocks external content from influencing compliance decisions

**Requirement 7.1 — Access to System Components and Data Is Limited**
Access must be limited to only what is required for each individual's job function.
- GS-05 Privilege Scope — enforces minimum privilege per workflow context

**Requirement 7.2 — Access to System Components and Data Is Appropriately Defined and Assigned**
Access must be defined based on job classification and function.
- GS-04 Tool Sequencer — enforces tool access rights per workflow state
- GS-05 Privilege Scope — enforces privilege rights per defined workflow

**Requirement 8.2 — User Identification and Authentication Are Managed**
User and system account management must prevent unauthorized access.
- GS-05 Privilege Scope — prevents AI agent service accounts from exceeding defined scope

**Requirement 10.2 — Audit Logs Are Implemented to Support Detection**
Audit logs must capture events to support anomaly detection and forensic analysis.
- GS-03 Audit Log — captures every agent decision with full context and SHA-256 signature
- GS-01 Data Provenance — logs all data source trust tier assignments at ingestion

**Requirement 10.3 — Audit Logs Are Protected From Destruction and Unauthorized Modifications**
Log integrity must be ensured.
- GS-03 Audit Log — tamper-evident SHA-256 signed immutable audit record

**Requirement 10.4 — Audit Logs Are Reviewed to Identify Anomalies**
Logs must be reviewed using automated mechanisms where possible.
- GS-02 Anomaly Detector — automated behavioral threshold review of agent actions
- GS-10 Cascade Breaker — automated statistical review of agent outputs
- GS-12 Rogue Agent Monitor — automated rolling drift review over time

**Requirement 10.5 — Audit Log History Is Retained and Available for Analysis**
Log retention must meet defined minimums.
- GS-03 Audit Log — persistent storage of all audit records

**Requirement 10.7 — Failures of Critical Security Controls Are Detected and Reported**
Failures of security control systems must be detected and addressed promptly.
- GS-02 Anomaly Detector — detects and flags behavioral control failures in real time
- GS-10 Cascade Breaker — detects statistical failures in agent output controls

**Requirement 12.3.2 — Targeted Risk Analysis for Customized Approaches**
Organizations using customized approaches must perform a targeted risk analysis.
- GS-01 through GS-12 — collectively constitute the targeted risk analysis and implemented controls for AI agent risks in the cardholder data environment

---

## HIPAA Security Rule Mapping Detail

45 CFR 164.312 — Technical Safeguards. Applies when GRC AI agents process, store, or transmit electronic Protected Health Information (ePHI). Healthcare GRC platforms and compliance agents managing HIPAA control evidence fall within scope.

**164.312(a)(1) — Access Control (Required)**
Technical policies and procedures allowing access to ePHI only to authorized persons and software programs.
- GS-05 Privilege Scope — restricts AI agent service account access to workflow-defined scope
- GS-04 Tool Sequencer — restricts tool access to authorized workflow states
- GS-01 Data Provenance — restricts external-tier content from entering agent context

**164.312(a)(2)(i) — Unique User Identification (Required)**
Assign unique identifiers to each user and software component.
- GS-03 Audit Log — records unique agent identity and session for every decision
- GS-09 Message Auth — HMAC signing identifies each sending agent uniquely

**164.312(b) — Audit Controls (Required)**
Implement mechanisms to record and examine activity in systems that create, receive, maintain, or transmit ePHI.
- GS-03 Audit Log — immutable SHA-256 signed record of all agent decisions and data accesses
- GS-02 Anomaly Detector — records all behavioral flag events with full context
- GS-10 Cascade Breaker — records all quarantine events with statistical evidence
- GS-12 Rogue Agent Monitor — records all drift detection events and mode changes

**164.312(c)(1) — Integrity (Required)**
Implement policies and procedures to protect ePHI from improper alteration or destruction.
- GS-03 Audit Log — tamper-evident storage prevents unauthorized modification of audit records
- GS-09 Message Auth — HMAC verification prevents unauthorized alteration of inter-agent messages
- GS-06 Supply Chain Integrity — SHA-256 hash verification prevents unauthorized alteration of plugin descriptors

**164.312(c)(2) — Mechanism to Authenticate ePHI (Addressable)**
Implement electronic mechanisms to corroborate that ePHI has not been altered or destroyed.
- GS-09 Message Auth — HMAC-SHA256 authentication corroborates message integrity
- GS-06 Supply Chain Integrity — hash comparison corroborates plugin descriptor integrity

**164.312(d) — Person or Entity Authentication (Required)**
Implement procedures to verify that persons or entities seeking access are who they claim to be.
- GS-09 Message Auth — HMAC-SHA256 verifies sending agent identity before message processing

**164.312(e)(1) — Transmission Security (Required)**
Implement technical measures to guard against unauthorized access to ePHI transmitted over electronic communications networks.
- GS-09 Message Auth — authenticates and integrity-checks all inter-agent message transmission

---

## EU AI Act Mapping Detail

Regulation (EU) 2024/1689. High-risk AI provisions apply from August 2026. GRC compliance agents autonomously influencing compliance decisions in regulated industries likely qualify as high-risk AI systems under Annex III.

**Article 9 — Risk Management System**
Requires a continuous, iterative risk management system throughout the AI system lifecycle.
- GS-01 through GS-12 — collectively implement the risk management system required by Article 9
- GS-12 Rogue Agent Monitor — satisfies the continuous monitoring and iterative review requirement

**Article 10 — Data and Data Governance**
Requires data governance controls including examination of data for biases and errors.
- GS-01 Data Provenance — trust tier tagging implements data governance at ingestion
- GS-08 RAG Integrity — prevents biased or corrupted external data from influencing decisions

**Article 12 — Record Keeping and Automatic Logging**
High-risk AI systems must automatically log events throughout their operation.
- GS-03 Audit Log — immutable SHA-256 signed audit record of every agent decision
- GS-02 Anomaly Detector — logs all behavioral flag events
- GS-10 Cascade Breaker — logs all quarantine events with full context

**Article 13 — Transparency and Provision of Information**
Deployers must be able to interpret AI system outputs and understand their basis.
- GS-11 Output Integrity — ensures all cited evidence is verifiable before presentation
- GS-03 Audit Log — provides complete decision reasoning chain for deployer review

**Article 14 — Human Oversight**
High-risk AI systems must enable effective human oversight and allow humans to intervene or override.
- GS-04 Tool Sequencer — requires human approval checkpoint before destructive actions
- GS-05 Privilege Scope — blocks out-of-scope actions pending human escalation
- GS-11 Output Integrity — applies mandatory cooling-off before approval UI activates
- GS-12 Rogue Agent Monitor — places drifting agents in supervised mode requiring human countersignature

**Article 15 — Accuracy, Robustness, and Cybersecurity**
High-risk AI systems must resist adversarial attacks and maintain accuracy throughout their lifecycle.
- GS-01 Data Provenance — trust tier tagging reduces adversarial input risk
- GS-06 Supply Chain Integrity — protects against adversarial supply chain attacks
- GS-07 Code Execution Monitor — protects against adversarial code injection
- GS-09 Message Auth — protects against adversarial inter-agent message spoofing

---

## DORA Mapping Detail

Regulation (EU) 2022/2554. Mandatory for financial services entities from January 2025. GRC platforms used by banks, insurers, and investment firms are ICT systems subject to DORA ICT risk management requirements.

**Article 8 — Identification**
Financial entities must identify and classify ICT assets and their risks.
- GS-01 Data Provenance — classifies all data inputs by trust tier
- GS-05 Privilege Scope — documents AI agent permission boundaries per workflow
- GS-06 Supply Chain Integrity — identifies and validates third-party ICT components

**Article 10 — Detection**
Financial entities must implement mechanisms to promptly detect anomalous activities.
- GS-02 Anomaly Detector — real-time behavioral anomaly detection
- GS-09 Message Auth — detects spoofed inter-agent communications immediately
- GS-12 Rogue Agent Monitor — detects systematic behavioral drift across time

**Article 11 — Response and Recovery**
Financial entities must have documented response and recovery plans for ICT incidents.
- GS-10 Cascade Breaker — automated quarantine and block before cascade propagation
- GS-03 Audit Log — forensic evidence required for incident response and regulatory reporting

---

## NIST AI RMF 1.0 Mapping Detail

Published January 2023. Voluntary and non-certifiable. Four core functions: GOVERN, MAP, MEASURE, MANAGE. Most organizations use NIST AI RMF inside an ISO 42001 AIMS. The Generative AI Profile (AI 600-1, July 2024) extends the framework to generative AI risk categories.

**GOVERN — Culture of Risk Management**
Establishes organizational accountability, policies, and oversight for AI risk. GRC-Shield addresses GOVERN through its threat model documentation, governance mapping, and human oversight controls.
- GS-11 Output Integrity — enforces human review gate before compliance decisions commit
- GS-04 Tool Sequencer — enforces human approval checkpoint before destructive actions
- GS-12 Rogue Agent Monitor — escalates to supervised mode requiring management countersignature
- GOVERNANCE_MAPPING.md (this document) — documents the organizational risk governance posture

**MAP — Context Is Recognized and Risks Identified**
Establishes context, identifies AI risks, and categorizes their potential impacts. GRC-Shield's ten threat model documents (docs/ASI01 through docs/ASI10) are the MAP function output for GRC AI agent deployments.
- docs/ASI01_Goal_Hijack.md through docs/ASI10_Rogue_Agents.md — ten complete risk context documents
- GS-01 Data Provenance — maps data source trust context before agent processing
- GS-05 Privilege Scope — maps permission context per workflow
- GS-06 Supply Chain Integrity — maps plugin supply chain risk context

**MEASURE — Risks Are Analyzed and Quantified**
Uses quantitative, qualitative, or mixed-method tools to analyze and benchmark AI risk. GRC-Shield's live simulations are the MEASURE function output.
- demo/ simulation files — live simulation results quantifying attack success and detection effectiveness
- GS-02 Anomaly Detector — quantifies behavioral deviation against defined thresholds
- GS-10 Cascade Breaker — quantifies statistical deviation (e.g. 3.23 standard deviations) before quarantine
- GS-12 Rogue Agent Monitor — quantifies drift (e.g. 1.55 standard deviations) against calibrated baseline

**MANAGE — Risks Are Prioritized and Addressed**
Allocates resources to address identified risks based on GOVERN definitions. GRC-Shield's detection controls are the MANAGE function implementation.
- GS-04 through GS-12 — nine controls implementing risk treatment for identified AI agent risks
- GS-10 Cascade Breaker — automated risk response — quarantine before cascade
- GS-12 Rogue Agent Monitor — automated risk escalation — supervised mode on drift detection

---

## How to Use This Document

**For compliance teams:** Use the master mapping table to identify which GRC-Shield controls address gaps in your current compliance posture across all eight frameworks simultaneously.

**For auditors:** Use the SOC 2 section to understand which Trust Services Criteria GRC-Shield controls provide evidence for — across both the COSO-derived CC1-CC5 and the operational CC6-CC9.

**For financial services teams:** Use the DORA section to identify which controls address ICT risk management requirements under Articles 8, 10, and 11.

**For healthcare teams:** Use the HIPAA 164.312 section to understand which controls address technical safeguard requirements when GRC agents process ePHI.

**For payment card environments:** Use the PCI DSS v4.0 section to identify which controls address Requirements 6, 7, 8, 10, and 12.3.2.

**For regulated AI deployers:** Use the EU AI Act section to understand which controls address Articles 9, 10, 12, 13, 14, and 15 for high-risk AI systems.

**For AI governance programs:** Use the NIST AI RMF section to map GRC-Shield outputs to the GOVERN, MAP, MEASURE, and MANAGE functions.

**For beginners:** Start with the master mapping table. Find the OWASP scenario most relevant to your platform. Read the corresponding threat model document in the docs/ folder. Run the simulation. Then check this document to understand which compliance requirement it addresses.

---

## References

1. ISO/IEC 42001:2023 — Artificial Intelligence Management System
2. ISO/IEC 27001:2022 — Information Security Management Systems
3. AICPA Trust Services Criteria 2017 (updated 2022) — SOC 2
4. COSO Internal Control — Integrated Framework 2013
5. PCI DSS v4.0 — Payment Card Industry Data Security Standard (March 2022)
6. 45 CFR 164.312 — HIPAA Security Rule Technical Safeguards
7. Regulation (EU) 2024/1689 — EU Artificial Intelligence Act
8. Regulation (EU) 2022/2554 — Digital Operational Resilience Act (DORA)
9. NIST AI Risk Management Framework 1.0 — January 2023 (NIST AI 100-1)
10. NIST Generative AI Profile (AI 600-1) — July 2024
11. OWASP Top 10 for Agentic Applications 2026 — genai.owasp.org

---

*GRC-Shield Governance Mapping v3.0 · July 2026*
*github.com/NSSMatta/grc-shield*
