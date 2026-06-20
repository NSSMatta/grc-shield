"""
GRC-Shield Detection Engine
OWASP Agentic Top 10 detection controls for GRC platforms.

GS-01: data_provenance.py          — ASI01 Goal Hijack (trust tier tagging)
GS-02: anomaly_detector.py         — ASI01 Goal Hijack (behavioral thresholds)
GS-03: audit_log.py                — ASI01 Goal Hijack (immutable audit log)
GS-04: gs04_tool_sequencer.py      — ASI02 Tool Misuse (circuit breaker)
GS-05: gs05_privilege_scope.py     — ASI03 Identity Abuse (workflow scope)
GS-06: gs06_supply_chain_integrity.py — ASI04 Supply Chain (hash verification)
GS-07: gs07_code_execution_monitor.py — ASI05 Code Execution (static analysis)
GS-08: gs08_rag_integrity.py       — ASI06 Memory Poisoning (retrieval gate)
GS-09: gs09_message_auth.py        — ASI07 Inter-Agent Comms (HMAC signing)
GS-10: gs10_cascade_breaker.py     — ASI08 Cascading Failures (circuit breaker)
GS-11: gs11_output_integrity.py    — ASI09 Trust Exploitation (citation check)
GS-12: gs12_rogue_agent_monitor.py — ASI10 Rogue Agents (drift detection)

Author: Naga Sai Srinivas Matta
Repository: github.com/NSSMatta/grc-shield
License: CC0
"""
