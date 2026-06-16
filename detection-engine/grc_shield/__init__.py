"""
GRC-Shield Detection Engine
============================
Governing the AI agents that govern your compliance.

Three controls that wrap any GRC agent deployment:

    GS-01: DataProvenanceTagger   — Trust tier enforcement
    GS-02: AnomalyDetector        — Behavioural anomaly detection  
    GS-03: GRCAuditLog            — Immutable reasoning chain log

Quick start:

    from grc_shield import DataProvenanceTagger, AnomalyDetector, GRCAuditLog

    tagger = DataProvenanceTagger()
    detector = AnomalyDetector()
    audit = GRCAuditLog(db_path="grc_shield_audit.db")
"""

from .data_provenance import (
    DataProvenanceTagger,
    TaggedDataSource,
    TrustTier,
)
from .anomaly_detector import (
    AnomalyDetector,
    AnomalyFlag,
    AnomalyType,
    AnomalySeverity,
    RecommendedAction,
    AgentAction,
    DEFAULT_THRESHOLDS,
)
from .audit_log import (
    GRCAuditLog,
    GRCAgentDecisionRecord,
)

__version__ = "0.1.0"
__all__ = [
    "DataProvenanceTagger",
    "TaggedDataSource",
    "TrustTier",
    "AnomalyDetector",
    "AnomalyFlag",
    "AnomalyType",
    "AnomalySeverity",
    "RecommendedAction",
    "AgentAction",
    "DEFAULT_THRESHOLDS",
    "GRCAuditLog",
    "GRCAgentDecisionRecord",
]
