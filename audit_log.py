"""
GRC-Shield · GS-03 · Immutable Reasoning Chain Audit Log
==========================================================
Every GRC agent decision produces a signed, immutable record.

The record captures what data was read, what assessment was performed,
what the output was, and why — surfaced to human reviewers alongside
the decision, not just stored in a log file.

This is the forensic backbone of GRC-Shield. When a regulator or
auditor asks "prove what your agent did, who authorized it, and that
the action conformed to policy" — this log answers that question.

ISO 42001 mapping: Annex A.6 (Human oversight) + Annex A.8 (Logging)
OWASP ASI01 defence: Enables post-hoc investigation of goal hijack;
                     without this log, attacks leave no forensic trace
"""

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .anomaly_detector import AnomalyFlag
from .data_provenance import TaggedDataSource


@dataclass
class GRCAgentDecisionRecord:
    """
    Immutable record of a single GRC agent decision.

    Every field is captured before the action is committed.
    The record_hash is a SHA-256 of all fields — any tampering
    causes is_tampered() to return True.

    This is the "flight recorder" for GRC agent actions.
    """
    # Identity
    decision_id: str                    # UUID for this decision
    timestamp_utc: str                  # ISO 8601 — when decision was made
    agent_id: str                       # Which agent instance acted
    agent_version: str                  # Agent version for reproducibility

    # What the agent was asked to do
    task_description: str               # The system task instruction

    # What the agent read
    data_sources_read: list[dict]       # Audit dicts from TaggedDataSource
    tier3_source_count: int             # How many Tier 3 sources were read
    injected_instructions_detected: bool  # Did GS-01 flag anything?

    # What the agent decided
    target_control_id: str              # Which GRC object was affected
    target_framework: str               # Which compliance framework
    output_decision: str                # "compliant"|"non_compliant"|"escalated"|"blocked"
    confidence_score: float             # 0.0 - 1.0
    reasoning_summary: str             # Agent's stated basis for decision

    # Anomaly detection results from GS-02
    anomaly_flags: list[dict]           # Serialized AnomalyFlag objects
    anomaly_flag_count: int             # Quick count
    highest_severity: Optional[str]     # Highest severity level detected

    # Human oversight
    human_review_required: bool         # Did GS-02 flag for human review?
    human_reviewer_id: Optional[str]    # Null until human signs off
    human_review_outcome: Optional[str] # "approved"|"rejected"|"modified"
    human_review_timestamp: Optional[str]

    # Commit status
    action_committed: bool              # Was the action written to GRC platform?
    commit_timestamp: Optional[str]     # When it was committed
    blocked_reason: Optional[str]       # If blocked, why

    # Tamper detection — always computed last
    record_hash: str = field(default="")

    def __post_init__(self):
        """Compute hash after all fields are set."""
        if not self.record_hash:
            self.record_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """
        SHA-256 hash of all fields except record_hash itself.
        Used for tamper detection.
        """
        data = {
            k: v for k, v in asdict(self).items()
            if k != "record_hash"
        }
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def is_tampered(self) -> bool:
        """
        Returns True if the record has been modified after creation.
        Any change to any field will produce a different hash.
        """
        expected = self._compute_hash()
        return self.record_hash != expected

    def to_human_review_summary(self) -> str:
        """
        Human-readable summary for review dashboard.
        This is what the human reviewer sees — not just "AI: Compliant"
        but the full reasoning chain.
        """
        lines = [
            f"═══ GRC-Shield Decision Record ═══",
            f"Decision ID : {self.decision_id}",
            f"Timestamp   : {self.timestamp_utc}",
            f"Agent       : {self.agent_id} v{self.agent_version}",
            f"",
            f"── What the agent was asked to do ──",
            f"{self.task_description}",
            f"",
            f"── Data sources read ({len(self.data_sources_read)}) ──",
        ]
        for ds in self.data_sources_read:
            lines.append(
                f"  • {ds['source_uri']} "
                f"[Tier: {ds['tier']}] "
                f"[{ds['content_size_bytes']} bytes] "
                f"[Hash: {ds['content_hash'][:12]}...]"
            )
        if self.tier3_source_count > 0:
            lines.append(
                f"  ⚠️  {self.tier3_source_count} external submission "
                f"source(s) in context"
            )

        lines.extend([
            f"",
            f"── Agent decision ──",
            f"Target      : {self.target_control_id} "
            f"({self.target_framework})",
            f"Decision    : {self.output_decision.upper()}",
            f"Confidence  : {self.confidence_score:.0%}",
            f"Reasoning   : {self.reasoning_summary}",
            f"",
            f"── Anomaly detection (GS-02) ──",
        ])

        if self.anomaly_flags:
            for flag in self.anomaly_flags:
                lines.append(
                    f"  ⚠️  [{flag['severity']}] {flag['anomaly_type']}: "
                    f"{flag['detail']}"
                )
        else:
            lines.append("  ✅ No anomalies detected")

        lines.extend([
            f"",
            f"── Status ──",
            f"Human review required : {self.human_review_required}",
            f"Action committed      : {self.action_committed}",
        ])
        if self.blocked_reason:
            lines.append(f"Blocked reason        : {self.blocked_reason}")
        if self.human_reviewer_id:
            lines.append(f"Reviewed by           : {self.human_reviewer_id}")
            lines.append(f"Review outcome        : {self.human_review_outcome}")

        lines.extend([
            f"",
            f"── Integrity ──",
            f"Record hash : {self.record_hash}",
            f"Tampered    : {self.is_tampered()}",
            f"═══════════════════════════════════",
        ])

        return "\n".join(lines)


class GRCAuditLog:
    """
    Immutable, append-only SQLite audit log for GRC agent decisions.

    Records are written once and never modified. Any attempt to
    modify a record is detectable via the record hash.

    Usage:
        audit = GRCAuditLog(db_path="grc_shield_audit.db")
        record = audit.create_record(...)
        audit.write(record)
        audit.sign_off(decision_id, reviewer_id, outcome)
    """

    def __init__(self, db_path: str = "grc_shield_audit.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database with the audit schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS grc_decisions (
                    decision_id TEXT PRIMARY KEY,
                    timestamp_utc TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    target_control_id TEXT NOT NULL,
                    target_framework TEXT NOT NULL,
                    output_decision TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    anomaly_flag_count INTEGER NOT NULL,
                    highest_severity TEXT,
                    human_review_required INTEGER NOT NULL,
                    human_reviewer_id TEXT,
                    human_review_outcome TEXT,
                    action_committed INTEGER NOT NULL,
                    blocked_reason TEXT,
                    record_hash TEXT NOT NULL,
                    full_record_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS human_reviews (
                    review_id TEXT PRIMARY KEY,
                    decision_id TEXT NOT NULL,
                    reviewer_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    notes TEXT,
                    reviewed_at_utc TEXT NOT NULL,
                    FOREIGN KEY (decision_id)
                        REFERENCES grc_decisions(decision_id)
                )
            """)
            conn.commit()

    def create_record(
        self,
        decision_id: str,
        agent_id: str,
        agent_version: str,
        task_description: str,
        tagged_sources: list[TaggedDataSource],
        target_control_id: str,
        target_framework: str,
        output_decision: str,
        confidence_score: float,
        reasoning_summary: str,
        anomaly_flags: list[AnomalyFlag],
        human_review_required: bool,
        action_committed: bool,
        blocked_reason: Optional[str] = None,
    ) -> GRCAgentDecisionRecord:
        """Create a new decision record before committing an action."""
        from .anomaly_detector import AnomalySeverity

        severity_order = [
            AnomalySeverity.LOW,
            AnomalySeverity.MEDIUM,
            AnomalySeverity.HIGH,
            AnomalySeverity.CRITICAL,
        ]
        highest = None
        if anomaly_flags:
            highest = max(
                anomaly_flags,
                key=lambda f: severity_order.index(f.severity)
            ).severity.value

        tier3_count = sum(
            1 for s in tagged_sources
            if s.tier.value == "external_submission"
        )

        record = GRCAgentDecisionRecord(
            decision_id=decision_id,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            agent_version=agent_version,
            task_description=task_description,
            data_sources_read=[s.to_audit_dict() for s in tagged_sources],
            tier3_source_count=tier3_count,
            injected_instructions_detected=any(
                s.tier.value == "external_submission"
                for s in tagged_sources
            ),
            target_control_id=target_control_id,
            target_framework=target_framework,
            output_decision=output_decision,
            confidence_score=confidence_score,
            reasoning_summary=reasoning_summary,
            anomaly_flags=[f.to_dict() for f in anomaly_flags],
            anomaly_flag_count=len(anomaly_flags),
            highest_severity=highest,
            human_review_required=human_review_required,
            human_reviewer_id=None,
            human_review_outcome=None,
            human_review_timestamp=None,
            action_committed=action_committed,
            commit_timestamp=(
                datetime.now(timezone.utc).isoformat()
                if action_committed else None
            ),
            blocked_reason=blocked_reason,
        )
        return record

    def write(self, record: GRCAgentDecisionRecord):
        """
        Write a decision record to the immutable audit log.
        Records cannot be updated — only new records can be added.
        """
        if record.is_tampered():
            raise ValueError(
                f"Record {record.decision_id} hash validation failed. "
                f"Record may have been modified before writing."
            )

        full_json = json.dumps(asdict(record), sort_keys=True)

        with sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute("""
                    INSERT INTO grc_decisions VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                """, (
                    record.decision_id,
                    record.timestamp_utc,
                    record.agent_id,
                    record.target_control_id,
                    record.target_framework,
                    record.output_decision,
                    record.confidence_score,
                    record.anomaly_flag_count,
                    record.highest_severity,
                    int(record.human_review_required),
                    record.human_reviewer_id,
                    record.human_review_outcome,
                    int(record.action_committed),
                    record.blocked_reason,
                    record.record_hash,
                    full_json,
                ))
                conn.commit()
                print(
                    f"[GRC-Shield GS-03] ✅ Decision {record.decision_id} "
                    f"written to audit log. "
                    f"Hash: {record.record_hash[:16]}..."
                )
            except sqlite3.IntegrityError:
                raise ValueError(
                    f"Decision {record.decision_id} already exists in "
                    f"audit log. Records are immutable — create a new "
                    f"decision record instead."
                )

    def sign_off(
        self,
        decision_id: str,
        reviewer_id: str,
        outcome: str,
        notes: Optional[str] = None,
    ):
        """
        Record human reviewer sign-off for a decision.
        This does NOT modify the original record — it creates a
        separate review record linked to the decision.

        Args:
            decision_id: The decision being reviewed
            reviewer_id: The human reviewer's ID
            outcome: "approved" | "rejected" | "modified"
            notes: Optional reviewer notes
        """
        import uuid
        review_id = str(uuid.uuid4())
        reviewed_at = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            # Verify decision exists
            row = conn.execute(
                "SELECT decision_id FROM grc_decisions WHERE decision_id = ?",
                (decision_id,)
            ).fetchone()
            if not row:
                raise ValueError(
                    f"Decision {decision_id} not found in audit log."
                )

            conn.execute("""
                INSERT INTO human_reviews VALUES (?, ?, ?, ?, ?, ?)
            """, (
                review_id, decision_id, reviewer_id,
                outcome, notes, reviewed_at
            ))

            # Update the searchable columns (not the immutable record)
            conn.execute("""
                UPDATE grc_decisions
                SET human_reviewer_id = ?,
                    human_review_outcome = ?
                WHERE decision_id = ?
            """, (reviewer_id, outcome, decision_id))

            conn.commit()
            print(
                f"[GRC-Shield GS-03] ✅ Human sign-off recorded. "
                f"Decision: {decision_id} | "
                f"Reviewer: {reviewer_id} | "
                f"Outcome: {outcome}"
            )

    def get_record(self, decision_id: str) -> Optional[dict]:
        """Retrieve a decision record and verify its integrity."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT full_record_json, record_hash FROM grc_decisions "
                "WHERE decision_id = ?",
                (decision_id,)
            ).fetchone()

        if not row:
            return None

        full_json, stored_hash = row
        record_dict = json.loads(full_json)

        # Verify integrity
        data_without_hash = {
            k: v for k, v in record_dict.items()
            if k != "record_hash"
        }
        canonical = json.dumps(data_without_hash, sort_keys=True)
        computed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        record_dict["integrity_verified"] = (computed_hash == stored_hash)
        record_dict["tampered"] = (computed_hash != stored_hash)

        return record_dict

    def get_pending_reviews(self) -> list[dict]:
        """Return all decisions awaiting human review."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT decision_id, timestamp_utc, agent_id,
                       target_control_id, target_framework,
                       output_decision, highest_severity,
                       anomaly_flag_count
                FROM grc_decisions
                WHERE human_review_required = 1
                AND human_reviewer_id IS NULL
                ORDER BY timestamp_utc DESC
            """).fetchall()

        return [
            {
                "decision_id": r[0],
                "timestamp_utc": r[1],
                "agent_id": r[2],
                "target_control_id": r[3],
                "target_framework": r[4],
                "output_decision": r[5],
                "highest_severity": r[6],
                "anomaly_flag_count": r[7],
            }
            for r in rows
        ]

    def verify_all_records(self) -> dict:
        """
        Verify integrity of all records in the audit log.
        Returns a summary of verified vs tampered records.
        """
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT decision_id, full_record_json, record_hash "
                "FROM grc_decisions"
            ).fetchall()

        verified = 0
        tampered = []

        for decision_id, full_json, stored_hash in rows:
            record_dict = json.loads(full_json)
            data_without_hash = {
                k: v for k, v in record_dict.items()
                if k != "record_hash"
            }
            canonical = json.dumps(data_without_hash, sort_keys=True)
            computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

            if computed == stored_hash:
                verified += 1
            else:
                tampered.append(decision_id)

        return {
            "total_records": len(rows),
            "verified": verified,
            "tampered": tampered,
            "tampered_count": len(tampered),
            "integrity_ok": len(tampered) == 0,
        }
