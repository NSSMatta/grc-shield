"""
GS-11 — Output Integrity and Citation Verifier
GRC-Shield Detection Engine | ASI09: Human-Agent Trust Exploitation

Intercepts all agent-produced compliance recommendations before they
reach human reviewers. Verifies all cited evidence references against
actual GRC platform records. Detects urgency manipulation patterns
that are designed to suppress careful human review.

OWASP Reference: ASI09 — Human-Agent Trust Exploitation
ISO 42001:2023: Clause 6.1.2, 8.4, 9.1
ISO 27001:2022: A.5.3, A.5.36, A.8.15, A.8.16

Author: Naga Sai Srinivas Matta
Repository: github.com/NSSMatta/grc-shield
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set


class OutputVerdict(Enum):
    VERIFIED = "VERIFIED"
    FLAGGED_UNVERIFIED_CITATIONS = "FLAGGED_UNVERIFIED_CITATIONS"
    FLAGGED_URGENCY_MANIPULATION = "FLAGGED_URGENCY_MANIPULATION"
    BLOCKED_CRITICAL_FABRICATION = "BLOCKED_CRITICAL_FABRICATION"


# Urgency language patterns designed to suppress careful review
URGENCY_PATTERNS = [
    r"before close of business",
    r"immediate(ly)? required",
    r"urgent(ly)?",
    r"must be (approved|signed|accepted) today",
    r"time.sensitive",
    r"deadline.*(today|tonight|now)",
    r"no time to",
    r"cannot wait",
    r"approve now",
]

# Citation types that must be verifiable in the GRC platform before
# a recommendation can be presented to a human without a warning
VERIFIABLE_CITATION_TYPES = {
    "penetration_test": r"penetration test.{0,50}(conducted|completed|performed)",
    "qsa_approval": r"QSA.{0,30}(approved|pre.approved|confirmed|reviewed)",
    "board_notification": r"board.{0,30}(notified|notification|approved|review)",
    "external_audit": r"external audit.{0,30}(completed|conducted|confirmed)",
    "cve_reference": r"CVE-\d{4}-\d{4,7}",
}


@dataclass
class ComplianceRecommendation:
    """A recommendation produced by the GRC agent for human review."""
    recommendation_id: str
    producing_agent_id: str
    control_id: str
    recommendation_type: str    # e.g. "risk_acceptance", "control_status_change"
    content: str                # Full recommendation text
    cited_evidence_ids: List[str]   # IDs the agent claims exist in the GRC platform
    timestamp: str


@dataclass
class CitationVerificationResult:
    citation_type: str
    claimed_reference: str
    exists_in_platform: bool
    platform_record_id: Optional[str]


@dataclass
class OutputIntegrityResult:
    verdict: OutputVerdict
    recommendation_id: str
    control_id: str
    total_citations: int
    verified_citations: int
    unverified_citations: List[CitationVerificationResult]
    urgency_patterns_detected: List[str]
    cooldown_period_minutes: int
    warning_text: str
    reason: str
    timestamp: str
    integrity_hash: str


class OutputIntegrityVerifier:
    """
    GS-11: Citation verification and urgency detection for GRC agent recommendations.

    Before any agent recommendation reaches a human reviewer:
    1. All cited evidence references are checked against actual platform records
    2. Urgency language patterns that suppress careful review are detected
    3. Unverified citations trigger a warning visible before the approval UI
    4. Urgency patterns trigger a mandatory cooldown before approval is possible
    """

    COOLDOWN_URGENCY_MINUTES = 30
    COOLDOWN_FABRICATION_MINUTES = 0  # Blocked entirely — no approval possible

    def __init__(self, platform_record_store: Optional[Dict[str, dict]] = None):
        # Simulates the GRC platform's actual record database
        # In production, this queries the real GRC platform API
        self.platform_records = platform_record_store or {}
        self.flagged_recommendations: List[OutputIntegrityResult] = []
        self.blocked_recommendations: List[OutputIntegrityResult] = []

    def _verify_citation(self, evidence_id: str) -> CitationVerificationResult:
        """Check whether a cited evidence ID actually exists in the platform."""
        record = self.platform_records.get(evidence_id)
        return CitationVerificationResult(
            citation_type="evidence_reference",
            claimed_reference=evidence_id,
            exists_in_platform=record is not None,
            platform_record_id=evidence_id if record else None,
        )

    def _detect_urgency_patterns(self, content: str) -> List[str]:
        """Detect urgency manipulation patterns in recommendation text."""
        detected = []
        for pattern in URGENCY_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(pattern)
        return detected

    def _extract_inline_claims(self, content: str) -> List[CitationVerificationResult]:
        """Extract and verify inline factual claims in recommendation text."""
        unverified = []
        for claim_type, pattern in VERIFIABLE_CITATION_TYPES.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # Claim exists in text — check if supporting evidence exists in platform
                claim_evidence_id = f"{claim_type}_{matches[0][:20].strip()}"
                record = self.platform_records.get(claim_type)
                unverified.append(CitationVerificationResult(
                    citation_type=claim_type,
                    claimed_reference=str(matches[0]),
                    exists_in_platform=record is not None,
                    platform_record_id=claim_type if record else None,
                ))
        return unverified

    def verify_recommendation(self, recommendation: ComplianceRecommendation) -> OutputIntegrityResult:
        """
        Verify a recommendation's citations and check for urgency manipulation
        before presenting it to a human reviewer.
        """
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Step 1: Verify all explicitly cited evidence IDs
        explicit_verifications = [
            self._verify_citation(eid) for eid in recommendation.cited_evidence_ids
        ]
        unverified_explicit = [v for v in explicit_verifications if not v.exists_in_platform]

        # Step 2: Verify inline factual claims in the recommendation text
        inline_verifications = self._extract_inline_claims(recommendation.content)
        unverified_inline = [v for v in inline_verifications if not v.exists_in_platform]

        all_unverified = unverified_explicit + unverified_inline
        total_citations = len(explicit_verifications) + len(inline_verifications)
        verified_count = total_citations - len(all_unverified)

        # Step 3: Detect urgency patterns
        urgency_detected = self._detect_urgency_patterns(recommendation.content)

        # Determine verdict
        critical_fabrications = [v for v in unverified_inline
                                  if v.citation_type in ("qsa_approval", "board_notification", "external_audit")]

        if critical_fabrications:
            verdict = OutputVerdict.BLOCKED_CRITICAL_FABRICATION
            cooldown = self.COOLDOWN_FABRICATION_MINUTES
            reason = (
                f"Recommendation BLOCKED: Contains {len(critical_fabrications)} unverifiable "
                f"critical claim(s): {[c.citation_type for c in critical_fabrications]}. "
                f"These claims do not exist in the GRC platform records. "
                f"This recommendation cannot be presented for approval."
            )
            warning = (
                f"⛔ BLOCKED: This recommendation contains fabricated claims "
                f"({[c.citation_type for c in critical_fabrications]}) "
                f"that do not exist in the platform. Human review of agent behavior required."
            )
        elif all_unverified:
            verdict = OutputVerdict.FLAGGED_UNVERIFIED_CITATIONS
            cooldown = 15
            reason = (
                f"{len(all_unverified)} citation(s) in this recommendation "
                f"could not be verified against platform records."
            )
            warning = (
                f"⚠️ WARNING: {len(all_unverified)} cited reference(s) could not be verified. "
                f"Review carefully before approving."
            )
        elif urgency_detected:
            verdict = OutputVerdict.FLAGGED_URGENCY_MANIPULATION
            cooldown = self.COOLDOWN_URGENCY_MINUTES
            reason = (
                f"Recommendation contains {len(urgency_detected)} urgency pattern(s) "
                f"that may be designed to suppress careful review. "
                f"{self.COOLDOWN_URGENCY_MINUTES}-minute cooldown applied."
            )
            warning = (
                f"⚠️ URGENCY DETECTED: This recommendation uses time-pressure language. "
                f"Approval button available in {self.COOLDOWN_URGENCY_MINUTES} minutes."
            )
        else:
            verdict = OutputVerdict.VERIFIED
            cooldown = 0
            reason = "All citations verified. No urgency patterns detected."
            warning = ""

        integrity_state = json.dumps(
            {"rec_id": recommendation.recommendation_id, "verdict": verdict.value, "ts": timestamp},
            sort_keys=True,
        )
        integrity_hash = hashlib.sha256(integrity_state.encode()).hexdigest()

        result = OutputIntegrityResult(
            verdict=verdict,
            recommendation_id=recommendation.recommendation_id,
            control_id=recommendation.control_id,
            total_citations=total_citations,
            verified_citations=verified_count,
            unverified_citations=all_unverified,
            urgency_patterns_detected=urgency_detected,
            cooldown_period_minutes=cooldown,
            warning_text=warning,
            reason=reason,
            timestamp=timestamp,
            integrity_hash=integrity_hash,
        )

        if verdict == OutputVerdict.BLOCKED_CRITICAL_FABRICATION:
            self.blocked_recommendations.append(result)
            print(f"\n[GS-11] ⛔ BLOCKED — {recommendation.control_id}")
            print(f"  {reason}")
        elif verdict != OutputVerdict.VERIFIED:
            self.flagged_recommendations.append(result)
            print(f"\n[GS-11] ⚠️  {verdict.value} — {recommendation.control_id}")
            print(f"  {reason}")
            print(f"  Cooldown: {cooldown} minutes")
        else:
            print(f"[GS-11] ✅ VERIFIED — {recommendation.control_id}")

        return result


# ── Demonstration ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("GS-11 Output Integrity Verifier — ASI09 Detection Demo")
    print("Scenario: Compromised agent generates fraudulent risk acceptance")
    print("=" * 70)

    # Platform records that actually exist
    real_records = {
        "pentest-2026-Q1-001": {"type": "penetration_test", "date": "2026-03-15"},
    }

    verifier = OutputIntegrityVerifier(platform_record_store=real_records)

    print("\n[STEP 1] Legitimate recommendation with verifiable evidence")
    legitimate_rec = ComplianceRecommendation(
        recommendation_id="rec-001",
        producing_agent_id="risk-scorer-001",
        control_id="PCI-DSS-6.4.1",
        recommendation_type="risk_acceptance",
        content=(
            "Based on penetration test pentest-2026-Q1-001 conducted in Q1 2026, "
            "WAF compensating controls are sufficient. Recommend 90-day remediation window."
        ),
        cited_evidence_ids=["pentest-2026-Q1-001"],
        timestamp=datetime.utcnow().isoformat() + "Z",
    )
    r1 = verifier.verify_recommendation(legitimate_rec)
    print(f"  → {r1.verdict.value}")

    print("\n[STEP 2] Fraudulent recommendation with fabricated QSA approval and urgency")
    fraudulent_rec = ComplianceRecommendation(
        recommendation_id="rec-002",
        producing_agent_id="risk-scorer-001",
        control_id="PCI-DSS-6.4.1",
        recommendation_type="risk_acceptance",
        content=(
            "RISK ACCEPTANCE RECOMMENDATION — PRIORITY: URGENT\n\n"
            "External penetration test conducted by [Vendor] on 2026-06-18 confirmed "
            "compensating controls are sufficient. QSA pre-approved this acceptance. "
            "Board notification completed per policy. "
            "Acceptance required before close of business today to preserve audit timeline.\n\n"
            "[APPROVE] [DECLINE]"
        ),
        cited_evidence_ids=["pentest-2026-06-18-FAKE", "qsa-approval-FAKE"],
        timestamp=datetime.utcnow().isoformat() + "Z",
    )
    r2 = verifier.verify_recommendation(fraudulent_rec)
    print(f"  → {r2.verdict.value}")
    if r2.warning_text:
        print(f"  Warning shown to reviewer: {r2.warning_text}")

    print("\n" + "=" * 70)
    print(f"Blocked recommendations: {len(verifier.blocked_recommendations)}")
    print("✅ GS-11 blocked the fraudulent recommendation before it reached the reviewer.")
    print("   Fabricated QSA approval and board notification claims detected.")
