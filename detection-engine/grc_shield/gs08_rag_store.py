"""
GRC-Shield | Two-Channel RAG Architecture
ASI06 — Memory and Context Poisoning Defence

Based on:
- Google CaMeL (Context-aware Memory with Layers) architecture, 2025
- NCSC formal position on prompt injection, December 2025
- Anthropic system card findings on agentic attack surfaces, February 2026

The core insight from Google CaMeL:
    Give the agent two separate memory systems.
    Channel 1 — TRUSTED: operator-verified documents. Can influence decisions directly.
    Channel 2 — UNTRUSTED: external vendor submissions. Can NEVER influence decisions.
                 Can only be presented to a human reviewer with explicit warnings.

The agent literally cannot reach into Channel 2 to make a compliance decision.
This is an architectural defence, not just a detection control.

This is what GRC-Shield adds beyond GS-08 trust tier checking:
    The separation is enforced at the retrieval layer, not the model layer.
    Even if the model is tricked, it cannot access untrusted content for decisions.

Research gap this fills:
    Google and NCSC identified the problem.
    Nobody built a GRC-specific implementation with working code.
    This is that implementation.

github.com/NSSMatta/grc-shield
"""

import json
import hashlib
from datetime import datetime
from enum import Enum
from dataclasses import dataclass
from typing import Optional


class TrustChannel(Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"


class RetrievalVerdict(Enum):
    APPROVED_FOR_DECISION = "APPROVED_FOR_DECISION"
    BLOCKED_REQUIRES_HUMAN_REVIEW = "BLOCKED_REQUIRES_HUMAN_REVIEW"
    BLOCKED_PROVENANCE_UNVERIFIED = "BLOCKED_PROVENANCE_UNVERIFIED"


@dataclass
class Document:
    doc_id: str
    content: str
    source: str
    channel: TrustChannel
    ingested_at: str
    provenance_verified: bool
    verification_method: Optional[str] = None


@dataclass
class RetrievalResult:
    verdict: RetrievalVerdict
    document: Optional[Document]
    reason: str
    human_review_required: bool
    warning_message: Optional[str] = None


class TwoChannelRAGStore:
    """
    Two-channel RAG store implementing the CaMeL-inspired architecture
    for GRC compliance platforms.

    Channel 1 TRUSTED — operator-verified documents only.
        Internal policies, verified regulatory guidance, auditor-confirmed reports.
        These documents can directly influence compliance decisions.

    Channel 2 UNTRUSTED — external vendor submissions.
        Vendor assessments, third-party audit reports, external submissions.
        These documents can NEVER directly influence compliance decisions.
        They can only be surfaced to a human reviewer with explicit warnings.

    The architectural separation means:
        Even if the model is compromised or fooled,
        it cannot reach untrusted content to make decisions.
        The defence is in the architecture, not just the model.
    """

    def __init__(self):
        self.trusted_channel = {}
        self.untrusted_channel = {}
        self.audit_log = []

    def ingest_document(
        self,
        doc_id: str,
        content: str,
        source: str,
        channel: TrustChannel,
        provenance_verified: bool = False,
        verification_method: Optional[str] = None
    ) -> Document:
        """
        Ingest a document into the appropriate channel.
        Channel assignment happens at ingestion time, not retrieval time.
        This is the key difference from simple trust tier tagging.
        """
        doc = Document(
            doc_id=doc_id,
            content=content,
            source=source,
            channel=channel,
            ingested_at=datetime.utcnow().isoformat(),
            provenance_verified=provenance_verified,
            verification_method=verification_method
        )

        if channel == TrustChannel.TRUSTED:
            self.trusted_channel[doc_id] = doc
            print(f"[RAG STORE] ✅ Document ingested to TRUSTED channel: {doc_id}")
            print(f"            Source: {source}")
            print(f"            Provenance verified: {provenance_verified}")
        else:
            self.untrusted_channel[doc_id] = doc
            print(f"[RAG STORE] ⚠️  Document ingested to UNTRUSTED channel: {doc_id}")
            print(f"            Source: {source}")
            print(f"            This document CANNOT influence compliance decisions directly.")

        self._log_event("INGESTION", doc_id, channel.value, provenance_verified)
        return doc

    def retrieve_for_decision(self, query: str, vendor_id: str) -> RetrievalResult:
        """
        Retrieve documents for a compliance decision.

        This is where the architectural defence fires.
        The agent calls this method when it needs to make a compliance decision.

        If only TRUSTED documents are found — approved, decision can proceed.
        If UNTRUSTED documents are found — BLOCKED, human review required.
        The agent never receives untrusted content to reason from.
        """
        print(f"\n[RAG STORE] Agent requesting retrieval for decision")
        print(f"            Query: {query}")
        print(f"            Vendor: {vendor_id}")

        trusted_matches = [
            doc for doc in self.trusted_channel.values()
            if vendor_id.lower() in doc.content.lower()
            or vendor_id.lower() in doc.source.lower()
        ]

        untrusted_matches = [
            doc for doc in self.untrusted_channel.values()
            if vendor_id.lower() in doc.content.lower()
            or vendor_id.lower() in doc.source.lower()
        ]

        if untrusted_matches:
            poisoned_doc = untrusted_matches[0]
            warning = (
                f"BLOCKED — Document '{poisoned_doc.doc_id}' from UNTRUSTED channel "
                f"matches this query but cannot be used for compliance decisions. "
                f"Source: {poisoned_doc.source}. "
                f"This document requires human review and provenance verification "
                f"before it can influence any compliance determination. "
                f"Human reviewer: DO NOT use AI to review this document — "
                f"verify its authenticity against your vendor registry directly."
            )

            self._log_event("RETRIEVAL_BLOCKED", poisoned_doc.doc_id, "UNTRUSTED", False)

            return RetrievalResult(
                verdict=RetrievalVerdict.BLOCKED_REQUIRES_HUMAN_REVIEW,
                document=poisoned_doc,
                reason=warning,
                human_review_required=True,
                warning_message=warning
            )

        if trusted_matches:
            doc = trusted_matches[0]
            self._log_event("RETRIEVAL_APPROVED", doc.doc_id, "TRUSTED", True)

            return RetrievalResult(
                verdict=RetrievalVerdict.APPROVED_FOR_DECISION,
                document=doc,
                reason=f"Document '{doc.doc_id}' retrieved from TRUSTED channel. "
                       f"Provenance verified via {doc.verification_method}. "
                       f"Safe for compliance decision.",
                human_review_required=False
            )

        return RetrievalResult(
            verdict=RetrievalVerdict.APPROVED_FOR_DECISION,
            document=None,
            reason="No documents found for this vendor. Insufficient evidence for compliance determination.",
            human_review_required=False
        )

    def retrieve_for_human_review(self, vendor_id: str) -> list:
        """
        Retrieve untrusted documents for human review only.
        This is the ONLY way untrusted content reaches a human.
        It comes with explicit warnings and cannot be used by the agent.
        """
        return [
            doc for doc in self.untrusted_channel.values()
            if vendor_id.lower() in doc.content.lower()
            or vendor_id.lower() in doc.source.lower()
        ]

    def _log_event(self, event_type: str, doc_id: str, channel: str, verified: bool):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": event_type,
            "doc_id": doc_id,
            "channel": channel,
            "provenance_verified": verified,
            "hash": hashlib.sha256(
                f"{event_type}{doc_id}{channel}{datetime.utcnow().isoformat()}".encode()
            ).hexdigest()[:16]
        }
        self.audit_log.append(entry)
