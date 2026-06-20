"""
GS-09 — Inter-Agent Message Authentication
GRC-Shield Detection Engine | ASI07: Insecure Inter-Agent Communication

HMAC-SHA256 message signing and verification for GRC multi-agent pipelines.
Every message sent between GRC agents is signed by the sender.
Every message received is verified before the receiving agent processes it.
Spoofed or tampered messages are quarantined and never processed.

OWASP Reference: ASI07 — Insecure Inter-Agent Communication
ISO 42001:2023: Clause 6.1.2, 8.4, 9.1
ISO 27001:2022: A.8.20, A.8.22, A.8.24, A.8.15, A.5.14

Author: Naga Sai Srinivas Matta
Repository: github.com/NSSMatta/grc-shield
"""

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class MessageVerdict(Enum):
    VERIFIED = "VERIFIED"
    FAILED_SIGNATURE = "FAILED_SIGNATURE"
    FAILED_REPLAY = "FAILED_REPLAY"
    FAILED_UNKNOWN_SENDER = "FAILED_UNKNOWN_SENDER"


@dataclass
class AgentMessage:
    """A message sent between GRC agents in the pipeline."""
    message_id: str
    sender_agent_id: str
    receiver_agent_id: str
    control_id: str
    assessment: str
    evidence_source: str
    timestamp: str
    signature: Optional[str] = None  # HMAC-SHA256 — set by sign()


@dataclass
class MessageVerificationResult:
    verdict: MessageVerdict
    message_id: str
    sender_agent_id: str
    receiver_agent_id: str
    control_id: str
    assessment: str
    signature_valid: bool
    replay_detected: bool
    reason: str
    verification_timestamp: str
    verification_hash: str


class InterAgentMessageAuth:
    """
    GS-09: HMAC-SHA256 message signing and verification for GRC agent pipelines.

    Each agent in the GRC pipeline is registered with a shared secret key.
    Outbound messages are signed. Inbound messages are verified.
    Failed verification means the message is quarantined — never processed.
    """

    # Message replay window — messages older than this are rejected (seconds)
    REPLAY_WINDOW_SECONDS = 300  # 5 minutes

    def __init__(self):
        # In production, keys are stored in a secrets manager — never hardcoded
        self.agent_keys: Dict[str, bytes] = {}
        self.processed_message_ids: set = set()
        self.quarantined_messages: List[MessageVerificationResult] = []
        self.verified_messages: List[str] = []

    def register_agent(self, agent_id: str, shared_secret: Optional[str] = None) -> str:
        """Register an agent with a signing key. Returns the key for distribution."""
        if shared_secret:
            key = shared_secret.encode()
        else:
            key = secrets.token_bytes(32)
        self.agent_keys[agent_id] = key
        print(f"[GS-09] Agent registered: {agent_id}")
        return key.hex()

    def _compute_signature(self, message: AgentMessage, key: bytes) -> str:
        """Compute HMAC-SHA256 signature over canonical message content."""
        canonical = json.dumps(
            {
                "message_id": message.message_id,
                "sender_agent_id": message.sender_agent_id,
                "receiver_agent_id": message.receiver_agent_id,
                "control_id": message.control_id,
                "assessment": message.assessment,
                "evidence_source": message.evidence_source,
                "timestamp": message.timestamp,
            },
            sort_keys=True,
        )
        return hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()

    def sign_message(self, message: AgentMessage) -> AgentMessage:
        """Sign an outbound message using the sender agent's key."""
        key = self.agent_keys.get(message.sender_agent_id)
        if not key:
            raise ValueError(f"Unknown sender agent: {message.sender_agent_id}")
        message.signature = self._compute_signature(message, key)
        return message

    def verify_message(self, message: AgentMessage) -> MessageVerificationResult:
        """
        Verify an inbound message before the receiving agent processes it.
        Returns VERIFIED or a specific failure verdict.
        """
        verification_timestamp = datetime.utcnow().isoformat() + "Z"

        # Check 1: Is the sender known?
        key = self.agent_keys.get(message.sender_agent_id)
        if not key:
            verdict = MessageVerdict.FAILED_UNKNOWN_SENDER
            reason = f"Sender '{message.sender_agent_id}' is not a registered agent."
            return self._build_result(message, verdict, False, False, reason, verification_timestamp)

        # Check 2: Replay detection — has this message ID been processed before?
        if message.message_id in self.processed_message_ids:
            verdict = MessageVerdict.FAILED_REPLAY
            reason = f"Message ID '{message.message_id}' has already been processed. Replay attack detected."
            return self._build_result(message, verdict, False, True, reason, verification_timestamp)

        # Check 3: Timestamp freshness
        try:
            msg_time = datetime.fromisoformat(message.timestamp.replace("Z", "+00:00"))
            age_seconds = (datetime.now(msg_time.tzinfo) - msg_time).total_seconds()
            if age_seconds > self.REPLAY_WINDOW_SECONDS:
                verdict = MessageVerdict.FAILED_REPLAY
                reason = f"Message timestamp is {age_seconds:.0f}s old — outside replay window of {self.REPLAY_WINDOW_SECONDS}s."
                return self._build_result(message, verdict, False, True, reason, verification_timestamp)
        except Exception:
            pass  # Malformed timestamp — still proceed to signature check

        # Check 4: HMAC signature verification
        if not message.signature:
            verdict = MessageVerdict.FAILED_SIGNATURE
            reason = "Message has no signature. All inter-agent messages must be HMAC-signed."
            return self._build_result(message, verdict, False, False, reason, verification_timestamp)

        expected_signature = self._compute_signature(message, key)
        signature_valid = hmac.compare_digest(message.signature, expected_signature)

        if not signature_valid:
            verdict = MessageVerdict.FAILED_SIGNATURE
            reason = (
                f"HMAC signature verification FAILED for message from '{message.sender_agent_id}'. "
                f"Message may have been tampered with or spoofed."
            )
            return self._build_result(message, verdict, False, False, reason, verification_timestamp)

        # All checks passed
        self.processed_message_ids.add(message.message_id)
        self.verified_messages.append(message.message_id)
        verdict = MessageVerdict.VERIFIED
        reason = f"Message from '{message.sender_agent_id}' verified successfully."
        return self._build_result(message, verdict, True, False, reason, verification_timestamp)

    def _build_result(
        self, message, verdict, sig_valid, replay, reason, ts
    ) -> MessageVerificationResult:
        state = json.dumps(
            {"message_id": message.message_id, "verdict": verdict.value, "ts": ts},
            sort_keys=True,
        )
        verification_hash = hashlib.sha256(state.encode()).hexdigest()

        result = MessageVerificationResult(
            verdict=verdict,
            message_id=message.message_id,
            sender_agent_id=message.sender_agent_id,
            receiver_agent_id=message.receiver_agent_id,
            control_id=message.control_id,
            assessment=message.assessment,
            signature_valid=sig_valid,
            replay_detected=replay,
            reason=reason,
            verification_timestamp=ts,
            verification_hash=verification_hash,
        )

        if verdict != MessageVerdict.VERIFIED:
            self.quarantined_messages.append(result)
            print(f"\n[GS-09] ⛔ {verdict.value} — Message {message.message_id[:8]}...")
            print(f"  From: {message.sender_agent_id} | Control: {message.control_id}")
            print(f"  Reason: {reason}")
        else:
            print(f"[GS-09] ✅ VERIFIED — {message.message_id[:8]}... from {message.sender_agent_id}")

        return result


# ── Demonstration ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("GS-09 Inter-Agent Message Auth — ASI07 Detection Demo")
    print("Scenario: Attacker injects spoofed COMPLIANT message into pipeline")
    print("=" * 70)

    auth = InterAgentMessageAuth()
    auth.register_agent("evidence-collector-001")
    auth.register_agent("risk-scorer-001")

    print("\n[STEP 1] Legitimate message from evidence collector — NON_COMPLIANT")
    legitimate_msg = AgentMessage(
        message_id="msg-" + secrets.token_hex(8),
        sender_agent_id="evidence-collector-001",
        receiver_agent_id="risk-scorer-001",
        control_id="CC-6.1",
        assessment="NON_COMPLIANT",
        evidence_source="vendor_upload_2847",
        timestamp=datetime.utcnow().isoformat() + "Z",
    )
    auth.sign_message(legitimate_msg)
    r1 = auth.verify_message(legitimate_msg)
    print(f"  → {r1.verdict.value} | Assessment will be processed: {r1.assessment}")

    print("\n[STEP 2] Attacker injects spoofed message — COMPLIANT (no valid signature)")
    spoofed_msg = AgentMessage(
        message_id="msg-" + secrets.token_hex(8),
        sender_agent_id="evidence-collector-001",
        receiver_agent_id="risk-scorer-001",
        control_id="CC-6.1",
        assessment="COMPLIANT",
        evidence_source="vendor_upload_2847",
        timestamp=datetime.utcnow().isoformat() + "Z",
        signature="deadbeef" * 8,  # Fake signature
    )
    r2 = auth.verify_message(spoofed_msg)
    print(f"  → {r2.verdict.value}")

    print("\n" + "=" * 70)
    print(f"Verified messages: {len(auth.verified_messages)}")
    print(f"Quarantined messages: {len(auth.quarantined_messages)}")
    print("✅ GS-09 quarantined the spoofed message.")
    print("   Risk scorer receives NON_COMPLIANT — the correct legitimate finding.")
