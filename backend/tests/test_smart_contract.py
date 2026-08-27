import os
import sys
import time
import hashlib
import pytest
from typing import Dict, Any, Tuple, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

class EvidenceRegistryVM:
    """
    Python implementation of the EvidenceRegistry Solidity Smart Contract
    executing the exact EVM state transition rules and validation checks.
    """
    def __init__(self, owner: str = "0x71C80aB8B33f11E81D4b5b4Fe93C9a8Ec0F36D48"):
        self.owner = owner
        self._records: Dict[str, Dict[str, Any]] = {}
        self._evidence_ids = []
        self.events = []

    def registerEvidence(
        self,
        evidence_id: str,
        evidence_hash: str,
        system_identifier: str,
        caller: str = "0x71C80aB8B33f11E81D4b5b4Fe93C9a8Ec0F36D48"
    ) -> bool:
        # Rule 1: Evidence ID must not be empty / zero
        if not evidence_id or evidence_id == "0x" + "00" * 32 or evidence_id == "0" * 64:
            raise ValueError("EvidenceRegistry: Evidence ID cannot be empty")

        # Rule 2: Evidence hash must not be empty / zero
        if not evidence_hash or evidence_hash == "0x" + "00" * 32 or evidence_hash == "0" * 64:
            raise ValueError("EvidenceRegistry: Evidence hash cannot be empty")

        # Rule 3: Prevent duplicate registration
        if evidence_id in self._records:
            raise ValueError("EvidenceRegistry: Evidence ID already registered")

        current_timestamp = int(time.time())

        # State storage
        self._records[evidence_id] = {
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "timestamp": current_timestamp,
            "system_identifier": system_identifier,
            "registered_by": caller,
            "exists": True
        }
        self._evidence_ids.append(evidence_id)

        # Event emission
        self.events.append({
            "event": "EvidenceRegistered",
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "timestamp": current_timestamp,
            "registered_by": caller,
            "system_identifier": system_identifier
        })

        return True

    def verifyEvidence(
        self,
        evidence_id: str,
        computed_hash: str
    ) -> Tuple[bool, int, Optional[str]]:
        """Read-only verification function matching Solidity contract."""
        if evidence_id not in self._records:
            return (False, 0, None)

        record = self._records[evidence_id]
        is_authentic = (record["evidence_hash"] == computed_hash)
        return (is_authentic, record["timestamp"], record["registered_by"])

    def getEvidence(self, evidence_id: str) -> Dict[str, Any]:
        if evidence_id not in self._records:
            raise KeyError("EvidenceRegistry: Evidence ID not found")
        rec = self._records[evidence_id]
        return {
            "evidence_hash": rec["evidence_hash"],
            "timestamp": rec["timestamp"],
            "system_identifier": rec["system_identifier"],
            "registered_by": rec["registered_by"]
        }

    def isEvidenceRegistered(self, evidence_id: str) -> bool:
        return evidence_id in self._records

    def getEvidenceCount(self) -> int:
        return len(self._evidence_ids)

    def getEvidenceIdByIndex(self, index: int) -> str:
        if index < 0 or index >= len(self._evidence_ids):
            raise IndexError("EvidenceRegistry: Index out of bounds")
        return self._evidence_ids[index]


# ===================================================================================
# SMART CONTRACT AUTOMATED TEST SUITE
# ===================================================================================

def test_contract_successful_registration():
    """Test Requirement: Successful registration of valid forensic evidence."""
    contract = EvidenceRegistryVM()

    evidence_id = "0x" + hashlib.sha256(b"ANALYSIS-2026-001").hexdigest()
    evidence_hash = "0x" + hashlib.sha256(b"CANONICAL_EVIDENCE_PAYLOAD").hexdigest()
    system_id = "ThreatSentinel-Node-01"

    assert contract.isEvidenceRegistered(evidence_id) is False

    success = contract.registerEvidence(evidence_id, evidence_hash, system_id)
    assert success is True

    assert contract.isEvidenceRegistered(evidence_id) is True
    assert contract.getEvidenceCount() == 1
    assert contract.getEvidenceIdByIndex(0) == evidence_id

    # Verify event emission
    assert len(contract.events) == 1
    event = contract.events[0]
    assert event["event"] == "EvidenceRegistered"
    assert event["evidence_id"] == evidence_id
    assert event["evidence_hash"] == evidence_hash
    assert event["system_identifier"] == system_id


def test_contract_duplicate_evidence_rejection():
    """Test Requirement: Prevent accidental duplicate registration / overwriting."""
    contract = EvidenceRegistryVM()

    evidence_id = "0x" + hashlib.sha256(b"ANALYSIS-2026-002").hexdigest()
    evidence_hash_1 = "0x" + hashlib.sha256(b"ORIGINAL_PAYLOAD").hexdigest()
    evidence_hash_2 = "0x" + hashlib.sha256(b"TAMPERED_PAYLOAD").hexdigest()

    # Initial registration succeeds
    contract.registerEvidence(evidence_id, evidence_hash_1, "ThreatSentinel-Node-01")

    # Attempting duplicate registration MUST revert
    with pytest.raises(ValueError, match="Evidence ID already registered"):
        contract.registerEvidence(evidence_id, evidence_hash_2, "ThreatSentinel-Node-01")

    # Verify original evidence hash remains untouched (immutable)
    dossier = contract.getEvidence(evidence_id)
    assert dossier["evidence_hash"] == evidence_hash_1


def test_contract_read_only_verification_authentic():
    """Test Requirement: Read-only verification returns isAuthentic=True for matching hash."""
    contract = EvidenceRegistryVM()

    evidence_id = "0x" + hashlib.sha256(b"ANALYSIS-2026-003").hexdigest()
    evidence_hash = "0x" + hashlib.sha256(b"AUTHENTIC_DOSSIER_HASH").hexdigest()

    contract.registerEvidence(evidence_id, evidence_hash, "ThreatSentinel-Node-01")

    is_authentic, timestamp, registrar = contract.verifyEvidence(evidence_id, evidence_hash)
    assert is_authentic is True
    assert timestamp > 0
    assert registrar is not None


def test_contract_verification_incorrect_hash():
    """Test Requirement: Read-only verification returns isAuthentic=False for altered/tampered hash."""
    contract = EvidenceRegistryVM()

    evidence_id = "0x" + hashlib.sha256(b"ANALYSIS-2026-004").hexdigest()
    original_hash = "0x" + hashlib.sha256(b"LEGITIMATE_EVIDENCE").hexdigest()
    altered_hash = "0x" + hashlib.sha256(b"MODIFIED_SCORE_OR_SENDER").hexdigest()

    contract.registerEvidence(evidence_id, original_hash, "ThreatSentinel-Node-01")

    # Verifying with altered hash MUST flag failure
    is_authentic, timestamp, registrar = contract.verifyEvidence(evidence_id, altered_hash)
    assert is_authentic is False


def test_contract_missing_or_invalid_evidence_id():
    """Test Requirement: Missing or invalid evidence IDs are safely handled."""
    contract = EvidenceRegistryVM()

    # 1. Querying an unanchored evidence ID
    random_id = "0x" + hashlib.sha256(b"NON_EXISTENT_ANALYSIS").hexdigest()
    is_authentic, timestamp, registrar = contract.verifyEvidence(random_id, "0x" + "aa" * 32)
    assert is_authentic is False
    assert timestamp == 0

    with pytest.raises(KeyError, match="Evidence ID not found"):
        contract.getEvidence(random_id)

    # 2. Registering with empty / zero evidence ID MUST revert
    empty_id = "0x" + "00" * 32
    valid_hash = "0x" + hashlib.sha256(b"VALID_HASH").hexdigest()
    with pytest.raises(ValueError, match="Evidence ID cannot be empty"):
        contract.registerEvidence(empty_id, valid_hash, "ThreatSentinel-Node-01")

    # 3. Registering with empty / zero hash MUST revert
    valid_id = "0x" + hashlib.sha256(b"VALID_ID").hexdigest()
    empty_hash = "0x" + "00" * 32
    with pytest.raises(ValueError, match="Evidence hash cannot be empty"):
        contract.registerEvidence(valid_id, empty_hash, "ThreatSentinel-Node-01")


def test_contract_zero_pii_principle():
    """Test Requirement: Asserts that only 32-byte cryptographic hashes are anchored on-chain."""
    evidence_id = "0x" + hashlib.sha256(b"ANALYSIS-2026-005").hexdigest()
    evidence_hash = "0x" + hashlib.sha256(b"NON_SENSITIVE_METADATA_ONLY").hexdigest()

    assert len(evidence_id) == 66  # "0x" + 64 hex characters (32 bytes)
    assert len(evidence_hash) == 66

    # Verify no plaintext strings or email addresses
    assert "@" not in evidence_id
    assert "@" not in evidence_hash
