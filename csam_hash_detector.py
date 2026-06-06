"""
csam_hash_detector.py
WhisperWard OSINT — CSAM Hash Detection Module
Pixora Inc. | Phase 4 Milestone 7

Architecture overview:
    This module provides three layers of hash detection:
        1. Local perceptual hash matching via imagehash (always available)
        2. PhotoDNA Cloud Service adapter (approval-gated, disabled by default)
        3. NCMEC hash list adapter (approval-gated, disabled by default)

CRITICAL CONSTRAINTS (non-negotiable, enforced in code):
    - No matched image content is ever stored. Hash value, result, source, and
      timestamp only. Image content is never written to disk, database, or log.
    - Human reviewer approval is required before any hash match result triggers
      a CyberTipline submission. This module produces a match_result only.
      Downstream escalation requires explicit human sign-off.
    - Synthetic images used for all testing. No real CSAM ever used in testing.

Registration status as of June 2026:
    PhotoDNA: pending Microsoft Trust & Safety organizational review
              Registration path: microsoft.com/en-us/photodna
    NCMEC:    outreach sent to techcoalition@ncmec.org — response pending
              Approval typically takes 2-4 weeks

Dependencies:
    imagehash >= 4.3.1  (local perceptual hashing — always active)
    Pillow >= 10.0.0    (image loading)
    requests            (API calls when adapters are enabled)
    python-dotenv       (API key management)

Usage:
    detector = CSAMHashDetector()
    result = detector.check_image("path/to/image.jpg")
    result = detector.check_image_url("https://example.com/avatar.png")
"""

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import imagehash
import requests
from dotenv import load_dotenv
from PIL import Image

load_dotenv()


# ─────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────

class MatchResult(Enum):
    NO_MATCH = "no_match"
    HASH_MATCH_LOCAL = "hash_match_local"
    HASH_MATCH_PHOTODNA = "hash_match_photodna"
    HASH_MATCH_NCMEC = "hash_match_ncmec"
    ERROR = "error"
    ADAPTER_DISABLED = "adapter_disabled"


@dataclass
class HashCheckResult:
    """
    Result object returned by CSAMHashDetector.check_image().
    Only hash values and metadata are stored — never image content.
    """
    match_result: MatchResult
    perceptual_hash: str              # imagehash value of the input image
    sha256_hash: str                  # SHA-256 of raw image bytes (chain of custody)
    database_source: Optional[str]    # "local" | "photodna" | "ncmec" | None
    confidence: float                 # 0.0 – 1.0
    flagged_at: str                   # UTC ISO 8601 timestamp
    requires_human_review: bool       # Always True on any match result
    error_message: Optional[str]      # Populated only on MatchResult.ERROR

    def to_dict(self) -> dict:
        return {
            "match_result": self.match_result.value,
            "perceptual_hash": self.perceptual_hash,
            "sha256_hash": self.sha256_hash,
            "database_source": self.database_source,
            "confidence": self.confidence,
            "flagged_at": self.flagged_at,
            "requires_human_review": self.requires_human_review,
            "error_message": self.error_message,
        }


# ─────────────────────────────────────────────
# Local hash database (synthetic test set)
# ─────────────────────────────────────────────

class LocalHashDatabase:
    """
    Local perceptual hash database for development and testing.
    Populated with synthetic test hashes only — never real CSAM hashes.
    In production, this would be supplemented by approved external sources.

    To add a test hash:
        db = LocalHashDatabase()
        db.add_test_hash("abcdef123456", "synthetic_test_case_001")
    """

    def __init__(self):
        self._hashes: dict[str, str] = {}
        self._load_synthetic_test_hashes()

    def _load_synthetic_test_hashes(self):
        """
        Load synthetic test hashes from environment or test fixture file.
        These are fabricated hash values for testing the detection pipeline only.
        Format: WHISPERWARD_TEST_HASH_1=<hash_value>
        """
        for key, value in os.environ.items():
            if key.startswith("WHISPERWARD_TEST_HASH_"):
                label = key.replace("WHISPERWARD_TEST_HASH_", "synthetic_")
                self._hashes[value] = label

    def add_test_hash(self, hash_value: str, label: str):
        """Add a synthetic test hash for development purposes."""
        self._hashes[hash_value] = label

    def check(self, perceptual_hash: str, threshold: int = 10) -> tuple[bool, float]:
        """
        Check a perceptual hash against the local database.
        Uses Hamming distance — lower distance = higher similarity.
        threshold: maximum Hamming distance to consider a match (default 10)

        Returns: (is_match, confidence_score)
        """
        if not self._hashes:
            return False, 0.0

        query_hash = imagehash.hex_to_hash(perceptual_hash)

        for stored_hash_str in self._hashes:
            try:
                stored_hash = imagehash.hex_to_hash(stored_hash_str)
                distance = query_hash - stored_hash
                if distance <= threshold:
                    confidence = 1.0 - (distance / 64.0)
                    return True, round(confidence, 3)
            except Exception:
                continue

        return False, 0.0


# ─────────────────────────────────────────────
# PhotoDNA adapter stub
# ─────────────────────────────────────────────

class PhotoDNAAdapter:
    """
    Adapter stub for Microsoft PhotoDNA Cloud Service.

    STATUS: APPROVAL PENDING — DISABLED BY DEFAULT
    Registration path: microsoft.com/en-us/photodna
    Contact: Microsoft Trust & Safety organizational review required

    When approved:
        1. Set PHOTODNA_API_KEY in .env
        2. Set PHOTODNA_ENABLED=true in .env
        3. Replace _call_api() stub with real implementation

    API reference (when access is granted):
        POST https://api.microsoftmoderator.com/photodna/v1.0/Match
        Headers: Ocp-Apim-Subscription-Key: <your_key>
        Body: multipart/form-data image upload

    CRITICAL: This adapter never stores image content.
    Only the match result and metadata are returned to the caller.
    """

    def __init__(self):
        self.enabled = os.getenv("PHOTODNA_ENABLED", "false").lower() == "true"
        self.api_key = os.getenv("PHOTODNA_API_KEY", "")
        self.api_endpoint = "https://api.microsoftmoderator.com/photodna/v1.0/Match"

    def is_available(self) -> bool:
        return self.enabled and bool(self.api_key)

    def check(self, image_bytes: bytes) -> tuple[MatchResult, float]:
        """
        Submit image to PhotoDNA for hash matching.
        Returns (MatchResult, confidence).
        Image bytes are submitted but never stored locally after this call.
        """
        if not self.is_available():
            return MatchResult.ADAPTER_DISABLED, 0.0

        # ── STUB ────────────────────────────────────────────────────────────
        # Replace this block with real PhotoDNA API call when access is granted.
        #
        # result = self._call_api(image_bytes)
        # if result["isMatch"]:
        #     return MatchResult.HASH_MATCH_PHOTODNA, result["matchConfidence"]
        # return MatchResult.NO_MATCH, 0.0
        # ─────────────────────────────────────────────────────────────────────

        raise NotImplementedError(
            "PhotoDNA adapter is approval-gated. "
            "Set PHOTODNA_ENABLED=true and PHOTODNA_API_KEY in .env after approval. "
            "Registration: microsoft.com/en-us/photodna"
        )

    def _call_api(self, image_bytes: bytes) -> dict:
        """
        Real PhotoDNA API call — implement after approval.
        Stub is left intentionally incomplete pending credential review.
        """
        headers = {
            "Ocp-Apim-Subscription-Key": self.api_key,
        }
        files = {"imgToMatch": ("image.jpg", image_bytes, "image/jpeg")}
        response = requests.post(self.api_endpoint, headers=headers, files=files, timeout=10)
        response.raise_for_status()
        return response.json()


# ─────────────────────────────────────────────
# NCMEC hash list adapter stub
# ─────────────────────────────────────────────

class NCMECAdapter:
    """
    Adapter stub for NCMEC hash list integration.

    STATUS: APPROVAL PENDING — DISABLED BY DEFAULT
    Contact: techcoalition@ncmec.org
    Outreach sent: June 2026 — awaiting response (typical 2-4 week review)

    NCMEC provides hash lists to approved technology partners and researchers.
    Approval requires organizational documentation and mission statement review.

    When approved:
        1. Set NCMEC_API_KEY in .env (or hash list file path)
        2. Set NCMEC_ENABLED=true in .env
        3. Replace _load_hash_list() and check() stubs with real implementation

    Integration options (determined after approval):
        Option A: API-based real-time lookup
        Option B: Offline hash list file synced on schedule

    CRITICAL: This adapter never stores image content.
    Only the hash value, match result, and UTC timestamp are returned.
    """

    def __init__(self):
        self.enabled = os.getenv("NCMEC_ENABLED", "false").lower() == "true"
        self.api_key = os.getenv("NCMEC_API_KEY", "")
        self._hash_list: set[str] = set()

        if self.enabled:
            self._load_hash_list()

    def is_available(self) -> bool:
        return self.enabled and bool(self.api_key)

    def _load_hash_list(self):
        """
        Load NCMEC hash list from approved source.
        Implementation depends on integration method approved by NCMEC.
        Stub left intentionally incomplete pending approval.
        """
        pass  # Replace with real implementation after NCMEC approval

    def check(self, perceptual_hash: str) -> tuple[MatchResult, float]:
        """
        Check a perceptual hash against the NCMEC hash list.
        Returns (MatchResult, confidence).
        """
        if not self.is_available():
            return MatchResult.ADAPTER_DISABLED, 0.0

        # ── STUB ────────────────────────────────────────────────────────────
        # Replace this block with real NCMEC hash list lookup after approval.
        #
        # if perceptual_hash in self._hash_list:
        #     return MatchResult.HASH_MATCH_NCMEC, 1.0
        # return MatchResult.NO_MATCH, 0.0
        # ─────────────────────────────────────────────────────────────────────

        raise NotImplementedError(
            "NCMEC adapter is approval-gated. "
            "Set NCMEC_ENABLED=true and NCMEC_API_KEY in .env after approval. "
            "Contact: techcoalition@ncmec.org"
        )


# ─────────────────────────────────────────────
# Main detector class
# ─────────────────────────────────────────────

class CSAMHashDetector:
    """
    Main CSAM hash detection interface for WhisperWard.

    Runs three-layer detection in order:
        1. Local perceptual hash database (always active)
        2. PhotoDNA Cloud Service (when enabled and approved)
        3. NCMEC hash list (when enabled and approved)

    Returns a HashCheckResult on every call.
    Never stores image content. Hash values and metadata only.
    All match results require human reviewer approval before any
    downstream escalation action is taken.
    """

    def __init__(self):
        self.local_db = LocalHashDatabase()
        self.photodna = PhotoDNAAdapter()
        self.ncmec = NCMECAdapter()

    def check_image(self, image_path: str) -> HashCheckResult:
        """
        Check a local image file against all available hash databases.
        image_path: path to image file on disk
        """
        try:
            path = Path(image_path)
            if not path.exists():
                return self._error_result(f"Image file not found: {image_path}")

            with open(path, "rb") as f:
                image_bytes = f.read()

            return self._run_detection(image_bytes)

        except Exception as e:
            return self._error_result(str(e))

    def check_image_url(self, url: str) -> HashCheckResult:
        """
        Download and check an image from a URL.
        Image bytes are processed in memory and never written to disk.
        url: public image URL (e.g. Roblox avatar URL)
        """
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            image_bytes = response.content
            return self._run_detection(image_bytes)

        except Exception as e:
            return self._error_result(str(e))

    def _run_detection(self, image_bytes: bytes) -> HashCheckResult:
        """
        Core detection pipeline. Runs all three layers in order.
        image_bytes are processed here and not retained after this call.
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        # Compute hashes from image bytes
        try:
            from io import BytesIO
            img = Image.open(BytesIO(image_bytes))
            phash = str(imagehash.phash(img))
        except Exception as e:
            return self._error_result(f"Failed to compute perceptual hash: {e}")

        sha256 = hashlib.sha256(image_bytes).hexdigest()

        # Layer 1 — Local perceptual hash database
        is_match, confidence = self.local_db.check(phash)
        if is_match:
            return HashCheckResult(
                match_result=MatchResult.HASH_MATCH_LOCAL,
                perceptual_hash=phash,
                sha256_hash=sha256,
                database_source="local",
                confidence=confidence,
                flagged_at=timestamp,
                requires_human_review=True,
                error_message=None,
            )

        # Layer 2 — PhotoDNA (approval-gated)
        if self.photodna.is_available():
            try:
                photodna_result, photodna_confidence = self.photodna.check(image_bytes)
                if photodna_result == MatchResult.HASH_MATCH_PHOTODNA:
                    return HashCheckResult(
                        match_result=photodna_result,
                        perceptual_hash=phash,
                        sha256_hash=sha256,
                        database_source="photodna",
                        confidence=photodna_confidence,
                        flagged_at=timestamp,
                        requires_human_review=True,
                        error_message=None,
                    )
            except Exception as e:
                # PhotoDNA failure is non-fatal — continue to next layer
                pass

        # Layer 3 — NCMEC hash list (approval-gated)
        if self.ncmec.is_available():
            try:
                ncmec_result, ncmec_confidence = self.ncmec.check(phash)
                if ncmec_result == MatchResult.HASH_MATCH_NCMEC:
                    return HashCheckResult(
                        match_result=ncmec_result,
                        perceptual_hash=phash,
                        sha256_hash=sha256,
                        database_source="ncmec",
                        confidence=ncmec_confidence,
                        flagged_at=timestamp,
                        requires_human_review=True,
                        error_message=None,
                    )
            except Exception as e:
                # NCMEC failure is non-fatal
                pass

        # No match across all available layers
        return HashCheckResult(
            match_result=MatchResult.NO_MATCH,
            perceptual_hash=phash,
            sha256_hash=sha256,
            database_source=None,
            confidence=0.0,
            flagged_at=timestamp,
            requires_human_review=False,
            error_message=None,
        )

    def _error_result(self, message: str) -> HashCheckResult:
        return HashCheckResult(
            match_result=MatchResult.ERROR,
            perceptual_hash="",
            sha256_hash="",
            database_source=None,
            confidence=0.0,
            flagged_at=datetime.now(timezone.utc).isoformat(),
            requires_human_review=False,
            error_message=message,
        )

    def get_adapter_status(self) -> dict:
        """
        Return current status of all detection adapters.
        Useful for the /metrics endpoint and operator dashboard.
        """
        return {
            "local_database": "active",
            "photodna": "enabled" if self.photodna.is_available() else "disabled (approval pending)",
            "ncmec": "enabled" if self.ncmec.is_available() else "disabled (approval pending)",
        }