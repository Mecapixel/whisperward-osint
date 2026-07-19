"""
test_structured_logger.py
WhisperWard OSINT — Structured Logger Tests
Pixora Inc. | Phase 4 Milestone 1
"""

import logging

import pytest
import structlog

from core.structured_logger import (
    CaseAuditLogger,
    configure_logging,
    get_logger,
)


class TestConfigureLogging:
    def test_configure_logging_runs_without_error(self):
        configure_logging(log_level="INFO", json_output=False, log_to_file=False)

    def test_configure_logging_json_mode(self):
        configure_logging(log_level="DEBUG", json_output=True, log_to_file=False)

    def test_configure_logging_sets_level(self):
        configure_logging(log_level="WARNING", log_to_file=False)
        assert logging.getLogger().level <= logging.WARNING


class TestGetLogger:
    def test_get_logger_returns_logger(self):
        configure_logging(log_to_file=False)
        logger = get_logger("test_module")
        assert logger is not None

    def test_logger_has_info_method(self):
        configure_logging(log_to_file=False)
        logger = get_logger("test_module")
        assert hasattr(logger, "info")

    def test_logger_info_does_not_raise(self):
        configure_logging(log_to_file=False)
        logger = get_logger("test_module")
        logger.info("test_event", case_id="CASE-TEST001", synthetic=True)

    def test_different_names_return_different_loggers(self):
        configure_logging(log_to_file=False)
        l1 = get_logger("module_a")
        l2 = get_logger("module_b")
        assert l1 is not l2


class TestCaseAuditLogger:
    def setup_method(self):
        configure_logging(log_to_file=False, json_output=False)

    def test_initializes_with_case_id(self):
        audit = CaseAuditLogger("CASE-TEST001", analyst="test_analyst")
        assert audit.case_id == "CASE-TEST001"
        assert audit.analyst == "test_analyst"

    def test_log_scan_started_does_not_raise(self):
        audit = CaseAuditLogger("CASE-TEST001")
        audit.log_scan_started("synthetic_user", "roblox")

    def test_log_artifact_collected_does_not_raise(self):
        audit = CaseAuditLogger("CASE-TEST001")
        audit.log_artifact_collected(
            target_id=1,
            module_name="RobloxOSINT",
            artifact_type="profile",
            sha256="a" * 64,
        )

    def test_log_analysis_completed_does_not_raise(self):
        audit = CaseAuditLogger("CASE-TEST001")
        audit.log_analysis_completed(target_id=1, risk_score=7.5, tier=3)

    def test_log_tier3_escalation_does_not_raise(self):
        audit = CaseAuditLogger("CASE-TEST001")
        audit.log_tier3_escalation(target_id=1, risk_score=8.5)

    def test_log_evidence_package_created_does_not_raise(self):
        audit = CaseAuditLogger("CASE-TEST001")
        audit.log_evidence_package_created(
            package_path="exports/CASE-TEST001.zip",
            sha256="b" * 64,
        )

    def test_log_case_purged_does_not_raise(self):
        audit = CaseAuditLogger("CASE-TEST001")
        audit.log_case_purged(reason="90_day_retention_expired")

    def test_sha256_truncated_in_log(self, capsys):
        configure_logging(log_to_file=False, json_output=False)
        audit = CaseAuditLogger("CASE-TEST001")
        full_sha = "abcdef1234567890" * 4
        audit.log_artifact_collected(1, "RobloxOSINT", "profile", full_sha)

        captured = capsys.readouterr()
        assert full_sha not in captured.out