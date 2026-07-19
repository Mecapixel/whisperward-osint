"""
structured_logger.py
WhisperWard OSINT — Immutable Structured Logging
Pixora Inc. | Phase 4 Milestone 1
"""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog

# ─────────────────────────────────────────────
# Log directory setup
# ─────────────────────────────────────────────
LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "whisperward.log"


def _add_utc_timestamp(logger, method_name, event_dict):
    """Add UTC ISO timestamp to every log entry."""
    event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    return event_dict


def _add_log_level(logger, method_name, event_dict):
    """Add uppercase log level to every entry."""
    event_dict["level"] = method_name.upper()
    return event_dict


def configure_logging(
    log_level: str = "INFO",
    json_output: bool = False,
    log_to_file: bool = True,
):
    """Configure structlog for the entire application."""
    level = getattr(logging, log_level.upper(), logging.INFO)

    handlers = [logging.StreamHandler(sys.stdout)]
    if log_to_file:
        handlers.append(logging.FileHandler(str(LOG_FILE), mode="a", encoding="utf-8"))

    logging.basicConfig(
        format="%(message)s",
        level=level,
        handlers=handlers,
        force=True,
    )

    shared_processors = [
        _add_utc_timestamp,
        _add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.add_log_level,
    ]

    if json_output:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    structlog.configure(
        processors=shared_processors + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str):
    """Return a named structured logger."""
    return structlog.get_logger(name)


# ─────────────────────────────────────────────
# Case-level audit logger (immutable chain-of-custody)
# ─────────────────────────────────────────────
class CaseAuditLogger:
    """
    Specialized logger for case actions.
    All entries are append-only and include case_id + analyst for traceability.
    """
    def __init__(self, case_id: str, analyst: str = "system"):
        self.case_id = case_id
        self.analyst = analyst
        self._logger = get_logger("case_audit")

    def log_scan_started(self, username: str, platform: str):
        self._logger.info("scan_started", case_id=self.case_id, analyst=self.analyst,
                         username=username, platform=platform)

    def log_artifact_collected(self, target_id: int, module_name: str, artifact_type: str, sha256: str):
        # Truncate SHA256 in logs for readability/security
        short_sha = sha256[:16] + "..." if len(sha256) > 16 else sha256
        self._logger.info("artifact_collected", case_id=self.case_id, analyst=self.analyst,
                         target_id=target_id, module_name=module_name,
                         artifact_type=artifact_type, sha256=short_sha)

    def log_analysis_completed(self, target_id: int, risk_score: float, tier: int):
        self._logger.info("analysis_completed", case_id=self.case_id, analyst=self.analyst,
                         target_id=target_id, risk_score=risk_score, tier=tier)

    def log_tier2_alert(self, target_id: int, risk_score: float):
        self._logger.warning("tier2_alert", case_id=self.case_id, analyst=self.analyst,
                            target_id=target_id, risk_score=risk_score)

    def log_tier3_escalation(self, target_id: int, risk_score: float):
        self._logger.warning("tier3_escalation", case_id=self.case_id, analyst=self.analyst,
                            target_id=target_id, risk_score=risk_score)

    def log_evidence_package_created(self, package_path: str, sha256: str):
        short_sha = sha256[:16] + "..." if len(sha256) > 16 else sha256
        self._logger.info("evidence_package_created", case_id=self.case_id, analyst=self.analyst,
                         package_path=package_path, sha256=short_sha)

    def log_case_purged(self, reason: str):
        self._logger.info("case_purged", case_id=self.case_id, analyst=self.analyst, reason=reason)

    def log_reviewer_action(self, action: str, operator_id: str, notes: str = ""):
        self._logger.info("reviewer_action", case_id=self.case_id, analyst=self.analyst,
                         operator_id=operator_id, action=action, notes=notes)