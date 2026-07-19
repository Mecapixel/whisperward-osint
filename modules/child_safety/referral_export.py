"""
WhisperWard OSINT — Structured Referral Export
Phase 4, Milestone 5
Pixora Inc.

This module assembles a case into a structured referral export whose fields are
aligned with the publicly described structure of a CyberTipline style report. It
is honest about what it is. It is a representative format, not an actual
CyberTipline submission. A real submission requires credentials issued to a
registered reporting entity, which this project does not have, so the export is
designed to map cleanly onto such a submission rather than to be one. The output
documents this plainly so no reviewer is misled.

The export is redacted by default. A referral is meant to leave the analyst's
hands, whether to a tip line, a partner, or a reviewer, and the safe posture for
anything shareable is that personal information is masked unless an internal full
detail copy is explicitly requested. Passing redact set to false produces the
unredacted internal view, which a reader can see is internal because the export
records its own redaction status.

When redaction is applied the export runs through the redaction engine, so the
same pattern based and analyst tagged masking that governs the rest of the system
governs the referral too, and the redaction is logged through that engine. The
export itself additionally appends a referral_exported entry to the tamper
evident chain of custody log.

The referral structure groups information the way a tip line report does. It
carries a reporting section describing the submitting context, an incident section
summarizing the concern and the platform, a subject section describing the
reported account, a supporting evidence section listing the artifacts by type with
their hashes, and a provenance section tying the referral to the case and to the
sealed evidence package when one exists.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from core.case_log import ChainOfCustodyLog
    _CASE_LOG_AVAILABLE = True
except Exception:
    try:
        from case_log import ChainOfCustodyLog
        _CASE_LOG_AVAILABLE = True
    except Exception:
        ChainOfCustodyLog = None
        _CASE_LOG_AVAILABLE = False

try:
    from core.redaction_engine import redact_case
    _REDACTION_AVAILABLE = True
except Exception:
    try:
        from redaction_engine import redact_case
        _REDACTION_AVAILABLE = True
    except Exception:
        redact_case = None
        _REDACTION_AVAILABLE = False


REFERRAL_FORMAT_VERSION = "1.0"

REPRESENTATIVE_NOTICE = (
    "This is a representative referral export. Its fields are aligned with the "
    "publicly described structure of a CyberTipline style report, but it is not an "
    "actual CyberTipline submission. A real submission requires credentials issued "
    "to a registered reporting entity. This export is designed to map onto such a "
    "submission and to support a qualified human in preparing one.")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _has_column(cur, table, column) -> bool:
    try:
        cols = {r[1] for r in cur.execute("PRAGMA table_info(" + table + ")")}
        return column in cols
    except sqlite3.Error:
        return False


def _read_package_reference(export_dir: str, case_id: str) -> dict:
    """Returns a reference to the sealed evidence package if one exists, reading
    the real manifest hash from its seal. Empty when no package exists, so the
    referral never claims a package that was not made."""
    pkg = Path(export_dir) / (case_id + "_evidence_package.zip")
    if not pkg.is_file():
        return {}
    try:
        with zipfile.ZipFile(pkg) as archive:
            seal_name = next((n for n in archive.namelist()
                              if n.endswith("_manifest.seal.json")), None)
            if seal_name is None:
                return {}
            seal = json.loads(archive.read(seal_name))
        return {
            "package_file": pkg.name,
            "manifest_sha256": seal.get("manifest_sha256", ""),
            "sealed_at": seal.get("sealed_at", ""),
        }
    except Exception:
        return {}


def _build_referral_structure(connection: sqlite3.Connection, case_id: str,
                              export_dir: str, referral_id: str) -> dict:
    """Assembles the case into the referral structure from real database content."""
    connection.row_factory = sqlite3.Row
    cur = connection.cursor()

    case = cur.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    case = dict(case) if case else {"case_id": case_id}

    targets = cur.execute(
        "SELECT * FROM targets WHERE case_id = ? ORDER BY target_id ASC", (case_id,)
    ).fetchall()

    subjects = []
    evidence_items = []
    highest_score = None
    for target in targets:
        analysis = cur.execute(
            "SELECT analysis_type, risk_score, analyst_notes, analyzed_at "
            "FROM analysis_results WHERE target_id = ? "
            "ORDER BY analyzed_at DESC LIMIT 1", (target["target_id"],)
        ).fetchone()
        score = analysis["risk_score"] if analysis else None
        if score is not None and (highest_score is None or score > highest_score):
            highest_score = score
        subjects.append({
            "platform": target["platform"],
            "reported_username": target["username"],
            "platform_user_id": target["platform_user_id"]
                if "platform_user_id" in target.keys() else None,
            "risk_score": score,
            "assessment_type": analysis["analysis_type"] if analysis else None,
        })

        has_collected = _has_column(cur, "artifacts", "collected_at")
        if has_collected:
            arts = cur.execute(
                "SELECT module_name, artifact_type, sha256, collected_at "
                "FROM artifacts WHERE target_id = ? ORDER BY artifact_id ASC",
                (target["target_id"],)
            ).fetchall()
        else:
            arts = cur.execute(
                "SELECT module_name, artifact_type, sha256 FROM artifacts "
                "WHERE target_id = ? ORDER BY artifact_id ASC",
                (target["target_id"],)
            ).fetchall()
        for art in arts:
            item = {
                "collected_by_module": art["module_name"],
                "artifact_type": art["artifact_type"],
                "sha256": art["sha256"],
            }
            if has_collected:
                item["collected_at"] = art["collected_at"]
            evidence_items.append(item)

    package_ref = _read_package_reference(export_dir, case_id)

    referral = {
        "referral_id": referral_id,
        "format_version": REFERRAL_FORMAT_VERSION,
        "generated_at": _utc_now_iso(),
        "representative_notice": REPRESENTATIVE_NOTICE,
        "reporting": {
            "reporting_tool": "WhisperWard OSINT",
            "reporting_context": "Open source intelligence lead for human review.",
            "case_id": case_id,
            "case_name": case.get("case_name"),
            "analyst": case.get("analyst_name"),
        },
        "incident": {
            "concern_summary": case.get("description"),
            "opened_at": case.get("created_at"),
            "status": case.get("status"),
            "highest_risk_score": highest_score,
        },
        "subjects": subjects,
        "supporting_evidence": {
            "artifact_count": len(evidence_items),
            "artifacts": evidence_items,
        },
        "provenance": {
            "sealed_evidence_package": package_ref if package_ref else
                "No sealed evidence package was found for this case.",
            "note": ("The authoritative unredacted record is the sealed evidence "
                     "package. This referral is a derived view for sharing."),
        },
    }
    return referral


def export_referral(case_id: str, analyst: Optional[str] = None,
                    redact: bool = True,
                    policy: str = "standard",
                    reason: str = "referral",
                    db_path: Optional[str] = None,
                    connection: Optional[sqlite3.Connection] = None,
                    output_dir: str = "exports",
                    write_file: bool = True) -> Optional[dict]:
    """Builds a structured referral export and returns a result dictionary. The
    export is redacted by default, which is the safe posture for a shareable
    artifact. Pass redact set to false for an internal full detail copy. When
    redaction is applied the referral content is masked by the redaction engine.
    A referral_exported entry is appended to the chain of custody log.

    The returned dictionary includes the referral data, whether it was redacted,
    any redaction counts, and the output path when a file was written."""

    own_connection = False
    conn = connection
    if conn is None and db_path is not None:
        conn = sqlite3.connect(db_path)
        own_connection = True
    if conn is None:
        print("A database connection or db_path is required to export a referral.")
        return None

    referral_id = "REF-" + uuid.uuid4().hex[:12].upper()

    try:
        referral = _build_referral_structure(conn, case_id, output_dir, referral_id)

        redaction_summary = None
        if redact:
            if not _REDACTION_AVAILABLE:
                if own_connection and conn is not None:
                    conn.close()
                print("Redaction was requested but the redaction engine is not "
                      "available, so a redacted referral cannot be produced. To "
                      "export the unredacted internal view deliberately, pass "
                      "redact set to false.")
                return None
            # Redact the assembled referral structure using the engine's value
            # walker, so the same masking that governs case redaction governs the
            # referral and the two stay consistent.
            referral, redaction_summary = _redact_referral(conn, case_id, referral, policy)

        referral["redaction"] = {
            "redacted": bool(redact),
            "policy": policy if redact else None,
            "reason": reason if redact else None,
            "summary": redaction_summary,
            "note": ("Redacted referrals mask structurally identifiable PII and "
                     "analyst tagged protected values. The unredacted original "
                     "remains in the sealed evidence package."
                     if redact else
                     "This is an unredacted internal view. Do not share externally "
                     "without redacting."),
        }
    except Exception as exc:
        if own_connection and conn is not None:
            conn.close()
        print("Error building referral export: " + str(exc))
        return None

    output_path = None
    if write_file:
        try:
            out_dir = Path(output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            suffix = "_referral_redacted.json" if redact else "_referral_internal.json"
            output_path = str(out_dir / (case_id + suffix))
            with open(output_path, "w", encoding="utf-8") as handle:
                json.dump(referral, handle, indent=2, sort_keys=True)
        except Exception as exc:
            if own_connection and conn is not None:
                conn.close()
            print("Referral built but writing the file failed: " + str(exc))
            return None

    if _CASE_LOG_AVAILABLE:
        try:
            log = ChainOfCustodyLog(connection=conn)
            log.append(
                action="referral_exported",
                case_id=case_id,
                analyst=analyst,
                notes=("Structured referral " + referral_id + " exported. Redacted "
                       + ("yes" if redact else "no") + ", format version "
                       + REFERRAL_FORMAT_VERSION + "."),
            )
        except Exception as exc:
            print("Warning, referral exported but the chain entry could not be "
                  "written: " + str(exc))

    if own_connection and conn is not None:
        conn.close()

    return {
        "case_id": case_id,
        "referral_id": referral_id,
        "redacted": bool(redact),
        "redaction_summary": redaction_summary,
        "output_path": output_path,
        "data": referral,
    }


def _redact_referral(connection: sqlite3.Connection, case_id: str,
                     referral: dict, policy: str):
    """Masks the assembled referral structure using the redaction engine's value
    walker and the same protected tags gathered for the case. Returns the redacted
    referral and a counts summary. This reuses the engine's logic rather than
    duplicating regex, so the referral and the case redaction stay consistent. The
    import uses the same relative then flat pattern as the rest of the module so it
    works however the package is run."""
    try:
        from core.redaction_engine import (_redact_value, RedactionResult, POLICIES,
                                        _gather_protected_values)
    except Exception:
        from redaction_engine import (_redact_value, RedactionResult, POLICIES,
                                       _gather_protected_values)
    if policy not in POLICIES:
        policy = "standard"
    policy_def = POLICIES[policy]
    protected_values = _gather_protected_values(connection, case_id)
    result = RedactionResult()
    redacted = _redact_value(referral, policy_def, protected_values, result)
    return redacted, result.summary()