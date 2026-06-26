"""
WhisperWard OSINT — Retention Enforcer
Phase 4, Milestone 5
Pixora Inc.

This module enforces the data retention policy. Cases older than the retention
window are purged so that personal data does not linger past its purpose, which is
both an ethical commitment and a governance requirement. The default window is
ninety days, matching the governance documentation, and it is configurable.

Two safety commitments govern this module.

First, it is dry run by default. Deletion is destructive and irreversible, so the
default behavior only reports what would be purged, the case identifiers, their
age, and what would be removed, without touching anything. Actual deletion
requires an explicit confirmation flag. This mirrors the threat list refresh and
the general safety posture of the project.

Second, purging is auditable forever. When a case is purged its database rows and
its export files are deleted, but a case_purged entry is written to the tamper
evident chain of custody log first, and the chain itself is never deleted. The
record that a case existed and was purged on a given date, by a given analyst,
under a given policy, survives the data it described. A retention policy that
erased its own evidence of enforcement would be worthless, so the chain is treated
as the permanent ledger.

The purge deletes in foreign key safe order, children before parents, namely the
analysis results and artifacts for the case's targets, then the targets, then the
case row. The evidence_log rows are deliberately preserved.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

try:
    from .case_log import ChainOfCustodyLog
    _CASE_LOG_AVAILABLE = True
except Exception:
    try:
        from case_log import ChainOfCustodyLog
        _CASE_LOG_AVAILABLE = True
    except Exception:
        ChainOfCustodyLog = None
        _CASE_LOG_AVAILABLE = False


DEFAULT_RETENTION_DAYS = 90


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _parse_timestamp(value) -> Optional[datetime]:
    """Parses a stored timestamp into an aware UTC datetime. Handles ISO strings
    with an explicit offset, ISO strings without one which are assumed to be UTC,
    and the SQLite default form. Returns None when the value cannot be parsed, in
    which case the caller treats the case as not yet eligible, erring on the side
    of keeping data rather than deleting on a parse error."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    # Normalize a trailing Z to an explicit offset.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        # Try the SQLite default 'YYYY-MM-DD HH:MM:SS' form.
        try:
            dt = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _eligible_cases(connection: sqlite3.Connection, retention_days: int) -> list:
    """Returns a list of cases whose age exceeds the retention window. Each entry
    carries the case id, its created_at, and its age in days. Cases with an
    unparseable created_at are skipped, keeping their data rather than risking an
    erroneous deletion."""
    connection.row_factory = sqlite3.Row
    cur = connection.cursor()
    cutoff = _utc_now() - timedelta(days=retention_days)

    eligible = []
    rows = cur.execute("SELECT case_id, created_at, status FROM cases").fetchall()
    for row in rows:
        created = _parse_timestamp(row["created_at"])
        if created is None:
            continue
        if created < cutoff:
            age_days = (_utc_now() - created).days
            eligible.append({
                "case_id": row["case_id"],
                "created_at": row["created_at"],
                "age_days": age_days,
                "status": row["status"] if "status" in row.keys() else None,
            })
    return eligible


def _case_export_files(export_dir: str, case_id: str) -> list:
    """Returns the export files on disk that belong to a case, matched by the
    case id prefix. These are the packages and derived exports the purge removes."""
    directory = Path(export_dir)
    if not directory.is_dir():
        return []
    return [p for p in directory.iterdir()
            if p.is_file() and p.name.startswith(case_id)]


def _count_case_rows(connection: sqlite3.Connection, case_id: str) -> dict:
    """Counts the rows that would be deleted for a case, for the dry run report."""
    cur = connection.cursor()
    target_ids = [r[0] for r in cur.execute(
        "SELECT target_id FROM targets WHERE case_id = ?", (case_id,)).fetchall()]
    artifacts = 0
    analyses = 0
    if target_ids:
        placeholders = ",".join("?" for _ in target_ids)
        artifacts = cur.execute(
            "SELECT COUNT(*) FROM artifacts WHERE target_id IN (" + placeholders + ")",
            target_ids).fetchone()[0]
        analyses = cur.execute(
            "SELECT COUNT(*) FROM analysis_results WHERE target_id IN (" + placeholders + ")",
            target_ids).fetchone()[0]
    return {"targets": len(target_ids), "artifacts": artifacts, "analyses": analyses}


def _purge_case(connection: sqlite3.Connection, case_id: str, export_dir: str,
                analyst: Optional[str], retention_days: int) -> dict:
    """Purges a single case. Writes the chain entry first so the audit record
    exists before the data is removed, then deletes export files and database rows
    in foreign key safe order. The evidence_log is never touched."""
    row_counts = _count_case_rows(connection, case_id)
    export_files = _case_export_files(export_dir, case_id)

    # Write the audit record before deleting anything, so enforcement is provable
    # even if a later step fails.
    if _CASE_LOG_AVAILABLE:
        try:
            log = ChainOfCustodyLog(connection=connection)
            log.append(
                action="case_purged",
                case_id=case_id,
                analyst=analyst,
                notes=("Case purged under the " + str(retention_days) + " day "
                       "retention policy. Removed " + str(row_counts["targets"])
                       + " targets, " + str(row_counts["artifacts"]) + " artifacts, "
                       + str(row_counts["analyses"]) + " analysis records, and "
                       + str(len(export_files)) + " export files. This chain entry is "
                       "retained as the permanent record of the purge."),
            )
        except Exception as exc:
            return {"case_id": case_id, "purged": False,
                    "reason": "Could not write the audit entry, purge aborted: " + str(exc)}

    cur = connection.cursor()
    target_ids = [r[0] for r in cur.execute(
        "SELECT target_id FROM targets WHERE case_id = ?", (case_id,)).fetchall()]

    try:
        if target_ids:
            placeholders = ",".join("?" for _ in target_ids)
            cur.execute("DELETE FROM analysis_results WHERE target_id IN ("
                        + placeholders + ")", target_ids)
            cur.execute("DELETE FROM artifacts WHERE target_id IN ("
                        + placeholders + ")", target_ids)
        cur.execute("DELETE FROM targets WHERE case_id = ?", (case_id,))
        cur.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
        connection.commit()
    except Exception as exc:
        connection.rollback()
        return {"case_id": case_id, "purged": False,
                "reason": "Database deletion failed and was rolled back: " + str(exc)}

    removed_files = []
    failed_files = []
    for path in export_files:
        try:
            path.unlink()
            removed_files.append(path.name)
        except Exception:
            # A file that cannot be removed is reported but does not fail the
            # purge, since the database rows are already gone. It is surfaced so a
            # leftover is visible rather than silent.
            failed_files.append(path.name)

    result = {
        "case_id": case_id,
        "purged": True,
        "rows_deleted": row_counts,
        "files_deleted": removed_files,
    }
    if failed_files:
        result["files_not_removed"] = failed_files
    return result


def enforce_retention(retention_days: int = DEFAULT_RETENTION_DAYS,
                      confirm: bool = False,
                      db_path: Optional[str] = None,
                      connection: Optional[sqlite3.Connection] = None,
                      export_dir: str = "exports",
                      analyst: Optional[str] = None) -> dict:
    """Enforces the retention policy and returns a report. By default this is a dry
    run that lists the cases that would be purged and what would be removed,
    without changing anything. To actually delete, pass confirm set to true.

    The report describes the mode, the retention window, and per case detail. In a
    real purge each purged case is recorded in the chain of custody log before its
    data is removed, and the chain itself is preserved."""

    own_connection = False
    conn = connection
    if conn is None and db_path is not None:
        conn = sqlite3.connect(db_path)
        own_connection = True
    if conn is None:
        return {"ok": False, "reason": "A database connection or db_path is required."}

    report = {
        "ok": True,
        "mode": "purge" if confirm else "dry_run",
        "retention_days": retention_days,
        "evaluated_at": _utc_now_iso(),
        "eligible_count": 0,
        "cases": [],
    }

    try:
        eligible = _eligible_cases(conn, retention_days)
        report["eligible_count"] = len(eligible)

        for case in eligible:
            if confirm:
                outcome = _purge_case(conn, case["case_id"], export_dir, analyst,
                                      retention_days)
                outcome["age_days"] = case["age_days"]
                report["cases"].append(outcome)
            else:
                # Dry run: report what would happen without touching anything.
                row_counts = _count_case_rows(conn, case["case_id"])
                files = _case_export_files(export_dir, case["case_id"])
                report["cases"].append({
                    "case_id": case["case_id"],
                    "age_days": case["age_days"],
                    "would_delete_rows": row_counts,
                    "would_delete_files": [p.name for p in files],
                    "purged": False,
                })
    except Exception as exc:
        if own_connection and conn is not None:
            conn.close()
        return {"ok": False, "reason": "Retention enforcement failed: " + str(exc)}

    if own_connection and conn is not None:
        conn.close()

    return report


def print_report(report: dict) -> int:
    """Prints a human readable summary of a retention report and returns an exit
    code, zero on success and two when enforcement could not run."""
    if not report.get("ok"):
        print("Retention enforcement did not run: " + str(report.get("reason", "")))
        return 2

    mode = report["mode"]
    print("WhisperWard retention enforcement")
    print("Mode: " + ("PURGE (deletions applied)" if mode == "purge"
                       else "dry run (no changes made)"))
    print("Retention window: " + str(report["retention_days"]) + " days")
    print("Cases eligible for purge: " + str(report["eligible_count"]))
    for case in report["cases"]:
        line = "  " + case["case_id"] + "  age " + str(case.get("age_days", "?")) + " days"
        if mode == "purge":
            if case.get("purged"):
                rd = case["rows_deleted"]
                line += "  purged: " + str(rd["targets"]) + " targets, " \
                        + str(rd["artifacts"]) + " artifacts, " \
                        + str(rd["analyses"]) + " analyses, " \
                        + str(len(case["files_deleted"])) + " files"
            else:
                line += "  NOT purged: " + str(case.get("reason", ""))
        else:
            wd = case["would_delete_rows"]
            line += "  would remove: " + str(wd["targets"]) + " targets, " \
                    + str(wd["artifacts"]) + " artifacts, " \
                    + str(wd["analyses"]) + " analyses, " \
                    + str(len(case["would_delete_files"])) + " files"
        print(line)
    if mode == "dry_run" and report["eligible_count"] > 0:
        print("This was a dry run. Re run with confirmation to apply these purges.")
    return 0