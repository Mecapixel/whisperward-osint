"""
WhisperWard OSINT — Evidence Packager
Phase 4, Milestone 5
Pixora Inc.

This module assembles a tamper evident evidence package for a case. It is an
upgrade of the original packager and keeps the same package shape, a ZIP archive
containing the case artifacts plus a manifest, so anything downstream that
consumed the old package still works. The upgrade addresses three forensic gaps
in the original.

First, every timestamp is recorded in UTC with an explicit timezone. A chain of
custody timestamp without a timezone is ambiguous, and ambiguity is challenged in
court.

Second, the manifest is itself hashed, and that manifest hash is recorded both
inside the package and in the chain of custody log. The original hashed each file
but left the manifest unprotected, so there was nothing proving the manifest was
not altered after the fact. Now the manifest carries a self hash computed over its
own contents, and the package records it.

Third, the package is built from a specific case's artifacts rather than from a
blind sweep of the exports directory. The original globbed every file under
exports, which risked pulling unrelated files into a case package. When a database
connection is supplied, the packager selects exactly the files belonging to the
case through its targets and artifacts, so the package contains only that case's
evidence.

Creating a package writes an entry to the tamper evident chain of custody log, so
the act of packaging is itself part of the record.

The module degrades gracefully. If no database is available it falls back to
packaging a supplied list of files, so it remains usable in a minimal setup, but
the database path is the forensically correct one and is preferred.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile
from datetime import datetime, timezone
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


PACKAGE_VERSION = "2.0"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _case_artifact_paths(connection: sqlite3.Connection, case_id: str) -> list:
    """Returns the on disk file paths of every artifact belonging to a case by
    walking targets and artifacts. Only artifacts that recorded a file_path are
    returned, since those are the ones with a file to package."""
    connection.row_factory = sqlite3.Row
    cur = connection.cursor()
    rows = cur.execute(
        """
        SELECT a.file_path, a.sha256, a.artifact_id, a.module_name, a.artifact_type
        FROM artifacts a
        JOIN targets t ON a.target_id = t.target_id
        WHERE t.case_id = ? AND a.file_path IS NOT NULL AND a.file_path != ''
        ORDER BY a.artifact_id ASC
        """,
        (case_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def create_evidence_package(case_id: str, export_dir: str = "exports",
                            db_path: Optional[str] = None,
                            connection: Optional[sqlite3.Connection] = None,
                            analyst: Optional[str] = None,
                            file_list: Optional[list] = None) -> Optional[str]:
    """Creates a tamper evident evidence package for a case and returns the path
    to the ZIP, or None on failure.

    When a database is available through db_path or connection, the package is
    built from exactly the artifacts belonging to the case. When no database is
    available, the caller may pass file_list to package a specific set of files.
    If neither is available the function reports that it has nothing authoritative
    to package rather than sweeping unrelated files.

    Creating a package appends an entry to the chain of custody log when one is
    available, recording the manifest hash so the packaging event is itself part
    of the tamper evident record."""

    export_path = Path(export_dir)
    export_path.mkdir(parents=True, exist_ok=True)
    package_path = export_path / (case_id + "_evidence_package.zip")

    own_connection = False
    conn = connection
    if conn is None and db_path is not None:
        conn = sqlite3.connect(db_path)
        own_connection = True

    manifest = {
        "case_id": case_id,
        "generated_at": _utc_now_iso(),
        "package_version": PACKAGE_VERSION,
        "files": [],
        "sha256_manifest": {},
        "source": "",
    }

    # Resolve the set of files to package, preferring the database.
    resolved_files = []
    if conn is not None:
        manifest["source"] = "database"
        for artifact in _case_artifact_paths(conn, case_id):
            candidate = Path(artifact["file_path"])
            if candidate.is_file():
                resolved_files.append(candidate)
    elif file_list is not None:
        manifest["source"] = "file_list"
        for item in file_list:
            candidate = Path(item)
            if candidate.is_file():
                resolved_files.append(candidate)
    else:
        if own_connection and conn is not None:
            conn.close()
        print("No database connection and no file list were provided, so there is "
              "nothing authoritative to package. Provide db_path, connection, or file_list.")
        return None

    try:
        with zipfile.ZipFile(package_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for file_path in resolved_files:
                if file_path.name == package_path.name:
                    continue
                arcname = file_path.name
                archive.write(file_path, arcname)
                manifest["files"].append(arcname)
                manifest["sha256_manifest"][arcname] = _sha256_file(file_path)

            # Serialize the manifest, hash that exact serialization, then write
            # both the manifest and a small seal file that records the manifest
            # hash. The seal is what proves the manifest itself was not altered.
            manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
            manifest_hash = _sha256_bytes(manifest_bytes)

            seal = {
                "case_id": case_id,
                "manifest_sha256": manifest_hash,
                "sealed_at": _utc_now_iso(),
                "package_version": PACKAGE_VERSION,
            }
            seal_bytes = json.dumps(seal, indent=2, sort_keys=True).encode("utf-8")

            archive.writestr(case_id + "_manifest.json", manifest_bytes)
            archive.writestr(case_id + "_manifest.seal.json", seal_bytes)

    except Exception as exc:
        if own_connection and conn is not None:
            conn.close()
        print("Error creating evidence package: " + str(exc))
        return None

    # Record the packaging event in the tamper evident chain when available.
    if conn is not None and _CASE_LOG_AVAILABLE:
        try:
            log = ChainOfCustodyLog(connection=conn)
            log.append(
                action="evidence_package_created",
                case_id=case_id,
                analyst=analyst,
                sha256=manifest_hash,
                notes="Evidence package " + package_path.name + " created with "
                      + str(len(manifest["files"])) + " files. Manifest hash recorded.",
            )
        except Exception as exc:
            # Logging failure must not destroy a built package. The package still
            # exists and is returned, and the failure is surfaced.
            print("Warning, evidence package was created but the chain of custody "
                  "entry could not be written: " + str(exc))

    if own_connection and conn is not None:
        conn.close()

    print("Evidence package created: " + str(package_path))
    return str(package_path)


def verify_evidence_package(package_path: str) -> dict:
    """Verifies a package after the fact. Confirms that the manifest hash recorded
    in the seal matches the manifest in the archive, and that every file in the
    archive matches the hash the manifest recorded for it. Returns a result
    describing whether the package is intact and what, if anything, failed."""
    result = {"intact": False, "checked_files": 0, "problems": []}
    path = Path(package_path)
    if not path.is_file():
        result["problems"].append("Package file not found at " + package_path + ".")
        return result

    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = archive.namelist()
            manifest_name = next((n for n in names if n.endswith("_manifest.json")), None)
            seal_name = next((n for n in names if n.endswith("_manifest.seal.json")), None)
            if manifest_name is None or seal_name is None:
                result["problems"].append("Package is missing its manifest or seal.")
                return result

            manifest_bytes = archive.read(manifest_name)
            seal = json.loads(archive.read(seal_name))

            # The manifest is re-serialized from its parsed form using the same
            # canonical settings so the hash comparison is stable.
            manifest = json.loads(manifest_bytes)
            recomputed_manifest_hash = _sha256_bytes(
                json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))

            if recomputed_manifest_hash != seal.get("manifest_sha256"):
                result["problems"].append(
                    "Manifest hash does not match the seal, the manifest was altered.")
                return result

            for arcname, expected_hash in manifest["sha256_manifest"].items():
                if arcname not in names:
                    result["problems"].append("File listed in manifest is missing: " + arcname)
                    continue
                actual = _sha256_bytes(archive.read(arcname))
                if actual != expected_hash:
                    result["problems"].append("File hash mismatch for " + arcname + ".")
                else:
                    result["checked_files"] += 1

    except Exception as exc:
        result["problems"].append("Could not read package: " + str(exc))
        return result

    result["intact"] = len(result["problems"]) == 0
    return result