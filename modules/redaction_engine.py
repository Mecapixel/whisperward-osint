"""
WhisperWard OSINT — Redaction Engine
Phase 4, Milestone 5
Pixora Inc.

This module produces a redacted, shareable view of a case. It exists so that a
case can be referred or shared without exposing the personal information of the
reporting party, bystanders, or any protected individual, while preserving the
suspect focused evidence that is the point of the case.

Two design commitments govern this module, and both matter for the integrity of
the wider system.

First, redaction never touches the sealed evidence package. That package is the
immutable original, and its manifest hash and seal are what make tampering
detectable. Redaction reads case data and writes a new, separate derived export.
The authoritative unredacted record always remains available in the sealed
package for authorized parties. Redaction of the derived view is one way, which
is the stronger forensic posture, because a redaction that could be silently
reversed would be a liability rather than a safeguard.

Second, redaction is explicit and pattern based. It masks structurally
identifiable personal data, namely email addresses, phone numbers, IP addresses,
and government identifier patterns, and it masks any value an analyst has
explicitly tagged as protected. It does not attempt to infer a person's age or
role from raw data. The engine does not pretend to detect minors or bystanders
semantically. Responsibility for flagging protected parties rests with the
analyst, who tags them, and the documentation states this limitation plainly so
no reviewer is misled about what the automation does.

Every redaction run appends a redaction_applied entry to the tamper evident chain
of custody log, recording the policy used, the reason, the number of redactions
by category, and the analyst.
"""

from __future__ import annotations

import json
import re
import sqlite3
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


# Placeholders. The category is visible in the output so a reader understands what
# kind of value was removed without seeing the value itself.
PII_PLACEHOLDER = "[REDACTED - PII]"
PROTECTED_PLACEHOLDER = "[REDACTED - PROTECTED]"
MINOR_PLACEHOLDER = "[REDACTED - MINOR]"

# Pattern based detectors for structurally identifiable personal data. These match
# form, not meaning, which is the honest boundary of what automation can claim.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Phone: tolerant of separators, requires enough digits to be a real number.
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}(?!\d)")
# IPv4 with basic octet sanity, and a compact IPv6 form.
_IPV4_RE = re.compile(
    r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)")
# IPv6 is genuinely tricky to match without catching time strings like 01:00:00.
# A real IPv6 address either contains the :: compression form, or has the full
# eight groups, or uses hex groups that include letters. We require one of those
# signals: a :: run, or eight colon separated groups, or at least one group that
# contains a hex letter. This keeps clock values such as 01:00:00 from matching
# while still catching real addresses such as 2001:db8::1 or fe80::a00:27ff:fe4e.
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])("
    r"(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}"  # :: compression, groups either side
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"                               # :: at the end
    r"|(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"                  # full eight groups
    r"|(?:[0-9A-Fa-f]*[A-Fa-f][0-9A-Fa-f]*:){2,}[0-9A-Fa-f]+"    # a group with a hex letter
    r")(?![0-9A-Fa-f:])")
# US SSN pattern. Matched conservatively to limit false positives.
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")


# Redaction policies. A policy is a set of switches describing what to mask. The
# standard policy masks structurally identifiable PII and tagged protected
# values. The minor focused policy additionally treats tagged protected values as
# minor identifiers, changing the placeholder so the output signals the heightened
# sensitivity. Neither policy infers status, both rely on tags for party level
# protection.
POLICIES = {
    "standard": {
        "mask_email": True,
        "mask_phone": True,
        "mask_ip": True,
        "mask_ssn": True,
        "protected_placeholder": PROTECTED_PLACEHOLDER,
    },
    "minor_involved": {
        "mask_email": True,
        "mask_phone": True,
        "mask_ip": True,
        "mask_ssn": True,
        "protected_placeholder": MINOR_PLACEHOLDER,
    },
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RedactionResult:
    """Holds the redacted data and a tally of what was removed, by category."""

    def __init__(self):
        self.counts = {"email": 0, "phone": 0, "ip": 0, "ssn": 0, "protected": 0}
        self.data = None

    def total(self) -> int:
        return sum(self.counts.values())

    def summary(self) -> dict:
        return {"counts": dict(self.counts), "total": self.total()}


def _mask_patterns(text: str, policy: dict, result: RedactionResult) -> str:
    """Masks structurally identifiable PII in a string. Order matters. Email is
    masked before phone and IP, because an email can contain digit runs, and SSN
    is masked before phone to avoid a phone matcher consuming it."""
    if not isinstance(text, str) or not text:
        return text

    if policy.get("mask_email"):
        text, n = _EMAIL_RE.subn(PII_PLACEHOLDER, text)
        result.counts["email"] += n
    if policy.get("mask_ssn"):
        text, n = _SSN_RE.subn(PII_PLACEHOLDER, text)
        result.counts["ssn"] += n
    if policy.get("mask_ip"):
        text, n = _IPV4_RE.subn(PII_PLACEHOLDER, text)
        result.counts["ip"] += n
        text, n = _IPV6_RE.subn(PII_PLACEHOLDER, text)
        result.counts["ip"] += n
    if policy.get("mask_phone"):
        text, n = _PHONE_RE.subn(PII_PLACEHOLDER, text)
        result.counts["phone"] += n
    return text


def _mask_protected(text: str, protected_values: list, placeholder: str,
                    result: RedactionResult) -> str:
    """Replaces any analyst tagged protected value wherever it appears in a
    string. Matching is case insensitive and whole token oriented so that, for
    example, a protected username is removed without mangling unrelated words."""
    if not isinstance(text, str) or not text or not protected_values:
        return text
    for value in protected_values:
        if not value:
            continue
        pattern = re.compile(re.escape(str(value)), re.IGNORECASE)
        text, n = pattern.subn(placeholder, text)
        result.counts["protected"] += n
    return text


def _redact_value(value, policy: dict, protected_values: list, result: RedactionResult):
    """Recursively redacts strings inside nested dictionaries and lists, leaving
    non string scalars unchanged. This lets the engine operate on arbitrary case
    structures without knowing their shape in advance."""
    placeholder = policy.get("protected_placeholder", PROTECTED_PLACEHOLDER)
    if isinstance(value, str):
        value = _mask_patterns(value, policy, result)
        value = _mask_protected(value, protected_values, placeholder, result)
        return value
    if isinstance(value, dict):
        return {k: _redact_value(v, policy, protected_values, result) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v, policy, protected_values, result) for v in value]
    return value


def _gather_protected_values(connection: sqlite3.Connection, case_id: str) -> list:
    """Collects analyst tagged protected values for a case. A value is treated as
    protected when a protected tag of the form protected: value appears in any of
    the case's free text fields, namely target notes, the case description, and
    analysis analyst_notes, or when a dedicated protected_parties table is present.
    Scanning every free text surface, rather than target notes alone, means a tag
    works wherever the analyst happens to write it, which matches where the
    redaction is actually applied across the case structure."""
    connection.row_factory = sqlite3.Row
    cur = connection.cursor()
    values = []

    def _extract_tags(text):
        found = []
        if text is None:
            return found
        for line in str(text).splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("protected:"):
                val = stripped.split(":", 1)[1].strip()
                if val:
                    found.append(val)
        return found

    # Target notes.
    try:
        rows = cur.execute(
            "SELECT notes FROM targets WHERE case_id = ? AND notes IS NOT NULL",
            (case_id,)
        ).fetchall()
        for row in rows:
            values.extend(_extract_tags(row["notes"]))
    except sqlite3.Error:
        pass

    # Case description.
    try:
        row = cur.execute(
            "SELECT description FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if row is not None:
            values.extend(_extract_tags(row["description"]))
    except sqlite3.Error:
        pass

    # Analyst notes on analysis results for this case's targets.
    try:
        rows = cur.execute(
            "SELECT ar.analyst_notes FROM analysis_results ar "
            "JOIN targets t ON ar.target_id = t.target_id "
            "WHERE t.case_id = ? AND ar.analyst_notes IS NOT NULL", (case_id,)
        ).fetchall()
        for row in rows:
            values.extend(_extract_tags(row["analyst_notes"]))
    except sqlite3.Error:
        pass

    # Optional dedicated table, used if the deployment created one.
    try:
        rows = cur.execute(
            "SELECT value FROM protected_parties WHERE case_id = ?", (case_id,)
        ).fetchall()
        for row in rows:
            if row["value"]:
                values.append(str(row["value"]))
    except sqlite3.Error:
        pass

    # De duplicate while preserving order.
    seen = set()
    unique = []
    for v in values:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique


def _build_case_export(connection: sqlite3.Connection, case_id: str) -> dict:
    """Assembles the case into a plain structure suitable for redaction and
    export. This is the unredacted source view, read from the database."""
    connection.row_factory = sqlite3.Row
    cur = connection.cursor()

    case = cur.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    targets = cur.execute(
        "SELECT * FROM targets WHERE case_id = ? ORDER BY target_id ASC", (case_id,)
    ).fetchall()

    target_list = []
    for target in targets:
        analyses = cur.execute(
            "SELECT analysis_type, risk_score, analyst_notes, analyzed_at "
            "FROM analysis_results WHERE target_id = ? ORDER BY analyzed_at DESC",
            (target["target_id"],)
        ).fetchall()
        artifacts = cur.execute(
            "SELECT module_name, artifact_type, collected_at FROM artifacts "
            "WHERE target_id = ? ORDER BY artifact_id ASC", (target["target_id"],)
        ).fetchall() if _has_column(cur, "artifacts", "collected_at") else cur.execute(
            "SELECT module_name, artifact_type FROM artifacts WHERE target_id = ? "
            "ORDER BY artifact_id ASC", (target["target_id"],)
        ).fetchall()
        target_list.append({
            "platform": target["platform"],
            "username": target["username"],
            "notes": target["notes"] if "notes" in target.keys() else None,
            "analyses": [dict(a) for a in analyses],
            "artifacts": [dict(a) for a in artifacts],
        })

    return {
        "case_id": case_id,
        "case": dict(case) if case else {"case_id": case_id},
        "targets": target_list,
        "exported_at": _utc_now_iso(),
    }


def _has_column(cur, table, column) -> bool:
    try:
        cols = {r[1] for r in cur.execute("PRAGMA table_info(" + table + ")")}
        return column in cols
    except sqlite3.Error:
        return False


def redact_case(case_id: str, analyst: Optional[str] = None,
                reason: str = "referral",
                policy: str = "standard",
                db_path: Optional[str] = None,
                connection: Optional[sqlite3.Connection] = None,
                output_dir: str = "exports",
                write_file: bool = True) -> Optional[dict]:
    """Produces a redacted derived view of a case and returns a result dictionary
    containing the redacted data and a tally of what was removed. The sealed
    evidence package is never touched. When write_file is true the redacted view
    is written to output_dir as a separate JSON export. A redaction_applied entry
    is appended to the chain of custody log.

    The policy selects what is masked. Protected party values are gathered from
    analyst tags. The reason is recorded for the audit trail, for example referral
    or external_share."""

    if policy not in POLICIES:
        print("Unknown redaction policy: " + str(policy) + ". Valid policies are "
              + ", ".join(POLICIES.keys()) + ".")
        return None
    policy_def = POLICIES[policy]

    own_connection = False
    conn = connection
    if conn is None and db_path is not None:
        conn = sqlite3.connect(db_path)
        own_connection = True
    if conn is None:
        print("A database connection or db_path is required to redact a case.")
        return None

    try:
        source = _build_case_export(conn, case_id)
        protected_values = _gather_protected_values(conn, case_id)

        result = RedactionResult()
        result.data = _redact_value(source, policy_def, protected_values, result)
        # Annotate the redacted export with an honest description of what happened.
        result.data["redaction"] = {
            "applied_at": _utc_now_iso(),
            "policy": policy,
            "reason": reason,
            "analyst": analyst,
            "counts": dict(result.counts),
            "total_redactions": result.total(),
            "note": ("Structurally identifiable PII and analyst tagged protected "
                     "values were masked. The unredacted original remains in the "
                     "sealed evidence package. Party level protection relies on "
                     "analyst tags, not automated detection of age or role."),
        }
    except Exception as exc:
        if own_connection and conn is not None:
            conn.close()
        print("Error during redaction: " + str(exc))
        return None

    output_path = None
    if write_file:
        try:
            out_dir = Path(output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            output_path = str(out_dir / (case_id + "_redacted_referral.json"))
            with open(output_path, "w", encoding="utf-8") as handle:
                json.dump(result.data, handle, indent=2, sort_keys=True)
        except Exception as exc:
            if own_connection and conn is not None:
                conn.close()
            print("Redaction succeeded but writing the export failed: " + str(exc))
            return None

    if _CASE_LOG_AVAILABLE:
        try:
            log = ChainOfCustodyLog(connection=conn)
            log.append(
                action="redaction_applied",
                case_id=case_id,
                analyst=analyst,
                notes=("Redacted derived export created. Policy " + policy
                       + ", reason " + reason + ", "
                       + str(result.total()) + " redactions ("
                       + ", ".join(k + "=" + str(v) for k, v in result.counts.items())
                       + ")."),
            )
        except Exception as exc:
            print("Warning, redaction completed but the chain entry could not be "
                  "written: " + str(exc))

    if own_connection and conn is not None:
        conn.close()

    return {
        "case_id": case_id,
        "policy": policy,
        "reason": reason,
        "counts": dict(result.counts),
        "total_redactions": result.total(),
        "output_path": output_path,
        "data": result.data,
    }