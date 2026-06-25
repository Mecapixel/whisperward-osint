"""
WhisperWard OSINT — Signed Case Report Generator
Phase 4, Milestone 5
Pixora Inc.

This module produces a professional case report as a PDF and applies a digital
signature to it. The report draws its content from the case database, so it
reflects exactly what was recorded for the case, and signing it makes the
document tamper evident at the file level, complementing the chain of custody log
and the sealed evidence package.

Everything in the report is real data read from the database or from the actual
signed certificate. The report never prints a hash or a value it cannot
substantiate. When an evidence package exists the report references that
package's real manifest hash read from its seal. When no package exists the
report says so plainly rather than inventing a reference.

A note on the signing certificate. A digital signature needs a certificate and
private key. For a portfolio and demonstration tool the honest approach is a self
signed certificate generated locally on first use, stored under the data
directory and clearly labelled as a portfolio signing identity. The resulting
signature is cryptographically valid and any tampering with the signed PDF is
detectable, but the certificate does not chain to a trusted public authority. A
real law enforcement deployment would use a credentialed certificate. The report
states this plainly.

Deferred features, noted here so the scope is explicit. A QR code linking to a
verification page is not included because no verification page is hosted yet, and
a code that links nowhere would be decoration rather than function. Embedded
screenshot captioning is also deferred, since the report generator does not embed
images and adding that is separate scope. Both can be added later.

Generating a report appends a report_signed entry to the tamper evident chain of
custody log. Optionally it can first create the sealed evidence package so the
report and the package are guaranteed to reference the same manifest hash.

The layout follows the Pixora document standard, a clean professional style with
a simple header, thin bordered tables, a per page footer, and no decorative
banners. Visual polish is reviewed on screen, since fine spacing is judged by eye.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle)
from reportlab.pdfgen import canvas as canvas_module

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

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

try:
    from .evidence_packager import create_evidence_package
    _PACKAGER_AVAILABLE = True
except Exception:
    try:
        from evidence_packager import create_evidence_package
        _PACKAGER_AVAILABLE = True
    except Exception:
        create_evidence_package = None
        _PACKAGER_AVAILABLE = False


REPORT_VERSION = "1.0"
WHISPERWARD_VERSION = "Phase 4"
DEFAULT_CERT_DIR = os.path.join("data", "signing")
CERT_FILE = "whisperward_portfolio_cert.pem"
PFX_FILE = "whisperward_portfolio_identity.pfx"
PFX_PASSPHRASE = b"whisperward-portfolio"

PIXORA_BLUE = colors.HexColor("#1F3864")
TABLE_BORDER = colors.HexColor("#999999")
HEADER_FILL = colors.HexColor("#EEF1F7")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


# ----------------------------------------------------------------------------
# Per page footer canvas. Draws the case id, page number, and the confidentiality
# notice at the bottom of every page.
# ----------------------------------------------------------------------------

class FooterCanvas(canvas_module.Canvas):
    footer_case_id = ""
    footer_report_id = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_pages = []

    def showPage(self):
        self._saved_pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_pages)
        for state in self._saved_pages:
            self.__dict__.update(state)
            self._draw_footer(total)
            super().showPage()
        super().save()

    def _draw_footer(self, total_pages):
        self.setFont("Helvetica", 7)
        self.setFillColor(colors.HexColor("#666666"))
        left = 0.8 * inch
        bottom = 0.5 * inch
        self.drawString(left, bottom,
                        "Case " + FooterCanvas.footer_case_id
                        + "   Report " + FooterCanvas.footer_report_id)
        self.drawCentredString(letter[0] / 2.0, bottom,
                               "Confidential, For Official Use")
        self.drawRightString(letter[0] - left, bottom,
                             "Page " + str(self._pageNumber) + " of " + str(total_pages))


# ----------------------------------------------------------------------------
# Signing identity
# ----------------------------------------------------------------------------

def ensure_signing_identity(cert_dir: str = DEFAULT_CERT_DIR) -> str:
    """Creates a self signed portfolio signing identity if one does not exist and
    returns the path to the PKCS12 identity file. Reused on subsequent runs."""
    directory = Path(cert_dir)
    directory.mkdir(parents=True, exist_ok=True)
    pfx_path = directory / PFX_FILE
    if pfx_path.is_file():
        return str(pfx_path)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pixora Inc."),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "WhisperWard OSINT"),
        x509.NameAttribute(NameOID.COMMON_NAME, "WhisperWard Portfolio Signing Identity"),
    ])
    now = _utc_now()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False),
            critical=True)
        .sign(key, hashes.SHA256())
    )

    from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
    pfx_bytes = pkcs12.serialize_key_and_certificates(
        name=b"whisperward-portfolio", key=key, cert=certificate, cas=None,
        encryption_algorithm=BestAvailableEncryption(PFX_PASSPHRASE))
    with open(pfx_path, "wb") as handle:
        handle.write(pfx_bytes)
    with open(directory / CERT_FILE, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))
    return str(pfx_path)


def _cert_details(cert_dir: str) -> dict:
    """Reads the real signing certificate and returns issuer, validity window, and
    SHA-256 fingerprint for the integrity block. Returns an empty dict if the
    certificate is not present."""
    path = Path(cert_dir) / CERT_FILE
    if not path.is_file():
        return {}
    with open(path, "rb") as handle:
        cert = x509.load_pem_x509_certificate(handle.read())
    return {
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
    }


# ----------------------------------------------------------------------------
# Data gathering
# ----------------------------------------------------------------------------

def _fetch_case_data(connection: sqlite3.Connection, case_id: str) -> dict:
    connection.row_factory = sqlite3.Row
    cur = connection.cursor()

    case = cur.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    targets = cur.execute(
        "SELECT * FROM targets WHERE case_id = ? ORDER BY target_id ASC", (case_id,)
    ).fetchall()

    target_rows = []
    artifact_counts = {}
    total_artifacts = 0
    for target in targets:
        analysis = cur.execute(
            "SELECT analysis_type, risk_score, analyst_notes, analyzed_at "
            "FROM analysis_results WHERE target_id = ? "
            "ORDER BY analyzed_at DESC LIMIT 1", (target["target_id"],)
        ).fetchone()
        target_rows.append({
            "platform": target["platform"],
            "username": target["username"],
            "risk_score": analysis["risk_score"] if analysis else None,
            "analysis_type": analysis["analysis_type"] if analysis else None,
            "analyst_notes": analysis["analyst_notes"] if analysis else None,
        })
        rows = cur.execute(
            "SELECT module_name, artifact_type FROM artifacts WHERE target_id = ?",
            (target["target_id"],)
        ).fetchall()
        for r in rows:
            key = (r["module_name"], r["artifact_type"])
            artifact_counts[key] = artifact_counts.get(key, 0) + 1
            total_artifacts += 1

    custody = []
    custody_total = 0
    verify_result = {"intact": None, "entries_checked": 0}
    if _CASE_LOG_AVAILABLE:
        try:
            log = ChainOfCustodyLog(connection=connection)
            custody = log.entries(case_id=case_id)
            custody_total = len(custody)
            verify_result = log.verify()
        except Exception:
            pass

    return {
        "case": dict(case) if case else {"case_id": case_id},
        "targets": target_rows,
        "artifact_counts": artifact_counts,
        "total_artifacts": total_artifacts,
        "custody": custody,
        "custody_total": custody_total,
        "verify": verify_result,
    }


def _read_package_seal(export_dir: str, case_id: str) -> dict:
    """Reads the real manifest hash from an existing evidence package seal.
    Returns an empty dict if no package exists, so the report never references a
    package that was not created."""
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
            "filename": pkg.name,
            "manifest_sha256": seal.get("manifest_sha256", ""),
            "sealed_at": seal.get("sealed_at", ""),
        }
    except Exception:
        return {}


def _tier_for_score(score) -> str:
    if score is None:
        return "Not scored"
    if score < 2.0:
        return "Tier 1 (monitor only)"
    if score < 7.0:
        return "Tier 2 (human review required)"
    return "Tier 3 (evidence package, sign off required)"


def _risk_narrative(score) -> str:
    if score is None:
        return ("No risk score has been recorded for this target. A score is "
                "produced once behavioral and correlation analysis has run.")
    tier = _tier_for_score(score)
    return ("The composite risk score for this target is "
            + ("%.1f out of 10" % score) + ", which places it in " + tier
            + ". This score reflects weighted behavioral and contextual signals "
            "and is a lead for human review, not a determination about any person.")


# ----------------------------------------------------------------------------
# PDF construction
# ----------------------------------------------------------------------------

def _build_pdf(case_data: dict, package_seal: dict, cert_info: dict,
               report_id: str, output_path: str):
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("PixTitle", parent=styles["Title"],
                                 textColor=PIXORA_BLUE, fontSize=20, spaceAfter=4)
    subtitle_style = ParagraphStyle("PixSub", parent=styles["Normal"],
                                    textColor=colors.HexColor("#444444"),
                                    fontSize=9, spaceAfter=1)
    heading_style = ParagraphStyle("PixHead", parent=styles["Heading2"],
                                   textColor=PIXORA_BLUE, fontSize=13,
                                   spaceBefore=14, spaceAfter=6)
    body_style = ParagraphStyle("PixBody", parent=styles["Normal"],
                                fontSize=10, leading=14)
    small_style = ParagraphStyle("PixSmall", parent=styles["Normal"],
                                 fontSize=8, textColor=colors.HexColor("#666666"),
                                 leading=11)
    mono_style = ParagraphStyle("PixMono", parent=styles["Normal"],
                                fontName="Courier", fontSize=8, leading=10)
    mono_hash_style = ParagraphStyle("PixMonoHash", parent=styles["Normal"],
                                     fontName="Courier", fontSize=7.5, leading=10,
                                     wordWrap="CJK")

    case = case_data["case"]
    story = []

    # Header block.
    story.append(Paragraph("WhisperWard OSINT Case Report", title_style))
    story.append(Paragraph("Pixora Inc. confidential investigative document", subtitle_style))
    story.append(Paragraph("Report ID " + report_id, subtitle_style))
    story.append(Paragraph("Report version " + REPORT_VERSION
                           + "   WhisperWard " + WHISPERWARD_VERSION, subtitle_style))
    story.append(Paragraph("Generated " + _utc_now_iso() + " UTC", subtitle_style))
    story.append(Spacer(1, 0.18 * inch))

    def kv_table(rows, col0=1.7 * inch, col1=4.3 * inch):
        t = Table(rows, colWidths=[col0, col1])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, TABLE_BORDER),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TEXTCOLOR", (0, 0), (0, -1), PIXORA_BLUE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return t

    # Case summary.
    story.append(Paragraph("Case Summary", heading_style))
    story.append(kv_table([
        ["Case ID", str(case.get("case_id", ""))],
        ["Case name", str(case.get("case_name", ""))],
        ["Status", str(case.get("status", ""))],
        ["Analyst", str(case.get("analyst_name", ""))],
        ["Opened", str(case.get("created_at", ""))],
    ]))

    # Targets and risk.
    story.append(Paragraph("Targets and Risk Assessment", heading_style))
    if case_data["targets"]:
        target_data = [["Platform", "Username", "Risk score", "Tier"]]
        for t in case_data["targets"]:
            score = t["risk_score"]
            score_text = ("%.1f / 10" % score) if score is not None else "Not scored"
            target_data.append([t["platform"], t["username"], score_text,
                               _tier_for_score(score)])
        tt = Table(target_data, colWidths=[1.1 * inch, 1.9 * inch, 1.1 * inch, 1.9 * inch])
        tt.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, TABLE_BORDER),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_FILL),
            ("TEXTCOLOR", (0, 0), (-1, 0), PIXORA_BLUE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(tt)
        story.append(Spacer(1, 0.08 * inch))
        for t in case_data["targets"]:
            story.append(Paragraph(_risk_narrative(t["risk_score"]), small_style))
    else:
        story.append(Paragraph("No targets recorded for this case.", body_style))

    # Artifacts summary.
    story.append(Paragraph("Artifacts Summary", heading_style))
    if case_data["total_artifacts"] > 0:
        art_data = [["Module", "Type", "Count"]]
        for (module, atype), count in sorted(case_data["artifact_counts"].items()):
            art_data.append([module, atype, str(count)])
        art_data.append(["Total", "", str(case_data["total_artifacts"])])
        at = Table(art_data, colWidths=[2.0 * inch, 2.5 * inch, 1.5 * inch])
        at.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, TABLE_BORDER),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_FILL),
            ("TEXTCOLOR", (0, 0), (-1, 0), PIXORA_BLUE),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(at)
    else:
        story.append(Paragraph("No artifacts recorded for this case.", body_style))

    # Analyst assessment.
    story.append(Paragraph("Analyst Assessment", heading_style))
    notes_found = False
    for t in case_data["targets"]:
        if t.get("analyst_notes"):
            notes_found = True
            story.append(Paragraph(t["username"] + ": " + str(t["analyst_notes"]), body_style))
    if not notes_found:
        story.append(Paragraph(
            "Pending analyst review. This section records the human analyst's "
            "assessment and conclusions. WhisperWard produces leads for review and "
            "does not make determinations about individuals.", body_style))

    # Chain of custody.
    story.append(Paragraph("Chain of Custody", heading_style))
    verify = case_data["verify"]
    case_count = case_data.get("custody_total", len(case_data["custody"]))
    if verify["intact"] is True:
        verify_text = ("Chain verification status: intact. The full tamper evident "
                       "chain of " + str(verify["entries_checked"]) + " entries across "
                       "all cases verified and confirmed. This case accounts for "
                       + str(case_count) + " of those entries, shown below.")
    elif verify["intact"] is False:
        verify_text = ("Chain verification status: BROKEN. The tamper evident chain "
                       "did not verify and the log may have been altered.")
    else:
        verify_text = "Chain verification status: not available."
    story.append(Paragraph(verify_text, body_style))
    story.append(Spacer(1, 0.06 * inch))
    if case_data["custody"]:
        total = case_data.get("custody_total", len(case_data["custody"]))
        # Show the most recent events first, capped at 12, since the final state
        # (packaged, signed, any late red flags) is what a reviewer needs.
        recent = list(reversed(case_data["custody"]))[:12]
        custody_data = [["Timestamp (UTC)", "Action", "Analyst"]]
        for entry in recent:
            custody_data.append([
                str(entry.get("timestamp", "")),
                str(entry.get("action", "")),
                str(entry.get("analyst") or ""),
            ])
        ct = Table(custody_data, colWidths=[2.6 * inch, 2.4 * inch, 1.0 * inch])
        ct.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, TABLE_BORDER),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_FILL),
            ("TEXTCOLOR", (0, 0), (-1, 0), PIXORA_BLUE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(ct)
        story.append(Spacer(1, 0.05 * inch))
        if total > len(recent):
            note = ("Showing the " + str(len(recent)) + " most recent events of "
                    + str(total) + " for this case, newest first. The full tamper "
                    "evident chain is preserved in the case database and the sealed "
                    "evidence package.")
        else:
            note = ("Showing all " + str(total) + " custody events for this case, "
                    "newest first. The full tamper evident chain is preserved in the "
                    "case database and the sealed evidence package.")
        story.append(Paragraph(note, small_style))
    else:
        story.append(Paragraph("No chained custody entries recorded.", body_style))

    # Evidence package.
    story.append(Paragraph("Evidence Package", heading_style))
    if package_seal:
        hash_para = Paragraph(package_seal.get("manifest_sha256", ""), mono_hash_style)
        pkg_rows = [
            [Paragraph("Package file", small_style), Paragraph(package_seal.get("filename", ""), small_style)],
            [Paragraph("Sealed at (UTC)", small_style), Paragraph(package_seal.get("sealed_at", ""), small_style)],
            [Paragraph("Manifest SHA-256", small_style), hash_para],
            [Paragraph("Seal file", small_style), Paragraph(case.get("case_id", "") + "_manifest.seal.json (inside package)", small_style)],
        ]
        pkg_table = Table(pkg_rows, colWidths=[1.7 * inch, 4.3 * inch])
        pkg_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, TABLE_BORDER),
            ("TEXTCOLOR", (0, 0), (0, -1), PIXORA_BLUE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(pkg_table)
        story.append(Spacer(1, 0.06 * inch))
        story.append(Paragraph(
            "This package was sealed at generation time. To confirm integrity, "
            "extract the manifest and compare it against the seal, then run "
            "verify_evidence_package(). The full seal JSON is stored inside the "
            "package. Any discrepancy should be treated as tampering.", small_style))
    else:
        story.append(Paragraph(
            "No sealed evidence package was generated for this report run. Generate "
            "a package to bind the artifacts to a verifiable manifest hash.", body_style))

    # Document integrity.
    story.append(Paragraph("Document Integrity", heading_style))
    story.append(Paragraph(
        "This report is digitally signed. The signature itself is the integrity "
        "mechanism. A PDF cannot embed its own hash, because adding the hash would "
        "change it, so the cryptographic signature serves that role. Any alteration "
        "of the signed document invalidates the signature and is detectable by any "
        "standard PDF signature validator.", body_style))
    story.append(Spacer(1, 0.06 * inch))
    if cert_info:
        story.append(Paragraph("Signing certificate", small_style))
        story.append(kv_table([
            ["Issuer", Paragraph(cert_info.get("issuer", ""), small_style)],
            ["Valid from", cert_info.get("not_before", "")],
            ["Valid to", cert_info.get("not_after", "")],
        ], col1=4.3 * inch))
        story.append(Spacer(1, 0.04 * inch))
        story.append(Paragraph("Certificate SHA-256 fingerprint", small_style))
        story.append(Paragraph(cert_info.get("fingerprint", ""), mono_style))
    story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph(
        "About this signing identity", small_style))
    story.append(Paragraph(
        "This is a self signed portfolio signing identity. The signature is valid "
        "and tamper detection works.", small_style))
    story.append(Spacer(1, 0.04 * inch))
    story.append(Paragraph(
        "The certificate does not chain to a public certificate authority, which is "
        "appropriate for a portfolio and demonstration tool. A production deployment "
        "would sign with a credentialed certificate issued by an appropriate "
        "authority.", small_style))
    story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph(
        "WhisperWard generates investigative intelligence for human review. It does "
        "not make autonomous determinations about individuals. Every escalation "
        "requires qualified human sign off.", small_style))

    FooterCanvas.footer_case_id = str(case.get("case_id", ""))
    FooterCanvas.footer_report_id = report_id
    doc = SimpleDocTemplate(output_path, pagesize=letter,
                            topMargin=0.8 * inch, bottomMargin=0.8 * inch,
                            leftMargin=0.8 * inch, rightMargin=0.8 * inch)
    doc.build(story, canvasmaker=FooterCanvas)


def _sign_pdf(unsigned_path: str, signed_path: str, pfx_path: str):
    signer = signers.SimpleSigner.load_pkcs12(
        pfx_file=pfx_path, passphrase=PFX_PASSPHRASE)
    with open(unsigned_path, "rb") as inf:
        writer = IncrementalPdfFileWriter(inf)
        append_signature_field(writer, SigFieldSpec(sig_field_name="WhisperWardSignature"))
        meta = signers.PdfSignatureMetadata(field_name="WhisperWardSignature")
        with open(signed_path, "wb") as outf:
            signers.sign_pdf(writer, meta, signer=signer, output=outf)


def generate_signed_report(case_id: str, output_dir: str = "reports",
                           db_path: Optional[str] = None,
                           connection: Optional[sqlite3.Connection] = None,
                           cert_dir: str = DEFAULT_CERT_DIR,
                           analyst: Optional[str] = None,
                           create_package: bool = False,
                           export_dir: str = "exports") -> Optional[str]:
    """Generates a signed case report PDF and returns its path, or None on
    failure. When create_package is true and the packager is available, the
    sealed evidence package is created first so the report references the same
    real manifest hash. Generating the report appends a report_signed entry to the
    chain of custody log."""

    own_connection = False
    conn = connection
    if conn is None and db_path is not None:
        conn = sqlite3.connect(db_path)
        own_connection = True
    if conn is None:
        print("A database connection or db_path is required to build a report.")
        return None

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    unsigned_path = str(out_dir / (case_id + "_report_unsigned.pdf"))
    signed_path = str(out_dir / (case_id + "_report_signed.pdf"))
    report_id = "WW-" + uuid.uuid4().hex[:12].upper()

    try:
        # Optionally create the package first so the report references a real seal.
        if create_package and _PACKAGER_AVAILABLE:
            create_evidence_package(case_id, export_dir=export_dir,
                                    connection=conn, analyst=analyst)

        case_data = _fetch_case_data(conn, case_id)
        package_seal = _read_package_seal(export_dir, case_id)
        cert_info_pre = _cert_details(cert_dir)
        # Ensure identity exists, then read its details for the integrity block.
        pfx_path = ensure_signing_identity(cert_dir)
        cert_info = _cert_details(cert_dir) or cert_info_pre

        _build_pdf(case_data, package_seal, cert_info, report_id, unsigned_path)
        _sign_pdf(unsigned_path, signed_path, pfx_path)
    except Exception as exc:
        if own_connection and conn is not None:
            conn.close()
        print("Error generating signed report: " + str(exc))
        return None

    try:
        os.unlink(unsigned_path)
    except Exception:
        pass

    if _CASE_LOG_AVAILABLE:
        try:
            log = ChainOfCustodyLog(connection=conn)
            log.append(action="report_signed", case_id=case_id, analyst=analyst,
                       notes="Signed case report " + report_id + " generated as "
                       + os.path.basename(signed_path))
        except Exception as exc:
            print("Warning, report was signed but the chain entry could not be "
                  "written: " + str(exc))

    if own_connection and conn is not None:
        conn.close()

    print("Signed case report created: " + signed_path)
    return signed_path