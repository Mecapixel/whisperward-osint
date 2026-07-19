"""
WhisperWard OSINT — Threat List Refresh
Phase 4, Milestone 4
Pixora Inc.

This script refreshes the local threat intelligence that the IP enrichment module
reads. It is meant to be run between cases, never during one, so that enrichment
lookups stay fully offline and deterministic while the underlying lists are still
kept current.

This is the only part of the IP enrichment capability that makes an outbound
network call, and the call sends no case data. It downloads the Tor Project's
public bulk exit node list, which is keyless and plain text, validates it, and
installs it atomically so a failed or truncated download can never replace a good
list with a bad one. If the download fails for any reason, the existing list is
left exactly as it was and the failure is reported.

The MaxMind GeoLite2 City and ASN databases and the IP2Proxy LITE database are
deliberately not auto downloaded, because both sit behind account logins and
license keys, and automating a credentialed download is out of scope. For those
this script reports whether the file is present and how old it is, and prints the
manual download steps when a file is missing or stale.

Finally the script validates the curated ASN authority file using the same rules
the enricher enforces, so a bad hand edit to that file is caught here, at refresh
time, rather than blocking the start of your next case.

Usage examples. Run the full refresh from the repository root with python
update_threat_lists.py. Refresh only the Tor list with the tor-only flag. Point at
a non default data directory with the data-dir option. The script exits with a non
zero status if the Tor refresh failed or the authority file is invalid, so it can
be used as a pre flight gate.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import sys
import tempfile
from datetime import datetime, timezone


# The official Tor Project bulk exit list. Plain text, one address per line, no
# key required. This is the single outbound call in the enrichment capability and
# it transmits no case data.
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"

# A real exit list contains on the order of a thousand or more addresses. If a
# download yields fewer than this, it is treated as truncated or wrong and the
# existing list is kept rather than replaced.
TOR_MINIMUM_REASONABLE_ENTRIES = 100

# Default data layout, matching the paths the enricher reads.
DEFAULT_DATA_DIR = "data"
TOR_RELATIVE = os.path.join("threat_intel", "tor_exit_nodes.txt")
TOR_META_RELATIVE = os.path.join("threat_intel", "tor_exit_nodes.meta.json")
ASN_SET_RELATIVE = os.path.join("threat_intel", "hosting_vpn_asns.json")
GEOIP_CITY_RELATIVE = os.path.join("geoip", "GeoLite2-City.mmdb")
GEOIP_ASN_RELATIVE = os.path.join("geoip", "GeoLite2-ASN.mmdb")
IP2PROXY_RELATIVE = os.path.join("proxy", "IP2PROXY-LITE-PX11.BIN")

# Files older than this many days are reported as stale in the summary.
STALE_AFTER_DAYS = 7


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _file_age_days(path: str):
    try:
        mtime = os.path.getmtime(path)
        delta = datetime.now(timezone.utc).timestamp() - mtime
        return round(delta / 86400.0, 2)
    except Exception:
        return None


def _sha256_text(text: str) -> str:
    """Returns the SHA-256 of the given text encoded as UTF-8. Used to stamp the
    exact installed Tor snapshot so later provenance checks can confirm which
    list produced a result."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def fetch_tor_exit_list(url: str = TOR_EXIT_LIST_URL, timeout: int = 30) -> str:
    """Downloads the Tor bulk exit list and returns its raw text. Uses requests
    when available and falls back to the standard library so the script has no
    hard third party dependency. Raises on any network or HTTP failure so the
    caller can keep the existing list intact."""
    try:
        import requests
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response.text
    except ImportError:
        from urllib.request import urlopen
        with urlopen(url, timeout=timeout) as handle:
            return handle.read().decode("utf-8", errors="replace")


def looks_like_web_page(text: str) -> bool:
    """Returns true when the downloaded body looks like an HTML page rather than a
    plain text list, which is the signature of an error page, a captcha, or an
    access block returned in place of the exit list. The validator would reject
    such a body anyway for lacking valid addresses, but detecting it explicitly
    lets the report explain the real problem instead of only reporting a low
    count."""
    head = text.lstrip()[:512].lower()
    return "<html" in head or "<!doctype" in head or "<head" in head or "<body" in head


def parse_and_validate_tor_text(text: str) -> tuple:
    """Parses raw exit list text into a deduplicated list of valid addresses.
    Returns a tuple of the unique valid address list, a list of human readable
    problems, and the raw count of valid lines seen before deduplication. Lines
    that are blank or start with a comment marker are ignored. Any line that is
    not a valid address is counted as a problem but does not stop parsing.
    Duplicate addresses are removed while preserving first seen order, so the
    installed list and its count reflect unique exits."""
    seen = set()
    valid = []
    problems = []
    raw_valid_count = 0
    for number, line in enumerate(text.splitlines(), start=1):
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            problems.append("Line " + str(number) + " is not a valid address: " + candidate[:60])
            continue
        raw_valid_count += 1
        if candidate in seen:
            continue
        seen.add(candidate)
        valid.append(candidate)

    duplicate_count = raw_valid_count - len(valid)
    if duplicate_count > 0:
        problems.append(str(duplicate_count) + " duplicate addresses were removed.")

    if len(valid) < TOR_MINIMUM_REASONABLE_ENTRIES:
        problems.append(
            "Only " + str(len(valid)) + " unique valid addresses were found, which is below "
            "the reasonable minimum of " + str(TOR_MINIMUM_REASONABLE_ENTRIES)
            + ". The download is treated as truncated or wrong and will not be installed.")
    return valid, problems, raw_valid_count


def atomic_write_lines(path: str, lines: list):
    """Writes the given lines to the target path atomically. The content is first
    written to a temporary file in the same directory and then moved into place
    with os.replace, which is atomic on a given filesystem. This guarantees that a
    reader never sees a half written file and that a failure mid write cannot
    corrupt the existing file.

    The file is written in binary mode with explicit newline characters so the
    bytes on disk are identical on every operating system. This matters because
    the provenance SHA-256 is computed over the same newline form, and a hash that
    changed depending on which platform wrote the file would be useless for
    verification. Writing binary avoids the text mode newline translation that
    Windows would otherwise apply."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    body = ("\n".join(lines) + "\n").encode("utf-8")
    handle = tempfile.NamedTemporaryFile(
        mode="wb", dir=directory, delete=False, suffix=".tmp")
    try:
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        os.replace(handle.name, path)
    except Exception:
        try:
            os.unlink(handle.name)
        except Exception:
            pass
        raise


def refresh_tor_list(data_dir: str, timeout: int = 30, fetcher=None,
                     dry_run: bool = False) -> dict:
    """Refreshes the Tor exit list under the given data directory. Downloads,
    validates, deduplicates, and only then installs the new list atomically. On
    any failure the existing list is left untouched. When dry_run is true the
    full fetch and validation run but nothing is written, so an operator can
    verify reachability and validation behavior safely. The fetcher argument
    allows a caller or a test to supply an alternative download function. Returns
    a result dictionary describing what happened."""
    target = os.path.join(data_dir, TOR_RELATIVE)
    meta_target = os.path.join(data_dir, TOR_META_RELATIVE)
    fetch = fetcher or fetch_tor_exit_list

    result = {"step": "tor_exit_list", "ok": False, "installed": False,
              "dry_run": dry_run, "count": 0, "raw_count": 0, "sha256": "",
              "problems": [], "detail": ""}

    try:
        text = fetch(TOR_EXIT_LIST_URL, timeout)
    except Exception as exc:
        result["detail"] = ("Download failed, the existing list was kept unchanged. Reason: "
                            + str(exc))
        return result

    if looks_like_web_page(text):
        result["detail"] = ("The endpoint returned a web page rather than the plain text exit "
                            "list, which usually means an error page or access block. The "
                            "existing list was kept unchanged.")
        result["problems"].append("Response body appears to be HTML, not a plain text list.")
        return result

    valid, problems, raw_count = parse_and_validate_tor_text(text)
    result["count"] = len(valid)
    result["raw_count"] = raw_count
    result["problems"] = problems

    if len(valid) < TOR_MINIMUM_REASONABLE_ENTRIES:
        result["detail"] = ("Downloaded content did not pass validation with "
                            + str(len(valid)) + " unique valid addresses, the existing list "
                            "was kept unchanged.")
        return result

    body = "\n".join(valid) + "\n"
    result["sha256"] = _sha256_text(body)

    if dry_run:
        result["ok"] = True
        result["detail"] = ("Dry run, validated " + str(len(valid)) + " unique Tor exit "
                            "addresses. Nothing was written.")
        return result

    try:
        atomic_write_lines(target, valid)
        now = _now_iso()
        meta = {"fetched_at": now, "validated_at": now, "source": TOR_EXIT_LIST_URL,
                "entry_count": len(valid), "raw_count": raw_count,
                "sha256": result["sha256"]}
        with open(meta_target, "w", encoding="utf-8") as handle:
            json.dump(meta, handle, indent=2)
    except Exception as exc:
        result["detail"] = "Validated list could not be written: " + str(exc)
        return result

    result["ok"] = True
    result["installed"] = True
    result["detail"] = ("Installed " + str(len(valid)) + " unique Tor exit addresses from "
                        + str(raw_count) + " valid lines.")
    return result


def check_credentialed_database(path: str, label: str, instructions: str) -> dict:
    """Reports presence and age for a database that cannot be auto downloaded
    because it sits behind an account or license key. Never fetches anything.
    Returns a result dictionary including the manual instructions when the file is
    missing or stale."""
    present = os.path.exists(path)
    age = _file_age_days(path) if present else None
    stale = present and age is not None and age > STALE_AFTER_DAYS
    manual_action_required = (not present) or stale
    result = {"step": label, "present": present, "age_days": age, "stale": stale,
              "manual_action_required": manual_action_required,
              "instructions": "", "detail": ""}
    if not present:
        result["detail"] = label + " is not present at " + path + "."
        result["instructions"] = instructions
    elif stale:
        result["detail"] = (label + " is present but is " + str(age)
                            + " days old, older than the " + str(STALE_AFTER_DAYS)
                            + " day staleness threshold.")
        result["instructions"] = instructions
    else:
        result["detail"] = label + " is present and current, " + str(age) + " days old."
    return result


def validate_authority_file(data_dir: str) -> dict:
    """Validates the curated ASN authority file using the same rules the enricher
    enforces, so a bad hand edit is caught at refresh time. Imports the validator
    from the enrichment module so there is a single source of truth for the
    category policy."""
    path = os.path.join(data_dir, ASN_SET_RELATIVE)
    result = {"step": "asn_authority", "ok": False, "present": os.path.exists(path),
              "errors": [], "detail": ""}
    if not os.path.exists(path):
        result["ok"] = True
        result["detail"] = ("No curated ASN authority file is present at " + path
                            + ". This is acceptable, the enricher degrades gracefully without it.")
        return result
    try:
        from core.ip_enrichment import validate_asn_set
    except Exception as exc:
        result["detail"] = "Could not import the validator from ip_enrichment: " + str(exc)
        return result
    errors = validate_asn_set(path)
    if errors:
        result["errors"] = errors
        result["detail"] = ("The curated ASN authority file has problems that will stop the "
                            "pipeline in strict mode. Fix these before your next case.")
        return result
    result["ok"] = True
    result["detail"] = "The curated ASN authority file is valid."
    return result


MAXMIND_INSTRUCTIONS = (
    "Create a free MaxMind account, then from the account portal open Download Databases "
    "and download GeoLite2 City and GeoLite2 ASN in the MMDB format. Place GeoLite2-City.mmdb "
    "and GeoLite2-ASN.mmdb in the geoip folder of your data directory.")

IP2PROXY_INSTRUCTIONS = (
    "Create a free IP2Location LITE account, download the IP2PROXY-LITE-PX11 database in the "
    "BIN format, and place IP2PROXY-LITE-PX11.BIN in the proxy folder of your data directory.")


def run_refresh(data_dir: str, tor_only: bool = False, skip_validate: bool = False,
                timeout: int = 30, fetcher=None, dry_run: bool = False) -> dict:
    """Runs the selected refresh steps and returns a structured report. This is
    the orchestration the command line entry point calls, separated so it can be
    driven programmatically or from a test. When dry_run is true the Tor step
    validates without writing, and the credentialed and authority checks are read
    only by nature."""
    report = {"started_at": _now_iso(), "data_dir": data_dir, "dry_run": dry_run,
              "steps": []}

    report["steps"].append(refresh_tor_list(data_dir, timeout=timeout, fetcher=fetcher,
                                            dry_run=dry_run))

    if not tor_only:
        report["steps"].append(check_credentialed_database(
            os.path.join(data_dir, GEOIP_CITY_RELATIVE), "GeoLite2 City database",
            MAXMIND_INSTRUCTIONS))
        report["steps"].append(check_credentialed_database(
            os.path.join(data_dir, GEOIP_ASN_RELATIVE), "GeoLite2 ASN database",
            MAXMIND_INSTRUCTIONS))
        report["steps"].append(check_credentialed_database(
            os.path.join(data_dir, IP2PROXY_RELATIVE), "IP2Proxy LITE database",
            IP2PROXY_INSTRUCTIONS))

    if not skip_validate:
        report["steps"].append(validate_authority_file(data_dir))

    report["finished_at"] = _now_iso()
    return report


def _print_report(report: dict) -> int:
    """Prints a human readable summary and returns a process exit code. The exit
    code is non zero when the Tor refresh failed or the authority file is invalid,
    so this script can serve as a pre flight gate."""
    print("WhisperWard threat list refresh")
    print("Started " + report["started_at"])
    print("Data directory " + os.path.abspath(report["data_dir"]))
    if report.get("dry_run"):
        print("Mode dry run, no files will be written.")
    print("")

    exit_code = 0
    for step in report["steps"]:
        name = step.get("step", "step")
        print(name)
        if "detail" in step and step["detail"]:
            print("  " + step["detail"])
        if name == "tor_exit_list":
            print("  source " + TOR_EXIT_LIST_URL)
            print("  unique addresses " + str(step.get("count", 0))
                  + ", raw valid lines " + str(step.get("raw_count", 0)))
            if step.get("sha256"):
                print("  sha256 " + step["sha256"])
        if "age_days" in step:
            age_display = "missing" if step.get("age_days") is None else (str(step["age_days"]) + " days")
            print("  age " + age_display
                  + (", manual action required" if step.get("manual_action_required") else ""))
        for problem in step.get("problems", [])[:5]:
            print("  note " + problem)
        for error in step.get("errors", []):
            print("  error " + error)
        if step.get("instructions"):
            print("  to fix, " + step["instructions"])
        print("")

        if name == "tor_exit_list" and not step.get("ok"):
            exit_code = 2
        if name == "asn_authority" and not step.get("ok"):
            exit_code = 2

    print("Finished " + report.get("finished_at", _now_iso()))
    if exit_code == 0:
        print("Result, refresh completed without blocking problems.")
    else:
        print("Result, one or more blocking problems were found, see above.")
    return exit_code


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Refresh WhisperWard local threat intelligence between cases.")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR,
                       help="Root data directory the enricher reads. Default is data.")
    parser.add_argument("--tor-only", action="store_true",
                       help="Refresh only the Tor exit list and skip the database checks.")
    parser.add_argument("--skip-validate", action="store_true",
                       help="Skip validation of the curated ASN authority file.")
    parser.add_argument("--timeout", type=int, default=30,
                       help="Network timeout in seconds for the Tor list download.")
    parser.add_argument("--dry-run", action="store_true",
                       help="Fetch and validate the Tor list and print the summary without "
                            "writing any files.")
    args = parser.parse_args(argv)

    report = run_refresh(args.data_dir, tor_only=args.tor_only,
                         skip_validate=args.skip_validate, timeout=args.timeout,
                         dry_run=args.dry_run)
    return _print_report(report)


if __name__ == "__main__":
    raise SystemExit(main())