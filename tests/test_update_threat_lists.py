"""
WhisperWard OSINT — Test suite for the Threat List Refresh script
Phase 4, Milestone 4
Pixora Inc.

These tests lock in the verified behavior of update_threat_lists.py so a future
edit cannot silently regress it. No test makes a network call. The Tor download
is simulated by passing an alternative fetcher into the refresh functions, which
is the same injection point the script exposes for exactly this purpose. All file
operations run inside temporary directories.

The behaviors under test are the ones that make this a safe maintenance tool. A
good download installs and stamps provenance. A truncated download, a network
error, or an HTML error page must all leave the existing list untouched. The dry
run validates without writing. The credentialed database checks report state
without ever fetching. The authority file gate catches a malformed file at
refresh time. And the process exit code is non zero when something would block a
case.
"""

import json
import os
import tempfile

import pytest

import core.update_threat_lists as u


# Simulated fetchers. Each stands in for the real Tor download.

def good_fetch(url, timeout):
    """Returns a realistic list of unique valid addresses well above the floor."""
    return "\n".join("185.220.%d.%d" % (i // 256, i % 256) for i in range(1200))


def dup_fetch(url, timeout):
    """Returns valid addresses plus duplicates, comments, and one garbage line."""
    lines = ["185.220.%d.%d" % (i // 256, i % 256) for i in range(1200)]
    lines += ["185.220.0.0", "185.220.0.1"] * 100
    lines += ["# a comment", "", "garbage-line"]
    return "\n".join(lines)


def truncated_fetch(url, timeout):
    """Returns far fewer than the reasonable minimum, simulating a bad fetch."""
    return "\n".join("1.2.3.%d" % i for i in range(10))


def error_fetch(url, timeout):
    raise ConnectionError("simulated network drop")


def html_fetch(url, timeout):
    return ("<!DOCTYPE html><html><head><title>403 Forbidden</title></head>"
            "<body>Access denied</body></html>")


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as directory:
        os.makedirs(os.path.join(directory, "threat_intel"), exist_ok=True)
        yield directory


def read_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def write_asn_authority(tmp_dir, entries):
    path = os.path.join(tmp_dir, u.ASN_SET_RELATIVE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"asns": entries}, handle)
    return path


def valid_authority_entry(asn, category="known-vpn"):
    return {"asn": asn, "organization": "Test Org", "category": category,
            "source": "test source"}


# Parsing and validation.

class TestParseAndValidate:
    def test_valid_list_parses(self):
        valid, problems, raw = u.parse_and_validate_tor_text(good_fetch(None, None))
        assert len(valid) == 1200
        assert raw == 1200

    def test_comments_and_blanks_skipped(self):
        text = "# header\n\n1.2.3.4\n   \n5.6.7.8\n"
        valid, problems, raw = u.parse_and_validate_tor_text(text)
        assert valid == ["1.2.3.4", "5.6.7.8"]

    def test_duplicates_removed_and_noted(self):
        valid, problems, raw = u.parse_and_validate_tor_text(dup_fetch(None, None))
        assert len(valid) == 1200
        assert raw == 1400
        assert any("duplicate" in p.lower() for p in problems)

    def test_garbage_line_is_a_problem(self):
        valid, problems, raw = u.parse_and_validate_tor_text("1.2.3.4\ngarbage\n5.6.7.8")
        assert "1.2.3.4" in valid
        assert any("not a valid address" in p for p in problems)

    def test_below_minimum_flagged(self):
        valid, problems, raw = u.parse_and_validate_tor_text(truncated_fetch(None, None))
        assert len(valid) == 10
        assert any("below" in p for p in problems)

    def test_ipv6_addresses_accepted(self):
        text = "\n".join(["2001:db8::%x" % i for i in range(1, 150)])
        valid, problems, raw = u.parse_and_validate_tor_text(text)
        assert len(valid) == 149


class TestWebPageDetection:
    def test_html_detected(self):
        assert u.looks_like_web_page(html_fetch(None, None)) is True

    def test_plain_list_not_html(self):
        assert u.looks_like_web_page("1.2.3.4\n5.6.7.8") is False

    def test_leading_whitespace_html_detected(self):
        assert u.looks_like_web_page("\n\n   <html><body>x</body></html>") is True


# Atomic write.

class TestAtomicWrite:
    def test_writes_lines(self, tmp_dir):
        target = os.path.join(tmp_dir, "out.txt")
        u.atomic_write_lines(target, ["1.1.1.1", "2.2.2.2"])
        with open(target, encoding="utf-8") as handle:
            content = handle.read().splitlines()
        assert content == ["1.1.1.1", "2.2.2.2"]

    def test_overwrites_existing(self, tmp_dir):
        target = os.path.join(tmp_dir, "out.txt")
        u.atomic_write_lines(target, ["old"])
        u.atomic_write_lines(target, ["new1", "new2"])
        with open(target, encoding="utf-8") as handle:
            content = handle.read().splitlines()
        assert content == ["new1", "new2"]


# Tor refresh, the core safety behavior.

class TestRefreshTorList:
    def test_successful_refresh_installs_and_stamps(self, tmp_dir):
        result = u.refresh_tor_list(tmp_dir, fetcher=good_fetch)
        assert result["ok"] is True
        assert result["installed"] is True
        assert result["count"] == 1200
        target = os.path.join(tmp_dir, u.TOR_RELATIVE)
        assert os.path.exists(target)
        with open(os.path.join(tmp_dir, u.TOR_META_RELATIVE), encoding="utf-8") as handle:
            meta = json.load(handle)
        assert meta["entry_count"] == 1200
        assert meta["sha256"]
        assert meta["fetched_at"]
        assert meta["validated_at"]
        assert meta["source"] == u.TOR_EXIT_LIST_URL

    def test_meta_hash_matches_installed_file(self, tmp_dir):
        result = u.refresh_tor_list(tmp_dir, fetcher=good_fetch)
        import hashlib
        with open(os.path.join(tmp_dir, u.TOR_RELATIVE), "rb") as handle:
            body = handle.read()
        assert result["sha256"] == hashlib.sha256(body).hexdigest()

    def test_duplicates_not_written(self, tmp_dir):
        u.refresh_tor_list(tmp_dir, fetcher=dup_fetch)
        with open(os.path.join(tmp_dir, u.TOR_RELATIVE), encoding="utf-8") as handle:
            lines = [l for l in handle.read().splitlines() if l]
        assert len(lines) == len(set(lines))
        assert len(lines) == 1200

    def test_truncated_download_keeps_old_list(self, tmp_dir):
        u.refresh_tor_list(tmp_dir, fetcher=good_fetch)
        target = os.path.join(tmp_dir, u.TOR_RELATIVE)
        before = read_text(target)
        result = u.refresh_tor_list(tmp_dir, fetcher=truncated_fetch)
        after = read_text(target)
        assert result["ok"] is False
        assert result["installed"] is False
        assert before == after

    def test_network_error_keeps_old_list(self, tmp_dir):
        u.refresh_tor_list(tmp_dir, fetcher=good_fetch)
        target = os.path.join(tmp_dir, u.TOR_RELATIVE)
        before = read_text(target)
        result = u.refresh_tor_list(tmp_dir, fetcher=error_fetch)
        after = read_text(target)
        assert result["ok"] is False
        assert before == after
        assert "Download failed" in result["detail"]

    def test_html_response_rejected_keeps_old_list(self, tmp_dir):
        u.refresh_tor_list(tmp_dir, fetcher=good_fetch)
        target = os.path.join(tmp_dir, u.TOR_RELATIVE)
        before = read_text(target)
        result = u.refresh_tor_list(tmp_dir, fetcher=html_fetch)
        after = read_text(target)
        assert result["ok"] is False
        assert before == after
        # The failure must explain the unexpected content, not just report a generic error.
        assert "web page" in result["detail"]
        assert any("HTML" in p for p in result["problems"])

    def test_dry_run_validates_without_writing(self, tmp_dir):
        result = u.refresh_tor_list(tmp_dir, fetcher=good_fetch, dry_run=True)
        assert result["ok"] is True
        assert result["installed"] is False
        assert result["dry_run"] is True
        assert result["count"] == 1200
        assert result["sha256"]
        assert not os.path.exists(os.path.join(tmp_dir, u.TOR_RELATIVE))
        assert not os.path.exists(os.path.join(tmp_dir, u.TOR_META_RELATIVE))


# Credentialed database reporting.

class TestCredentialedDatabaseCheck:
    def test_missing_requires_manual_action(self, tmp_dir):
        result = u.check_credentialed_database(
            os.path.join(tmp_dir, "missing.mmdb"), "GeoLite2 City", u.MAXMIND_INSTRUCTIONS)
        assert result["present"] is False
        assert result["manual_action_required"] is True
        assert result["instructions"]

    def test_present_and_fresh_no_action(self, tmp_dir):
        path = os.path.join(tmp_dir, "fresh.bin")
        open(path, "w").write("data")
        result = u.check_credentialed_database(path, "IP2Proxy", u.IP2PROXY_INSTRUCTIONS)
        assert result["present"] is True
        assert result["manual_action_required"] is False
        assert result["instructions"] == ""

    def test_present_but_stale_requires_action(self, tmp_dir):
        path = os.path.join(tmp_dir, "stale.bin")
        open(path, "w").write("data")
        old = u.datetime.now(u.timezone.utc).timestamp() - (u.STALE_AFTER_DAYS + 5) * 86400
        os.utime(path, (old, old))
        result = u.check_credentialed_database(path, "GeoLite2 ASN", u.MAXMIND_INSTRUCTIONS)
        assert result["present"] is True
        assert result["stale"] is True
        assert result["manual_action_required"] is True


# Authority file gate.

class TestAuthorityValidation:
    def test_valid_authority_passes(self, tmp_dir):
        write_asn_authority(tmp_dir, [
            valid_authority_entry(14061, "hosting-datacenter"),
            valid_authority_entry(9009, "known-vpn"),
        ])
        result = u.validate_authority_file(tmp_dir)
        assert result["ok"] is True

    def test_bad_category_fails(self, tmp_dir):
        write_asn_authority(tmp_dir, [valid_authority_entry(7922, "residential-isp")])
        result = u.validate_authority_file(tmp_dir)
        assert result["ok"] is False
        assert result["errors"]

    def test_duplicate_asn_fails(self, tmp_dir):
        write_asn_authority(tmp_dir, [
            valid_authority_entry(9009, "known-vpn"),
            valid_authority_entry(9009, "hosting-datacenter"),
        ])
        result = u.validate_authority_file(tmp_dir)
        assert result["ok"] is False
        assert any("duplicate" in e.lower() for e in result["errors"])

    def test_absent_authority_is_acceptable(self, tmp_dir):
        result = u.validate_authority_file(tmp_dir)
        assert result["ok"] is True
        assert result["present"] is False


# Full orchestration and exit codes.

class TestRunRefreshAndExitCodes:
    def test_full_report_structure(self, tmp_dir):
        report = u.run_refresh(tmp_dir, fetcher=good_fetch)
        names = [s["step"] for s in report["steps"]]
        assert "tor_exit_list" in names
        assert "GeoLite2 City database" in names
        assert "IP2Proxy LITE database" in names
        assert "asn_authority" in names

    def test_tor_only_skips_db_checks(self, tmp_dir):
        report = u.run_refresh(tmp_dir, tor_only=True, fetcher=good_fetch)
        names = [s["step"] for s in report["steps"]]
        assert "GeoLite2 City database" not in names

    def test_skip_validate_skips_authority(self, tmp_dir):
        report = u.run_refresh(tmp_dir, skip_validate=True, fetcher=good_fetch)
        names = [s["step"] for s in report["steps"]]
        assert "asn_authority" not in names

    def test_exit_code_zero_on_success(self, tmp_dir):
        report = u.run_refresh(tmp_dir, fetcher=good_fetch)
        assert u._print_report(report) == 0

    def test_exit_code_nonzero_on_tor_failure(self, tmp_dir):
        report = u.run_refresh(tmp_dir, fetcher=error_fetch)
        assert u._print_report(report) == 2

    def test_exit_code_nonzero_on_bad_authority(self, tmp_dir):
        write_asn_authority(tmp_dir, [valid_authority_entry(1, "bad-category")])
        report = u.run_refresh(tmp_dir, fetcher=good_fetch)
        assert u._print_report(report) == 2

    def test_dry_run_writes_nothing_through_run_refresh(self, tmp_dir):
        u.run_refresh(tmp_dir, fetcher=good_fetch, dry_run=True)
        assert not os.path.exists(os.path.join(tmp_dir, u.TOR_RELATIVE))
        assert not os.path.exists(os.path.join(tmp_dir, u.TOR_META_RELATIVE))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))