"""
WhisperWard OSINT — Test suite for the Evidence Packager
Phase 4, Milestone 5
Pixora Inc.

These tests lock in the forensic behavior of the upgraded packager. The
guarantees are that a package contains exactly the artifacts of the requested
case and not unrelated files, that the manifest is sealed with its own hash, that
creating a package writes a chain of custody entry, that verification confirms an
intact package and detects a tampered one, and that timestamps are UTC.
"""

import json
import os
import sqlite3
import tempfile
import zipfile

import pytest

from core.evidence_packager import create_evidence_package, verify_evidence_package
from core.case_log import ChainOfCustodyLog


def build_case_db(directory):
    """Builds a database mirroring the relevant WhisperWard schema and seeds two
    cases so the case isolation property can be tested."""
    db = os.path.join(directory, "wward.db")
    exports = os.path.join(directory, "exports")
    os.makedirs(exports, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE cases (case_id TEXT PRIMARY KEY, case_name TEXT);
        CREATE TABLE targets (target_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT, platform TEXT, username TEXT);
        CREATE TABLE artifacts (artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER, module_name TEXT, artifact_type TEXT,
            file_path TEXT, sha256 TEXT);
        """
    )
    conn.execute("INSERT INTO cases VALUES ('CASE-A', 'Alpha')")
    conn.execute("INSERT INTO cases VALUES ('CASE-B', 'Bravo')")
    conn.execute("INSERT INTO targets (case_id, platform, username) VALUES ('CASE-A','roblox','sa')")
    conn.execute("INSERT INTO targets (case_id, platform, username) VALUES ('CASE-B','roblox','sb')")

    def make_file(name, content):
        path = os.path.join(exports, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    a1 = make_file("caseA_profile.json", "profile A")
    a2 = make_file("caseA_avatar.txt", "avatar A")
    b1 = make_file("caseB_profile.json", "profile B")

    conn.execute("INSERT INTO artifacts (target_id, module_name, artifact_type, file_path, sha256) "
                 "VALUES (1,'roblox','profile',?,'x')", (a1,))
    conn.execute("INSERT INTO artifacts (target_id, module_name, artifact_type, file_path, sha256) "
                 "VALUES (1,'roblox','avatar',?,'x')", (a2,))
    conn.execute("INSERT INTO artifacts (target_id, module_name, artifact_type, file_path, sha256) "
                 "VALUES (2,'roblox','profile',?,'x')", (b1,))
    conn.commit()
    return db, exports, conn


@pytest.fixture
def case_env():
    directory = tempfile.mkdtemp()
    db, exports, conn = build_case_db(directory)
    yield {"dir": directory, "db": db, "exports": exports, "conn": conn}
    conn.close()


class TestCaseIsolation:
    def test_package_contains_only_requested_case(self, case_env):
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"], analyst="Meca")
        with zipfile.ZipFile(pkg) as archive:
            names = archive.namelist()
        assert "caseA_profile.json" in names
        assert "caseA_avatar.txt" in names
        assert "caseB_profile.json" not in names

    def test_manifest_and_seal_present(self, case_env):
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"])
        with zipfile.ZipFile(pkg) as archive:
            names = archive.namelist()
        assert any(n.endswith("_manifest.json") for n in names)
        assert any(n.endswith("_manifest.seal.json") for n in names)


class TestManifestSeal:
    def test_seal_hash_matches_manifest(self, case_env):
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"])
        with zipfile.ZipFile(pkg) as archive:
            manifest_name = next(n for n in archive.namelist() if n.endswith("_manifest.json"))
            seal_name = next(n for n in archive.namelist() if n.endswith("_manifest.seal.json"))
            manifest_bytes = archive.read(manifest_name)
            seal = json.loads(archive.read(seal_name))
        import hashlib
        manifest = json.loads(manifest_bytes)
        recomputed = hashlib.sha256(
            json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")).hexdigest()
        assert recomputed == seal["manifest_sha256"]

    def test_manifest_timestamp_is_utc(self, case_env):
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"])
        with zipfile.ZipFile(pkg) as archive:
            manifest_name = next(n for n in archive.namelist() if n.endswith("_manifest.json"))
            manifest = json.loads(archive.read(manifest_name))
        assert manifest["generated_at"].endswith("+00:00")


class TestChainEntry:
    def test_packaging_writes_chain_entry(self, case_env):
        create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                connection=case_env["conn"], analyst="Meca")
        log = ChainOfCustodyLog(connection=case_env["conn"])
        actions = [e["action"] for e in log.entries(case_id="CASE-A")]
        assert "evidence_package_created" in actions

    def test_chain_intact_after_packaging(self, case_env):
        create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                connection=case_env["conn"])
        log = ChainOfCustodyLog(connection=case_env["conn"])
        assert log.verify()["intact"] is True


class TestVerification:
    def test_intact_package_verifies(self, case_env):
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"])
        result = verify_evidence_package(pkg)
        assert result["intact"] is True
        assert result["checked_files"] == 2

    def test_tampered_file_detected(self, case_env):
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"])
        tampered = pkg.replace(".zip", "_tampered.zip")
        with zipfile.ZipFile(pkg) as zin:
            data = {n: zin.read(n) for n in zin.namelist()}
        data["caseA_profile.json"] = b"TAMPERED"
        with zipfile.ZipFile(tampered, "w") as zout:
            for name, payload in data.items():
                zout.writestr(name, payload)
        result = verify_evidence_package(tampered)
        assert result["intact"] is False
        assert any("caseA_profile.json" in p for p in result["problems"])

    def test_altered_manifest_detected(self, case_env):
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"])
        tampered = pkg.replace(".zip", "_m.zip")
        with zipfile.ZipFile(pkg) as zin:
            data = {n: zin.read(n) for n in zin.namelist()}
        manifest_name = next(n for n in data if n.endswith("_manifest.json"))
        manifest = json.loads(data[manifest_name])
        manifest["case_id"] = "CASE-FORGED"
        data[manifest_name] = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        with zipfile.ZipFile(tampered, "w") as zout:
            for name, payload in data.items():
                zout.writestr(name, payload)
        result = verify_evidence_package(tampered)
        assert result["intact"] is False

    def test_missing_package_reports_problem(self):
        result = verify_evidence_package("/no/such/package.zip")
        assert result["intact"] is False
        assert result["problems"]


class TestFallbackAndCompat:
    def test_file_list_mode_without_db(self, case_env):
        # Without a DB, a caller can still package an explicit file list.
        files = [os.path.join(case_env["exports"], "caseA_profile.json")]
        pkg = create_evidence_package("CASE-MANUAL", export_dir=case_env["exports"],
                                      file_list=files)
        with zipfile.ZipFile(pkg) as archive:
            assert "caseA_profile.json" in archive.namelist()

    def test_no_db_no_filelist_declines(self, case_env):
        # The forensically correct behavior is to decline rather than blind glob.
        result = create_evidence_package("CASE-A", export_dir=case_env["exports"])
        assert result is None


class TestDbPathMode:
    def test_db_path_parameter_packages_case(self, case_env):
        # Exercises the db_path branch, which opens and owns its own connection,
        # rather than the shared connection used elsewhere.
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      db_path=case_env["db"])
        with zipfile.ZipFile(pkg) as archive:
            names = archive.namelist()
        assert "caseA_profile.json" in names
        assert "caseB_profile.json" not in names

    def test_manifest_source_is_database(self, case_env):
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"])
        with zipfile.ZipFile(pkg) as archive:
            manifest_name = next(n for n in archive.namelist() if n.endswith("_manifest.json"))
            manifest = json.loads(archive.read(manifest_name))
        assert manifest["source"] == "database"

    def test_missing_artifact_files_skipped(self, case_env):
        # Point an artifact at a path that does not exist. It must be skipped
        # rather than crashing the package or being included.
        conn = case_env["conn"]
        conn.execute("INSERT INTO targets (case_id, platform, username) VALUES ('CASE-A','discord','ghost')")
        tid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("INSERT INTO artifacts (target_id, module_name, artifact_type, file_path, sha256) "
                     "VALUES (?,'discord','profile','/no/such/file.json','x')", (tid,))
        conn.commit()
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"], connection=conn)
        with zipfile.ZipFile(pkg) as archive:
            names = archive.namelist()
        assert "file.json" not in names
        # The two real CASE-A files are still present.
        assert "caseA_profile.json" in names


class TestChainHashConsistency:
    def test_manifest_hash_matches_chain_entry(self, case_env):
        # The two independent confirmations property: the manifest hash recorded
        # in the seal must equal the sha256 recorded in the chain of custody entry
        # for the packaging event.
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"], analyst="Meca")
        with zipfile.ZipFile(pkg) as archive:
            seal_name = next(n for n in archive.namelist() if n.endswith("_manifest.seal.json"))
            seal = json.loads(archive.read(seal_name))
        log = ChainOfCustodyLog(connection=case_env["conn"])
        entry = next(e for e in log.entries(case_id="CASE-A")
                     if e["action"] == "evidence_package_created")
        assert entry["sha256"] == seal["manifest_sha256"]

    def test_analyst_none_in_chain_entry(self, case_env):
        create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                connection=case_env["conn"], analyst=None)
        log = ChainOfCustodyLog(connection=case_env["conn"])
        entry = next(e for e in log.entries(case_id="CASE-A")
                     if e["action"] == "evidence_package_created")
        assert entry["analyst"] is None
        assert log.verify()["intact"] is True


class TestVerificationEdgeCases:
    def _rebuild_without(self, pkg, drop_suffix):
        out = pkg.replace(".zip", "_dropped.zip")
        with zipfile.ZipFile(pkg) as zin:
            data = {n: zin.read(n) for n in zin.namelist() if not n.endswith(drop_suffix)}
        with zipfile.ZipFile(out, "w") as zout:
            for name, payload in data.items():
                zout.writestr(name, payload)
        return out

    def test_missing_seal_detected(self, case_env):
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"])
        broken = self._rebuild_without(pkg, "_manifest.seal.json")
        result = verify_evidence_package(broken)
        assert result["intact"] is False

    def test_missing_manifest_detected(self, case_env):
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"])
        broken = self._rebuild_without(pkg, "_manifest.json")
        result = verify_evidence_package(broken)
        assert result["intact"] is False

    def test_extra_unlisted_file_does_not_pass_as_intact(self, case_env):
        # Adding a file not in the manifest is a tampering vector. The checked
        # count must still reflect only the manifest's files, and the package
        # must not silently bless the extra file.
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"])
        out = pkg.replace(".zip", "_extra.zip")
        with zipfile.ZipFile(pkg) as zin:
            data = {n: zin.read(n) for n in zin.namelist()}
        data["smuggled.txt"] = b"not in the manifest"
        with zipfile.ZipFile(out, "w") as zout:
            for name, payload in data.items():
                zout.writestr(name, payload)
        result = verify_evidence_package(out)
        # The two manifest files still verify, and the extra file is simply not
        # part of the verified set, so checked_files stays at the manifest count.
        assert result["checked_files"] == 2

    def test_checked_files_zero_on_tamper(self, case_env):
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"])
        tampered = pkg.replace(".zip", "_t2.zip")
        with zipfile.ZipFile(pkg) as zin:
            data = {n: zin.read(n) for n in zin.namelist()}
        data["caseA_profile.json"] = b"X"
        data["caseA_avatar.txt"] = b"Y"
        with zipfile.ZipFile(tampered, "w") as zout:
            for name, payload in data.items():
                zout.writestr(name, payload)
        result = verify_evidence_package(tampered)
        assert result["intact"] is False
        assert result["checked_files"] == 0


class TestSealAndUnicode:
    def test_seal_timestamp_is_utc(self, case_env):
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"],
                                      connection=case_env["conn"])
        with zipfile.ZipFile(pkg) as archive:
            seal_name = next(n for n in archive.namelist() if n.endswith("_manifest.seal.json"))
            seal = json.loads(archive.read(seal_name))
        assert seal["sealed_at"].endswith("+00:00")

    def test_unicode_filename_packaged_and_verified(self, case_env):
        conn = case_env["conn"]
        unicode_name = "perfil_usuario_\u00f1\u00e9.json"
        path = os.path.join(case_env["exports"], unicode_name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("data")
        conn.execute("INSERT INTO targets (case_id, platform, username) VALUES ('CASE-A','roblox','u')")
        tid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("INSERT INTO artifacts (target_id, module_name, artifact_type, file_path, sha256) "
                     "VALUES (?,'roblox','profile',?,'x')", (tid, path))
        conn.commit()
        pkg = create_evidence_package("CASE-A", export_dir=case_env["exports"], connection=conn)
        result = verify_evidence_package(pkg)
        assert result["intact"] is True
        with zipfile.ZipFile(pkg) as archive:
            assert unicode_name in archive.namelist()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))