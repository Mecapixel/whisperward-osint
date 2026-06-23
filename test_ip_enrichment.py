"""
WhisperWard OSINT — Test suite for the IP Enrichment module
Phase 4, Milestone 4
Pixora Inc.

These tests lock in the verified behavior of ip_enrichment.py so that a future
edit cannot silently regress it. No test makes a network call. Geolocation and
proxy lookups are exercised through injected fake readers so the full enrich path
runs deterministically, and the curated authority file is validated through
temporary fixture files written for each test.

A note on test addresses. The reserved documentation ranges described in RFC 5737
are treated as non global by Python's ipaddress module and short circuit before
enrichment, so they are used here only to test the short circuit itself. To
exercise the full enrichment path the tests use a globally routable address and
inject fake database readers that return controlled records regardless of the
address, which keeps the classification logic under test rather than the contents
of any real database.
"""

import json
import os
import tempfile
from types import SimpleNamespace

import pytest

import ip_enrichment as module
from ip_enrichment import (
    IPEnricher,
    EnrichmentConfig,
    NetworkInfo,
    NetworkType,
    SourceStatus,
    InvalidASNCategoryError,
    validate_asn_set,
    validate_asn_set_data,
    RECOGNIZED_ASN_CATEGORIES,
)


# A globally routable address used to pass the is_global gate so the injected
# fake readers can be exercised. The fakes ignore the address value.
GLOBAL_IP = "8.8.8.8"


# Fake database readers. Each mimics only the surface the module touches.

class FakeCityReader:
    def __init__(self, **fields):
        self._fields = fields

    def city(self, ip):
        f = self._fields
        location = SimpleNamespace(
            latitude=f.get("latitude"),
            longitude=f.get("longitude"),
            accuracy_radius=f.get("accuracy_radius"),
        )
        country = SimpleNamespace(name=f.get("country"), iso_code=f.get("country_code"))
        subdivisions = SimpleNamespace(
            most_specific=SimpleNamespace(name=f.get("region")))
        city = SimpleNamespace(name=f.get("city"))
        return SimpleNamespace(country=country, subdivisions=subdivisions,
                              city=city, location=location)

    def close(self):
        pass


class FakeASNReader:
    def __init__(self, asn=None, organization=None):
        self._asn = asn
        self._org = organization

    def asn(self, ip):
        return SimpleNamespace(autonomous_system_number=self._asn,
                              autonomous_system_organization=self._org)

    def close(self):
        pass


class FakeIP2Proxy:
    def __init__(self, record):
        self._record = record

    def get_all(self, ip):
        return self._record

    def close(self):
        pass


# Helpers for building enrichers and fixture files.

def make_config(tmp_path, **overrides):
    """Builds a config pointing every database at a nonexistent path by default,
    so a constructed enricher is fully degraded unless a test injects readers or
    points a path at a fixture."""
    base = dict(
        geoip_city_path=os.path.join(tmp_path, "nope-city.mmdb"),
        geoip_asn_path=os.path.join(tmp_path, "nope-asn.mmdb"),
        ip2proxy_path=os.path.join(tmp_path, "nope-proxy.bin"),
        tor_exit_path=os.path.join(tmp_path, "nope-tor.txt"),
        asn_set_path=os.path.join(tmp_path, "nope-asn.json"),
    )
    base.update(overrides)
    return EnrichmentConfig(**base)


def write_asn_file(tmp_path, entries, name="asns.json"):
    path = os.path.join(tmp_path, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"asns": entries}, handle)
    return path


def assess_only(tor_exits=None, asn_set=None, config=None):
    """Returns an enricher with no databases loaded, suitable for unit testing
    the _assess scoring logic with directly injected state."""
    enricher = IPEnricher.__new__(IPEnricher)
    enricher.config = config or EnrichmentConfig()
    enricher._tor_exits = set(tor_exits or [])
    enricher._asn_set = dict(asn_set or {})
    enricher._geoip_city_reader = None
    enricher._geoip_asn_reader = None
    enricher._ip2proxy_reader = None
    enricher._source_meta = {}
    enricher.custody_logger = None
    return enricher


@pytest.fixture
def tmp_path_str():
    with tempfile.TemporaryDirectory() as directory:
        yield directory


# Address gating.

class TestAddressGating:
    def test_invalid_address_is_noted_not_crashed(self, tmp_path_str):
        enricher = IPEnricher(make_config(tmp_path_str))
        result = enricher.enrich("definitely-not-an-ip")
        assert result.note == "invalid-address"
        assert result.is_public is False
        assert result.network_type == NetworkType.UNKNOWN.value

    def test_private_address_short_circuits(self, tmp_path_str):
        enricher = IPEnricher(make_config(tmp_path_str))
        result = enricher.enrich("10.0.0.5")
        assert result.note == "non-global-address"
        assert result.is_public is False

    def test_loopback_short_circuits(self, tmp_path_str):
        enricher = IPEnricher(make_config(tmp_path_str))
        result = enricher.enrich("127.0.0.1")
        assert result.note == "non-global-address"

    def test_documentation_range_is_non_global(self, tmp_path_str):
        enricher = IPEnricher(make_config(tmp_path_str))
        result = enricher.enrich("203.0.113.10")
        assert result.note == "non-global-address"


# Graceful degradation.

class TestGracefulDegradation:
    def test_constructs_with_no_databases(self, tmp_path_str):
        enricher = IPEnricher(make_config(tmp_path_str))
        result = enricher.enrich(GLOBAL_IP)
        assert result.is_public is True
        assert len(result.degraded_sources) >= 1

    def test_missing_sources_recorded(self, tmp_path_str):
        enricher = IPEnricher(make_config(tmp_path_str))
        result = enricher.enrich(GLOBAL_IP)
        by_name = {m["name"]: m for m in result.source_metadata}
        assert "tor_exit_list" in by_name
        assert by_name["tor_exit_list"]["status"] == SourceStatus.MISSING_FILE.value

    def test_no_signals_yields_zero_confidence(self, tmp_path_str):
        enricher = IPEnricher(make_config(tmp_path_str))
        result = enricher.enrich(GLOBAL_IP)
        assert result.anonymization.confidence == 0
        assert result.anonymization.is_anonymized is False


# ASN authority file policy.

class TestASNAuthorityPolicy:
    def test_clean_file_loads_in_strict_mode(self, tmp_path_str):
        path = write_asn_file(tmp_path_str, [
            {"asn": 14061, "organization": "DigitalOcean", "category": "hosting-datacenter"},
            {"asn": 9009, "organization": "M247", "category": "known-vpn"},
        ])
        enricher = IPEnricher(make_config(tmp_path_str, asn_set_path=path))
        assert len(enricher._asn_set) == 2

    def test_bad_category_raises_in_strict_mode(self, tmp_path_str):
        path = write_asn_file(tmp_path_str, [
            {"asn": 7922, "organization": "Comcast", "category": "residential-isp"},
        ])
        with pytest.raises(InvalidASNCategoryError):
            IPEnricher(make_config(tmp_path_str, asn_set_path=path))

    def test_bad_category_degrades_in_lenient_mode(self, tmp_path_str):
        path = write_asn_file(tmp_path_str, [
            {"asn": 7922, "organization": "Comcast", "category": "residential-isp"},
        ])
        enricher = IPEnricher(make_config(
            tmp_path_str, asn_set_path=path, strict_asn_categories=False))
        assert len(enricher._asn_set) == 0
        by_name = {m["name"]: m for m in enricher._result_source_metadata()[0]}
        assert by_name["hosting_vpn_asns"]["status"] == SourceStatus.INVALID_CATEGORY.value

    def test_missing_file_does_not_raise_in_strict_mode(self, tmp_path_str):
        enricher = IPEnricher(make_config(
            tmp_path_str, asn_set_path=os.path.join(tmp_path_str, "absent.json")))
        by_name = {m["name"]: m for m in enricher._result_source_metadata()[0]}
        assert by_name["hosting_vpn_asns"]["status"] == SourceStatus.MISSING_FILE.value

    def test_broken_json_is_load_error_not_crash(self, tmp_path_str):
        path = os.path.join(tmp_path_str, "broken.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{ not valid json ")
        enricher = IPEnricher(make_config(tmp_path_str, asn_set_path=path))
        by_name = {m["name"]: m for m in enricher._result_source_metadata()[0]}
        assert by_name["hosting_vpn_asns"]["status"] == SourceStatus.LOAD_ERROR.value

    def test_missing_category_is_invalid(self, tmp_path_str):
        path = write_asn_file(tmp_path_str, [{"asn": 20001, "organization": "X"}])
        with pytest.raises(InvalidASNCategoryError):
            IPEnricher(make_config(tmp_path_str, asn_set_path=path))


# Standalone validators.

class TestValidators:
    def test_validate_data_accepts_clean(self):
        assert validate_asn_set_data({"asns": [{"asn": 1, "category": "known-vpn"}]}) == []

    def test_validate_data_rejects_unknown_category(self):
        errors = validate_asn_set_data({"asns": [{"asn": 1, "category": "nope"}]})
        assert len(errors) == 1
        assert "nope" in errors[0]

    def test_validate_data_rejects_missing_asn(self):
        errors = validate_asn_set_data({"asns": [{"category": "known-vpn"}]})
        assert any("missing an asn" in e for e in errors)

    def test_validate_data_rejects_non_list(self):
        assert validate_asn_set_data({"asns": "not a list"})

    def test_validate_path_reports_missing_file(self):
        errors = validate_asn_set("/path/does/not/exist.json")
        assert errors and "not found" in errors[0]

    def test_validate_path_reports_broken_json(self, tmp_path_str):
        path = os.path.join(tmp_path_str, "broken.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{ broken ")
        errors = validate_asn_set(path)
        assert errors and "JSON" in errors[0]

    def test_validate_path_accepts_clean_file(self, tmp_path_str):
        path = write_asn_file(tmp_path_str, [
            {"asn": 9009, "category": "known-vpn"}])
        assert validate_asn_set(path) == []

    def test_recognized_categories_constant(self):
        assert set(RECOGNIZED_ASN_CATEGORIES) == {"known-vpn", "hosting-datacenter"}


# Classification and confidence. These are the match, non match, and adversarial
# fixtures that exercise the scoring priority and the composed score.

class TestClassification:
    def test_tor_exit_list_dominates(self):
        enricher = assess_only(tor_exits={GLOBAL_IP})
        network_type, assessment = enricher._assess(GLOBAL_IP, NetworkInfo(asn=1), {})
        assert network_type == NetworkType.TOR_EXIT.value
        assert assessment.confidence >= 60

    def test_ip2proxy_vpn_is_known_vpn(self):
        enricher = assess_only()
        network_type, assessment = enricher._assess(
            GLOBAL_IP, NetworkInfo(asn=1), {"proxy_type": "VPN"})
        assert network_type == NetworkType.KNOWN_VPN.value
        assert assessment.confidence == 40

    def test_known_vpn_asn_is_known_vpn(self):
        asn_set = {9009: {"organization": "M247", "category": "known-vpn"}}
        enricher = assess_only(asn_set=asn_set)
        network_type, assessment = enricher._assess(
            GLOBAL_IP, NetworkInfo(asn=9009), {})
        assert network_type == NetworkType.KNOWN_VPN.value
        assert assessment.confidence == 40

    def test_datacenter_asn_is_hosting(self):
        asn_set = {14061: {"organization": "DigitalOcean", "category": "hosting-datacenter"}}
        enricher = assess_only(asn_set=asn_set)
        network_type, assessment = enricher._assess(
            GLOBAL_IP, NetworkInfo(asn=14061), {})
        assert network_type == NetworkType.HOSTING_DATACENTER.value
        assert assessment.confidence == 30

    def test_clean_residential(self):
        enricher = assess_only()
        network_type, assessment = enricher._assess(
            GLOBAL_IP, NetworkInfo(asn=100), {"usage_type": "ISP"})
        assert network_type == NetworkType.RESIDENTIAL.value
        assert assessment.confidence == 0

    def test_mobile_usage(self):
        enricher = assess_only()
        network_type, assessment = enricher._assess(
            GLOBAL_IP, NetworkInfo(asn=100), {"usage_type": "MOB"})
        assert network_type == NetworkType.MOBILE.value

    def test_no_data_is_unknown(self):
        enricher = assess_only()
        network_type, assessment = enricher._assess(
            GLOBAL_IP, NetworkInfo(asn=None), {})
        assert network_type == NetworkType.UNKNOWN.value

    def test_unrecognized_injected_category_is_suspicious(self):
        # An unrecognized category cannot reach the engine through the strict
        # loader, but if injected directly it must route to suspicious with no
        # false hosting confidence, never silently become hosting.
        asn_set = {7922: {"organization": "Comcast", "category": "residential-isp"}}
        enricher = assess_only(asn_set=asn_set)
        network_type, assessment = enricher._assess(
            GLOBAL_IP, NetworkInfo(asn=7922), {"usage_type": "ISP"})
        assert network_type == NetworkType.SUSPICIOUS.value
        assert assessment.confidence == 15

    def test_real_usage_conflict_fires_anomaly(self):
        asn_set = {14061: {"organization": "DigitalOcean", "category": "hosting-datacenter"}}
        enricher = assess_only(asn_set=asn_set)
        network_type, assessment = enricher._assess(
            GLOBAL_IP, NetworkInfo(asn=14061), {"usage_type": "ISP"})
        signal_names = [s["signal"] for s in assessment.signals]
        assert "anomaly_trigger" in signal_names

    def test_absent_usage_does_not_fire_anomaly(self):
        # Degraded mode with no IP2Proxy data must not invent a usage conflict.
        asn_set = {14061: {"organization": "DigitalOcean", "category": "hosting-datacenter"}}
        enricher = assess_only(asn_set=asn_set)
        network_type, assessment = enricher._assess(
            GLOBAL_IP, NetworkInfo(asn=14061), {})
        signal_names = [s["signal"] for s in assessment.signals]
        assert "anomaly_trigger" not in signal_names
        assert assessment.confidence == 30


class TestConfidenceComposition:
    def test_score_is_capped_at_100(self):
        asn_set = {9009: {"organization": "M247", "category": "known-vpn"}}
        enricher = assess_only(tor_exits={GLOBAL_IP}, asn_set=asn_set)
        network_type, assessment = enricher._assess(
            GLOBAL_IP, NetworkInfo(asn=9009), {"proxy_type": "TOR"})
        assert assessment.confidence == 100

    def test_score_is_sum_of_named_signals(self):
        enricher = assess_only()
        network_type, assessment = enricher._assess(
            GLOBAL_IP, NetworkInfo(asn=1), {"proxy_type": "VPN"})
        total = sum(s["weight"] for s in assessment.signals)
        assert assessment.confidence == min(total, 100)

    def test_flag_derived_at_threshold(self):
        enricher = assess_only(tor_exits={GLOBAL_IP})
        network_type, assessment = enricher._assess(GLOBAL_IP, NetworkInfo(asn=1), {})
        assert assessment.is_anonymized is True

    def test_below_threshold_not_flagged(self):
        asn_set = {14061: {"organization": "DigitalOcean", "category": "hosting-datacenter"}}
        enricher = assess_only(asn_set=asn_set)
        network_type, assessment = enricher._assess(GLOBAL_IP, NetworkInfo(asn=14061), {})
        assert assessment.confidence == 30
        assert assessment.is_anonymized is False


# Custody logging.

class TestCustodyLogging:
    def test_custody_record_emitted(self, tmp_path_str):
        captured = []
        enricher = IPEnricher(make_config(tmp_path_str),
                             custody_logger=lambda record: captured.append(record))
        enricher.enrich(GLOBAL_IP)
        assert len(captured) == 1
        record = captured[0]
        assert record["event"] == "ip_enrichment"
        assert record["input_ip"] == GLOBAL_IP
        assert "output" in record
        assert "databases" in record
        assert "absent_sources" in record
        assert record["timestamp"]

    def test_custody_logger_failure_does_not_crash(self, tmp_path_str):
        def boom(record):
            raise RuntimeError("logger is down")
        enricher = IPEnricher(make_config(tmp_path_str), custody_logger=boom)
        result = enricher.enrich(GLOBAL_IP)
        assert result.ip == GLOBAL_IP

    def test_no_logger_is_fine(self, tmp_path_str):
        enricher = IPEnricher(make_config(tmp_path_str))
        result = enricher.enrich(GLOBAL_IP)
        assert result is not None


# Full path through injected readers, including geolocation output.

class TestFullEnrichPath:
    def _enricher_with_readers(self, tmp_path_str, city=None, asn=None, proxy=None,
                               tor_exits=None):
        enricher = IPEnricher(make_config(tmp_path_str))
        if city is not None:
            enricher._geoip_city_reader = city
        if asn is not None:
            enricher._geoip_asn_reader = asn
        if proxy is not None:
            enricher._ip2proxy_reader = proxy
        enricher._tor_exits = set(tor_exits or [])
        return enricher

    def test_geolocation_fields_populated(self, tmp_path_str):
        city = FakeCityReader(country="United States", country_code="US",
                              region="California", city="Mountain View",
                              latitude=37.4, longitude=-122.0, accuracy_radius=50)
        enricher = self._enricher_with_readers(tmp_path_str, city=city)
        result = enricher.enrich(GLOBAL_IP)
        assert result.geolocation.country == "United States"
        assert result.geolocation.latitude == 37.4
        assert result.geolocation.longitude == -122.0
        assert result.geolocation.accuracy_radius_km == 50

    def test_asn_fields_populated(self, tmp_path_str):
        asn = FakeASNReader(asn=15169, organization="Google LLC")
        enricher = self._enricher_with_readers(tmp_path_str, asn=asn)
        result = enricher.enrich(GLOBAL_IP)
        assert result.network.asn == 15169
        assert result.network.organization == "Google LLC"

    def test_full_vpn_detection_through_readers(self, tmp_path_str):
        proxy = FakeIP2Proxy({"proxy_type": "VPN", "usage_type": "DCH"})
        enricher = self._enricher_with_readers(tmp_path_str, proxy=proxy)
        result = enricher.enrich(GLOBAL_IP)
        assert result.network_type == NetworkType.KNOWN_VPN.value
        assert result.anonymization.confidence == 40

    def test_output_serializes_to_json(self, tmp_path_str):
        enricher = self._enricher_with_readers(tmp_path_str)
        result = enricher.enrich(GLOBAL_IP)
        parsed = json.loads(result.to_json())
        assert parsed["ip"] == GLOBAL_IP
        assert "anonymization" in parsed
        assert "geolocation" in parsed

    def test_enrich_many_returns_one_per_input(self, tmp_path_str):
        enricher = self._enricher_with_readers(tmp_path_str)
        results = enricher.enrich_many([GLOBAL_IP, "1.1.1.1", "10.0.0.1"])
        assert len(results) == 3


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))