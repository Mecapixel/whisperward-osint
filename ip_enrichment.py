"""
WhisperWard OSINT — IP Enrichment and Anonymization Detection
Phase 4, Milestone 4
Pixora Inc.

This module enriches IP addresses that an investigator has already entered into
a case. It never harvests addresses on its own, and the public Roblox and Discord
APIs that WhisperWard consumes do not expose them, so every address reaching this
module arrives by deliberate analyst entry. That intake boundary is recorded in
the governance documentation and is the reason this module is ethically clean.

Every lookup is performed entirely offline against local databases. No suspect
address is ever transmitted to a third party during enrichment. The only network
activity associated with this capability lives in a separate script,
update_threat_lists.py, which refreshes public threat lists between cases and
sends no case data when it runs. During actual casework, an address never leaves
the machine.

For each address the module resolves geolocation (country, region, city,
latitude and longitude with an accuracy radius), network ownership (autonomous
system number and organization), and a network type classification drawn from a
fixed vocabulary. It then composes an anonymization confidence score from zero to
one hundred, where the number is built from itemized signal contributions rather
than estimated, and attaches a prose rationale naming exactly which indicators
produced the score. A derived boolean is provided for convenience, but the score
is the source of truth.

The module degrades gracefully. If a database file or its supporting library is
missing, the source is marked unavailable, its absence is recorded on the result
and in the custody record, and enrichment continues with whatever remains. A
missing database lowers completeness, never crashes a case run.

The curated ASN file is the one deliberate exception to graceful degradation, and
this is an intentional hard-fail policy rather than an implementation detail. That
file is treated as an authority, not a reference list. The only categories the
engine will assert are known-vpn and hosting-datacenter, declared once in
RECOGNIZED_ASN_CATEGORIES. A missing ASN file still degrades gracefully, because
absence is not an authoring error. A file that is present but contains an
unrecognized category is an authoring error in authoritative data, and in strict
mode, the default, that stops the whole enricher from constructing so the pipeline
refuses to start against malformed authority data rather than asserting something
it should not. The distinction is missing equals degrade, malformed equals stop.
The discipline that makes this safe is running the standalone validator,
validate_asn_set, after every edit to the file and before a case run, which is why
that validator exists separately from the enricher. A caller that prefers the
softer behavior can set strict_asn_categories to false, in which case a malformed
file is refused with an invalid-category source status and the rest of the module
stays alive without the ASN signal.

Output is structured as JSON for direct downstream consumption by the risk engine
and the evidence packager. Every lookup produces a chain of custody record that
captures the UTC timestamp, the input address, the complete output, and the
version, age, and SHA-256 hash of every database consulted, along with a list of
any sources that were absent at the time of the lookup.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional


# Guarded imports. The module must load and run in a degraded state even when the
# optional geolocation and proxy libraries are not installed, so import failures
# are caught here and surfaced later as unavailable sources rather than crashes.
try:
    import geoip2.database as _geoip2_database
    import geoip2.errors as _geoip2_errors
    _GEOIP2_AVAILABLE = True
except Exception:
    _geoip2_database = None
    _geoip2_errors = None
    _GEOIP2_AVAILABLE = False

try:
    import IP2Proxy as _IP2Proxy
    _IP2PROXY_AVAILABLE = True
except Exception:
    _IP2Proxy = None
    _IP2PROXY_AVAILABLE = False


# Default locations for the local threat intelligence and geolocation databases.
# Each may be overridden through EnrichmentConfig so the module is portable.
DEFAULT_GEOIP_CITY_PATH = os.path.join("data", "geoip", "GeoLite2-City.mmdb")
DEFAULT_GEOIP_ASN_PATH = os.path.join("data", "geoip", "GeoLite2-ASN.mmdb")
DEFAULT_IP2PROXY_PATH = os.path.join("data", "proxy", "IP2PROXY-LITE-PX11.BIN")
DEFAULT_TOR_EXIT_PATH = os.path.join("data", "threat_intel", "tor_exit_nodes.txt")
DEFAULT_ASN_SET_PATH = os.path.join("data", "threat_intel", "hosting_vpn_asns.json")

# The Tor exit list is considered stale beyond this age. A stale list cannot
# crash a lookup, but the staleness is surfaced so a false negative is visible
# rather than silent.
TOR_LIST_STALE_AFTER_HOURS = 48

# The boolean anonymization flag is derived from the composed score at this
# threshold. The score itself remains the authoritative output.
ANONYMIZATION_FLAG_THRESHOLD = 50

# The curated ASN file is treated as an authority, not a reference list. The only
# categories the engine will assert are declared here in one place so the policy
# is auditable rather than buried in control flow. A category of known-vpn or
# hosting-datacenter is asserted and scored. Any other category in the file is an
# authoring error. In strict mode, the default, a file containing an unrecognized
# category fails to load loudly at construction so the pipeline refuses to start
# against a malformed authority database rather than asserting something it should
# not. A missing file is a different case and degrades gracefully, because absence
# is not an authoring error.
RECOGNIZED_ASN_CATEGORIES = ("known-vpn", "hosting-datacenter")

# Confidence contributions per signal, on the zero to one hundred scale. These
# values are intentionally additive and documented so any score can be traced
# back to the exact indicators that produced it.
SIGNAL_WEIGHTS = {
    "tor_exit_list": 60,
    "ip2proxy_tor": 55,
    "ip2proxy_vpn": 40,
    "asn_set_known_vpn": 40,
    "ip2proxy_public_proxy": 35,
    "ip2proxy_residential_proxy": 35,
    "ip2proxy_datacenter": 35,
    "asn_set_hosting_datacenter": 30,
    "ip2proxy_web_proxy": 30,
    "anomaly_trigger": 15,
}


class InvalidASNCategoryError(ValueError):
    """Raised when the curated ASN authority file contains a category outside the
    recognized set and strict mode is in effect. The message names every
    offending entry so the authoring mistake is immediately fixable."""


class NetworkType(str, Enum):
    """The fixed vocabulary for network classification. The suspicious value is a
    deliberate catch all for addresses that do not fit any clean category but
    exhibit anomalous characteristics, so that an unusual address is labelled
    rather than silently forced into residential."""

    RESIDENTIAL = "residential"
    MOBILE = "mobile"
    HOSTING_DATACENTER = "hosting-datacenter"
    TOR_EXIT = "tor-exit"
    KNOWN_VPN = "known-vpn"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class SourceStatus(str, Enum):
    """Per source availability, recorded on every result and in the custody
    record so a degraded lookup is auditable after the fact."""

    AVAILABLE = "available"
    MISSING_FILE = "missing-file"
    MISSING_LIBRARY = "missing-library"
    LOAD_ERROR = "load-error"
    INVALID_CATEGORY = "invalid-category"


@dataclass
class SourceMetadata:
    """Provenance for a single local database. The SHA-256 hash is what allows a
    result to be proven months later against the exact data that produced it."""

    name: str
    status: str
    path: Optional[str] = None
    sha256: Optional[str] = None
    fetched_at: Optional[str] = None
    age_hours: Optional[float] = None
    detail: Optional[str] = None


@dataclass
class GeoLocation:
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius_km: Optional[int] = None


@dataclass
class NetworkInfo:
    asn: Optional[int] = None
    organization: Optional[str] = None


@dataclass
class AnonymizationAssessment:
    confidence: int = 0
    is_anonymized: bool = False
    signals: list = field(default_factory=list)
    rationale: str = ""


@dataclass
class EnrichmentResult:
    ip: str
    is_public: bool
    network_type: str
    geolocation: GeoLocation
    network: NetworkInfo
    anonymization: AnonymizationAssessment
    source_metadata: list = field(default_factory=list)
    degraded_sources: list = field(default_factory=list)
    enriched_at: str = ""
    note: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def _sha256_file(path: str) -> Optional[str]:
    """Returns the SHA-256 of a file, reading in chunks so a large database does
    not have to be held in memory. Returns None if the file cannot be read."""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return None


def _file_age_hours(path: str) -> Optional[float]:
    """Returns the age of a file in hours based on its modification time, used to
    surface threat list staleness."""
    try:
        mtime = os.path.getmtime(path)
        delta = datetime.now(timezone.utc).timestamp() - mtime
        return round(delta / 3600.0, 2)
    except Exception:
        return None


def _file_mtime_iso(path: str) -> Optional[str]:
    try:
        mtime = os.path.getmtime(path)
        return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
    except Exception:
        return None


def validate_asn_set_data(raw) -> list:
    """Validates already parsed ASN authority data held in memory. Returns a list
    of human readable error strings, empty when the data is clean. This is the
    single place the category policy is enforced, so both the loader and the
    standalone preflight share identical rules and the file is parsed only once
    per use."""
    errors = []
    entries = raw.get("asns", raw) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        return ["ASN authority file does not contain a list of entries."]

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append("Entry " + str(index) + " is not an object.")
            continue
        if entry.get("asn") is None:
            errors.append("Entry " + str(index) + " is missing an asn value.")
        category = entry.get("category")
        if category not in RECOGNIZED_ASN_CATEGORIES:
            errors.append(
                "Entry " + str(index) + " (asn " + str(entry.get("asn"))
                + ") has unrecognized category '" + str(category)
                + "'. Recognized categories are " + " and ".join(RECOGNIZED_ASN_CATEGORIES) + ".")
    return errors


def validate_asn_set(path: str) -> list:
    """Validates a curated ASN authority file by path without constructing an
    enricher, opening and parsing the file once and delegating the category rules
    to validate_asn_set_data. Returns a list of human readable error strings,
    empty when the file is clean. Intended for a pre flight check, for
    update_threat_lists.py, or for tests, so a malformed authority file can be
    caught before any case run begins.

    A missing file is reported as a single error here because a caller asking to
    validate a specific path expects that path to exist. The enricher itself
    treats a missing file as graceful degradation rather than an error."""
    if not os.path.exists(path):
        return ["ASN authority file not found at " + path]
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except Exception as exc:
        return ["ASN authority file could not be parsed as JSON: " + str(exc)]
    return validate_asn_set_data(raw)


@dataclass
class EnrichmentConfig:
    """All database paths and tunable thresholds in one place so the module is
    portable and so tests can point at fixture files. strict_asn_categories
    governs authority behavior. When true, the default, a present ASN file
    containing an unrecognized category raises InvalidASNCategoryError at
    construction. When false, such a file is refused with an invalid-category
    source status and enrichment continues without the ASN signal."""

    geoip_city_path: str = DEFAULT_GEOIP_CITY_PATH
    geoip_asn_path: str = DEFAULT_GEOIP_ASN_PATH
    ip2proxy_path: str = DEFAULT_IP2PROXY_PATH
    tor_exit_path: str = DEFAULT_TOR_EXIT_PATH
    asn_set_path: str = DEFAULT_ASN_SET_PATH
    flag_threshold: int = ANONYMIZATION_FLAG_THRESHOLD
    tor_stale_after_hours: int = TOR_LIST_STALE_AFTER_HOURS
    strict_asn_categories: bool = True


class IPEnricher:
    """Loads the available local databases once and enriches addresses against
    them. Construct it once per case run and reuse it across lookups so the
    databases and their hashes are not recomputed for every address.

    An optional custody_logger callable may be supplied. When present it is
    invoked with the custody record dictionary for every lookup, which lets the
    existing evidence and chain of custody subsystem record enrichment without
    this module needing to know that subsystem's internals."""

    def __init__(
        self,
        config: Optional[EnrichmentConfig] = None,
        custody_logger: Optional[Callable[[dict], None]] = None,
    ):
        self.config = config or EnrichmentConfig()
        self.custody_logger = custody_logger

        self._geoip_city_reader = None
        self._geoip_asn_reader = None
        self._ip2proxy_reader = None
        self._tor_exits: set = set()
        self._asn_set: dict = {}

        # Provenance for each source is captured at load time so it can be copied
        # onto every result and into every custody record without recomputation.
        self._source_meta: dict = {}

        self._load_geoip_city()
        self._load_geoip_asn()
        self._load_ip2proxy()
        self._load_tor_exits()
        self._load_asn_set()

    # Loading. Each loader records a SourceMetadata entry describing whether the
    # source came up available, was missing its file, was missing its library, or
    # failed to load, and stamps the hash and age where a file exists.

    def _record_source(self, name: str, status: str, path: Optional[str] = None,
                       detail: Optional[str] = None, hash_file: bool = True):
        meta = SourceMetadata(name=name, status=status, path=path, detail=detail)
        if path and os.path.exists(path):
            if hash_file:
                meta.sha256 = _sha256_file(path)
            meta.fetched_at = _file_mtime_iso(path)
            meta.age_hours = _file_age_hours(path)
        self._source_meta[name] = meta

    def _load_geoip_city(self):
        name = "geolite2_city"
        if not _GEOIP2_AVAILABLE:
            self._record_source(name, SourceStatus.MISSING_LIBRARY.value,
                                detail="geoip2 package not installed")
            return
        path = self.config.geoip_city_path
        if not os.path.exists(path):
            self._record_source(name, SourceStatus.MISSING_FILE.value, path=path)
            return
        try:
            self._geoip_city_reader = _geoip2_database.Reader(path)
            self._record_source(name, SourceStatus.AVAILABLE.value, path=path)
        except Exception as exc:
            self._record_source(name, SourceStatus.LOAD_ERROR.value, path=path,
                                detail=str(exc))

    def _load_geoip_asn(self):
        name = "geolite2_asn"
        if not _GEOIP2_AVAILABLE:
            self._record_source(name, SourceStatus.MISSING_LIBRARY.value,
                                detail="geoip2 package not installed")
            return
        path = self.config.geoip_asn_path
        if not os.path.exists(path):
            self._record_source(name, SourceStatus.MISSING_FILE.value, path=path)
            return
        try:
            self._geoip_asn_reader = _geoip2_database.Reader(path)
            self._record_source(name, SourceStatus.AVAILABLE.value, path=path)
        except Exception as exc:
            self._record_source(name, SourceStatus.LOAD_ERROR.value, path=path,
                                detail=str(exc))

    def _load_ip2proxy(self):
        name = "ip2proxy_lite"
        if not _IP2PROXY_AVAILABLE:
            self._record_source(name, SourceStatus.MISSING_LIBRARY.value,
                                detail="IP2Proxy package not installed")
            return
        path = self.config.ip2proxy_path
        if not os.path.exists(path):
            self._record_source(name, SourceStatus.MISSING_FILE.value, path=path)
            return
        try:
            reader = _IP2Proxy.IP2Proxy()
            reader.open(path)
            self._ip2proxy_reader = reader
            self._record_source(name, SourceStatus.AVAILABLE.value, path=path)
        except Exception as exc:
            self._record_source(name, SourceStatus.LOAD_ERROR.value, path=path,
                                detail=str(exc))

    def _load_tor_exits(self):
        name = "tor_exit_list"
        path = self.config.tor_exit_path
        if not os.path.exists(path):
            self._record_source(name, SourceStatus.MISSING_FILE.value, path=path)
            return
        try:
            exits = set()
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    candidate = line.strip()
                    if not candidate or candidate.startswith("#"):
                        continue
                    exits.add(candidate)
            self._tor_exits = exits
            self._record_source(name, SourceStatus.AVAILABLE.value, path=path)
        except Exception as exc:
            self._record_source(name, SourceStatus.LOAD_ERROR.value, path=path,
                                detail=str(exc))

    def _load_asn_set(self):
        name = "hosting_vpn_asns"
        path = self.config.asn_set_path
        if not os.path.exists(path):
            # Absence is graceful degradation, not an authoring error.
            self._record_source(name, SourceStatus.MISSING_FILE.value, path=path)
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except Exception as exc:
            self._record_source(name, SourceStatus.LOAD_ERROR.value, path=path,
                                detail=str(exc))
            return

        # A present file is treated as an authority and validated before use. The
        # already parsed data is validated in memory so the file is read only once.
        # An unrecognized category is an authoring mistake. The invalid-category
        # source status is recorded in both modes so provenance is preserved even
        # when strict mode then aborts the run. In strict mode the run stops loudly.
        # Otherwise the set is refused and enrichment proceeds without the ASN
        # signal, with the gap visible in the source metadata.
        errors = validate_asn_set_data(raw)
        if errors:
            detail = " ".join(errors)
            self._record_source(name, SourceStatus.INVALID_CATEGORY.value,
                                path=path, detail=detail)
            if self.config.strict_asn_categories:
                raise InvalidASNCategoryError(
                    "The curated ASN authority file at " + path
                    + " contains unrecognized categories and was rejected. " + detail)
            return

        try:
            entries = raw.get("asns", raw) if isinstance(raw, dict) else raw
            mapping = {}
            for entry in entries:
                asn = entry.get("asn")
                if asn is None:
                    continue
                mapping[int(asn)] = {
                    "organization": entry.get("organization", ""),
                    "category": entry.get("category"),
                    "source": entry.get("source", ""),
                }
            self._asn_set = mapping
            self._record_source(name, SourceStatus.AVAILABLE.value, path=path)
        except Exception as exc:
            self._record_source(name, SourceStatus.LOAD_ERROR.value, path=path,
                                detail=str(exc))

    # Per source query helpers. Each returns None or an empty result when its
    # source is unavailable, so the caller can treat absence uniformly.

    def _query_geoip_city(self, ip: str) -> GeoLocation:
        geo = GeoLocation()
        if self._geoip_city_reader is None:
            return geo
        try:
            response = self._geoip_city_reader.city(ip)
            geo.country = response.country.name
            geo.country_code = response.country.iso_code
            geo.region = response.subdivisions.most_specific.name
            geo.city = response.city.name
            geo.latitude = response.location.latitude
            geo.longitude = response.location.longitude
            geo.accuracy_radius_km = response.location.accuracy_radius
        except Exception:
            # An address absent from the database is a normal outcome, not an error.
            return geo
        return geo

    def _query_geoip_asn(self, ip: str) -> NetworkInfo:
        net = NetworkInfo()
        if self._geoip_asn_reader is None:
            return net
        try:
            response = self._geoip_asn_reader.asn(ip)
            net.asn = response.autonomous_system_number
            net.organization = response.autonomous_system_organization
        except Exception:
            return net
        return net

    def _query_ip2proxy(self, ip: str) -> dict:
        if self._ip2proxy_reader is None:
            return {}
        try:
            record = self._ip2proxy_reader.get_all(ip)
            if not isinstance(record, dict):
                return {}
            return record
        except Exception:
            return {}

    # Scoring and classification.

    def _assess(self, ip: str, net: NetworkInfo, proxy: dict) -> tuple:
        """Returns a tuple of network type and an AnonymizationAssessment. The
        confidence is composed additively from named signals, each appended to a
        signals list with its contribution, and the rationale narrates exactly
        which indicators fired."""

        signals = []
        confidence = 0
        on_tor_list = ip in self._tor_exits

        proxy_type = (proxy.get("proxy_type") or "").upper() if proxy else ""
        usage_type = (proxy.get("usage_type") or "").upper() if proxy else ""

        asn_entry = self._asn_set.get(net.asn) if net.asn is not None else None
        asn_category = asn_entry.get("category") if asn_entry else None

        def add(key: str, description: str):
            nonlocal confidence
            weight = SIGNAL_WEIGHTS.get(key, 0)
            confidence += weight
            signals.append({"signal": key, "weight": weight, "detail": description})

        if on_tor_list:
            add("tor_exit_list", "Address is present on the cached Tor exit node list.")
        if proxy_type == "TOR":
            add("ip2proxy_tor", "IP2Proxy classifies this address as a Tor node.")
        if proxy_type == "VPN":
            add("ip2proxy_vpn", "IP2Proxy classifies this address as a VPN endpoint.")
        if proxy_type == "PUB":
            add("ip2proxy_public_proxy", "IP2Proxy classifies this address as a public proxy.")
        if proxy_type == "RES":
            add("ip2proxy_residential_proxy",
                "IP2Proxy classifies this address as a residential proxy, a category that is frequently abused to mask origin.")
        if proxy_type == "WEB":
            add("ip2proxy_web_proxy", "IP2Proxy classifies this address as a web proxy.")
        if proxy_type == "DCH":
            add("ip2proxy_datacenter", "IP2Proxy classifies this address as datacenter or hosting space.")

        if asn_entry is not None:
            org = asn_entry.get("organization", "")
            if asn_category == "known-vpn":
                add("asn_set_known_vpn",
                    "Owning network " + str(net.asn) + " (" + org + ") is on the curated known VPN list.")
            elif asn_category == "hosting-datacenter":
                add("asn_set_hosting_datacenter",
                    "Owning network " + str(net.asn) + " (" + org + ") is on the curated hosting and datacenter list.")
            # Any other category contributes no confidence and is surfaced as an
            # anomaly below rather than being forced into a hosting label.

        # Anomaly detection for addresses that do not match a clean anonymization
        # signal but still look wrong. A residential or ISP usage type that
        # simultaneously sits on a hosting or proxy indicator is the canonical
        # case the suspicious label exists for.
        anomalies = []
        # A usage based conflict requires an actually observed residential or ISP
        # usage type. An empty usage type means IP2Proxy data was absent, not that
        # the address is residential, so absence must never trigger this anomaly or
        # its rationale would assert a usage type that was never observed.
        residential_usage = usage_type in ("ISP", "COM")
        recognized_asn_hosting = asn_category in RECOGNIZED_ASN_CATEGORIES
        has_hosting_signal = recognized_asn_hosting or proxy_type in ("DCH", "RES", "PUB", "WEB")
        if residential_usage and has_hosting_signal and not on_tor_list and proxy_type not in ("VPN", "TOR"):
            anomalies.append("Address presents a residential or ISP usage type while also matching a hosting or proxy indicator, an inconsistent profile.")
        if asn_entry is not None and not recognized_asn_hosting:
            anomalies.append("Owning network " + str(net.asn) + " appears in the curated ASN set with an unrecognized category '" + str(asn_category) + "'. It is not asserted as hosting or VPN, and the list entry warrants manual review.")
        if proxy and proxy_type and proxy_type not in (
            "TOR", "VPN", "PUB", "RES", "WEB", "DCH", "SES", "CDN", "-"
        ):
            anomalies.append("IP2Proxy returned an unrecognized proxy type, which warrants manual review.")
        for description in anomalies:
            add("anomaly_trigger", description)

        confidence = min(confidence, 100)

        # Classification follows a priority order. A Tor signal dominates, then a
        # named VPN, then datacenter or hosting, then mobile, then residential.
        # An ASN only contributes a hosting or VPN label when its curated category
        # is explicitly one of those two values. Anything left with anomaly flags
        # but no clean category is suspicious.
        if on_tor_list or proxy_type == "TOR":
            network_type = NetworkType.TOR_EXIT
        elif proxy_type == "VPN" or asn_category == "known-vpn":
            network_type = NetworkType.KNOWN_VPN
        elif proxy_type == "DCH" or asn_category == "hosting-datacenter":
            network_type = NetworkType.HOSTING_DATACENTER
        elif usage_type == "MOB":
            network_type = NetworkType.MOBILE
        elif anomalies:
            network_type = NetworkType.SUSPICIOUS
        elif net.asn is not None or usage_type in ("ISP", "COM"):
            network_type = NetworkType.RESIDENTIAL
        else:
            network_type = NetworkType.UNKNOWN

        rationale = self._build_rationale(network_type, confidence, signals)
        assessment = AnonymizationAssessment(
            confidence=confidence,
            is_anonymized=confidence >= self.config.flag_threshold,
            signals=signals,
            rationale=rationale,
        )
        return network_type.value, assessment

    def _build_rationale(self, network_type: NetworkType, confidence: int,
                        signals: list) -> str:
        """Produces a prose rationale with no list formatting, suitable for a
        forensic report. When no anonymization signal fired, it says so plainly."""
        if not signals:
            return ("No anonymization indicators fired for this address. It presents as an "
                    "ordinary endpoint based on the data available, classified as "
                    + network_type.value + ". Confidence that the address is anonymized is "
                    + str(confidence) + " out of 100.")
        fragments = [signal["detail"] for signal in signals]
        joined = " ".join(fragments)
        return (joined + " Taken together these indicators classify the address as "
                + network_type.value + " with an anonymization confidence of "
                + str(confidence) + " out of 100. The score is the sum of the named signal "
                "contributions above and a human analyst confirms any conclusion.")

    # Source metadata assembly and staleness surfacing.

    def _result_source_metadata(self) -> tuple:
        meta_list = []
        degraded = []
        for name, meta in self._source_meta.items():
            entry = asdict(meta)
            if name == "tor_exit_list" and meta.status == SourceStatus.AVAILABLE.value:
                if meta.age_hours is not None and meta.age_hours > self.config.tor_stale_after_hours:
                    entry["stale"] = True
                    entry["detail"] = ("Tor exit list is older than the staleness threshold of "
                                       + str(self.config.tor_stale_after_hours)
                                       + " hours. A stale list can produce false negatives. Run "
                                       "update_threat_lists.py between cases to refresh it.")
                else:
                    entry["stale"] = False
            if meta.status != SourceStatus.AVAILABLE.value:
                degraded.append(name)
            meta_list.append(entry)
        return meta_list, degraded

    # Public entry point.

    def enrich(self, ip: str) -> EnrichmentResult:
        """Enriches a single address and returns a structured result. Private,
        loopback, reserved, and malformed addresses short circuit with a note and
        no geolocation, because they cannot be meaningfully resolved and should
        never be sent anywhere."""

        enriched_at = datetime.now(timezone.utc).isoformat()
        source_metadata, degraded = self._result_source_metadata()

        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            result = EnrichmentResult(
                ip=ip,
                is_public=False,
                network_type=NetworkType.UNKNOWN.value,
                geolocation=GeoLocation(),
                network=NetworkInfo(),
                anonymization=AnonymizationAssessment(
                    rationale="The supplied value is not a valid IP address and was not enriched."),
                source_metadata=source_metadata,
                degraded_sources=degraded,
                enriched_at=enriched_at,
                note="invalid-address",
            )
            self._emit_custody(result)
            return result

        if not parsed.is_global:
            result = EnrichmentResult(
                ip=ip,
                is_public=False,
                network_type=NetworkType.UNKNOWN.value,
                geolocation=GeoLocation(),
                network=NetworkInfo(),
                anonymization=AnonymizationAssessment(
                    rationale="The address is private, loopback, or otherwise non global and was not enriched against external geolocation data."),
                source_metadata=source_metadata,
                degraded_sources=degraded,
                enriched_at=enriched_at,
                note="non-global-address",
            )
            self._emit_custody(result)
            return result

        geo = self._query_geoip_city(ip)
        net = self._query_geoip_asn(ip)
        proxy = self._query_ip2proxy(ip)

        network_type, assessment = self._assess(ip, net, proxy)

        result = EnrichmentResult(
            ip=ip,
            is_public=True,
            network_type=network_type,
            geolocation=geo,
            network=net,
            anonymization=assessment,
            source_metadata=source_metadata,
            degraded_sources=degraded,
            enriched_at=enriched_at,
        )
        self._emit_custody(result)
        return result

    def enrich_many(self, ips: list) -> list:
        """Enriches a list of addresses, returning one result per input."""
        return [self.enrich(ip) for ip in ips]

    def _emit_custody(self, result: EnrichmentResult):
        """Builds the chain of custody record and hands it to the configured
        logger if one was supplied. The record captures the timestamp, the input
        address, the complete output, and the provenance of every database that
        was consulted, including any that were absent."""
        if self.custody_logger is None:
            return
        record = {
            "event": "ip_enrichment",
            "timestamp": result.enriched_at,
            "input_ip": result.ip,
            "output": result.to_dict(),
            "databases": result.source_metadata,
            "absent_sources": result.degraded_sources,
        }
        try:
            self.custody_logger(record)
        except Exception:
            # Custody logging must never take down a case run. A logging failure
            # is swallowed here and the enrichment result is still returned.
            pass

    def close(self):
        """Releases database readers. Safe to call more than once."""
        for reader in (self._geoip_city_reader, self._geoip_asn_reader):
            try:
                if reader is not None:
                    reader.close()
            except Exception:
                pass
        try:
            if self._ip2proxy_reader is not None:
                self._ip2proxy_reader.close()
        except Exception:
            pass


if __name__ == "__main__":
    # A small self contained demonstration using addresses reserved for
    # documentation by RFC 5737, so no real address is ever touched. With no
    # databases present this exercises the graceful degradation path and prints
    # structured JSON for each address.
    enricher = IPEnricher()
    for sample in ("203.0.113.10", "198.51.100.4", "192.0.2.1", "10.0.0.5", "not-an-ip"):
        print(enricher.enrich(sample).to_json())
        print("-" * 60)
    enricher.close()