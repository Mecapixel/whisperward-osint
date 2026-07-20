"""
WhisperWard — STIX 2.1 Export
Platform Phase 4, Milestone 1
Pixora Inc.

This module lets a WhisperWard case travel in the language threat-intelligence
platforms already speak. The export is deliberately conservative about what it
claims. STIX has vocabulary for asserting adversaries and attacks; WhisperWard
does not make those assertions, so this exporter never emits threat-actor,
malware, attack-pattern, or indicator objects. What a case actually contains is
observed accounts, machine-scored correlation leads with their justification,
and analyst-resolved entities — and that is exactly what the bundle carries:

user-account observables for every target on record; related-to relationships
between accounts for every scored correlation, carrying STIX confidence mapped
from correlation strength and a description that preserves the rationale and
any contradiction note verbatim; identity objects (identity_class "unknown")
for analyst-resolved entities, each stating who promoted it and when; and a
grouping with context "suspicious-activity", the STIX 2.1 construct intended
for material shared out of an ongoing investigation.

Identifiers are deterministic. SCO identifiers follow the STIX 2.1
UUIDv5-from-contributing-properties rule the library implements; SDO and SRO
identifiers are derived with UUIDv5 from a WhisperWard namespace and the
object's stable content, and timestamps come from a caller-supplied as_of
moment. Identical case content therefore produces an identical bundle, which
is what lets a STIX export travel inside a hash-verified evidence package.
"""

from __future__ import annotations

import json
import uuid
from typing import Optional

import stix2

# UUIDv5 namespace for deterministic WhisperWard SDO/SRO identifiers.
WHISPERWARD_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "whisperward.pixora.inc")

TOOL_NAME = "WhisperWard OSINT"

SCOPE_STATEMENT = (
    "Produced by WhisperWard from public-signal investigation data. "
    "Relationships are machine-scored correlation leads with supporting "
    "evidence, not assertions of shared identity. Identity objects record "
    "explicit analyst resolution decisions. No adversary, malware, or attack "
    "assertion is made or implied."
)


def _det_id(object_type: str, *parts: str) -> str:
    """Deterministic STIX identifier: uuid5 over the WhisperWard namespace and
    the object's stable content parts."""
    return object_type + "--" + str(
        uuid.uuid5(WHISPERWARD_NAMESPACE, object_type + "|" + "|".join(parts)))


def _confidence_from_strength(strength: float) -> int:
    """Correlation strength (0..1) mapped to the STIX confidence scale
    (0..100), clamped."""
    return max(0, min(100, int(round(float(strength) * 100))))


class StixExporter:
    """Builds a STIX 2.1 bundle for one case from the evidence store."""

    def __init__(self, as_of: str):
        """as_of: ISO-8601 UTC timestamp applied as created/modified on every
        SDO/SRO, so identical content serializes identically regardless of
        when the export runs. Callers pass the export decision time."""
        self.as_of = as_of

    # ------------------------------------------------------------- build

    def bundle_for_case(self, database, case_id: str) -> stix2.Bundle:
        creator = self._creator_identity()
        objects: list = [creator]

        accounts: dict[str, stix2.UserAccount] = {}
        for target in database.get_case_targets(case_id):
            profile_id = ((target["platform"] or "unknown").lower()
                          + ":" + target["username"])
            accounts[profile_id] = self._user_account(
                platform=(target["platform"] or "unknown").lower(),
                username=target["username"],
                user_id=target.get("platform_user_id"))

        correlation = self._latest_correlation(database, case_id)
        relationships = []
        for pair in (correlation or {}).get("pairwise", []):
            rel = self._correlation_relationship(pair, accounts, creator)
            if rel is not None:
                relationships.append(rel)

        entity_objects = []
        entity_relationships = []
        for record in database.get_case_entities(case_id):
            identity, member_rels = self._resolved_entity(
                record, accounts, creator)
            entity_objects.append(identity)
            entity_relationships.extend(member_rels)

        objects.extend(sorted(accounts.values(), key=lambda o: o.id))
        objects.extend(relationships)
        objects.extend(entity_objects)
        objects.extend(entity_relationships)

        grouping = stix2.Grouping(
            id=_det_id("grouping", case_id),
            created=self.as_of, modified=self.as_of,
            created_by_ref=creator.id,
            name="WhisperWard case " + case_id,
            context="suspicious-activity",
            description=SCOPE_STATEMENT,
            object_refs=[o.id for o in objects],
        )
        objects.append(grouping)
        return stix2.Bundle(id=_det_id("bundle", case_id), objects=objects,
                            allow_custom=False)

    # ----------------------------------------------------------- objects

    def _creator_identity(self) -> stix2.Identity:
        return stix2.Identity(
            id=_det_id("identity", "tool", TOOL_NAME),
            created=self.as_of, modified=self.as_of,
            name=TOOL_NAME,
            identity_class="system",
            description=("Open-source explainable digital investigations "
                         "platform. " + SCOPE_STATEMENT),
        )

    def _user_account(self, platform: str, username: str,
                      user_id: Optional[str]) -> stix2.UserAccount:
        kwargs = {"account_type": platform, "account_login": username,
                  "display_name": username}
        if user_id:
            kwargs["user_id"] = str(user_id)
        return stix2.UserAccount(**kwargs)

    def _correlation_relationship(self, pair: dict, accounts: dict,
                                  creator) -> Optional[stix2.Relationship]:
        a = pair.get("profile_a")
        b = pair.get("profile_b")
        if a not in accounts or b not in accounts:
            return None
        rationale = "; ".join(pair.get("rationale", []) or [])
        contradiction = (pair.get("contradiction_note") or "").strip()
        description = ("Correlation lead" if pair.get("is_lead")
                       else "Sub-lead correlation")
        if rationale:
            description += ". Rationale: " + rationale
        if contradiction:
            description += ". Contradiction observed: " + contradiction
        description += ". " + SCOPE_STATEMENT
        source, target = sorted([a, b])
        return stix2.Relationship(
            id=_det_id("relationship", "correlation", source, target),
            created=self.as_of, modified=self.as_of,
            created_by_ref=creator.id,
            relationship_type="related-to",
            source_ref=accounts[source].id,
            target_ref=accounts[target].id,
            confidence=_confidence_from_strength(
                pair.get("correlation_strength", 0.0)),
            description=description,
        )

    def _resolved_entity(self, record: dict, accounts: dict, creator):
        entity = record["entity"]
        identity = stix2.Identity(
            id=_det_id("identity", "entity", entity["entity_id"]),
            created=self.as_of, modified=self.as_of,
            created_by_ref=creator.id,
            name=entity["canonical_handle"],
            identity_class="unknown",
            description=("Analyst-resolved account grouping "
                         + entity["entity_id"] + ", promoted by "
                         + entity["promoted_by"] + " at "
                         + str(entity["promoted_at"])
                         + ". Records a human resolution decision over "
                         "correlated accounts; it does not assert a "
                         "real-world identity."),
        )
        relationships = []
        for member in record.get("members", []):
            profile_id = member["profile_id"]
            account = accounts.get(profile_id)
            if account is None:
                account = self._user_account(
                    platform=member.get("platform", "unknown"),
                    username=member.get("username", profile_id),
                    user_id=None)
                accounts[profile_id] = account
            relationships.append(stix2.Relationship(
                id=_det_id("relationship", "membership",
                           entity["entity_id"], profile_id),
                created=self.as_of, modified=self.as_of,
                created_by_ref=creator.id,
                relationship_type="related-to",
                source_ref=identity.id,
                target_ref=account.id,
                description=("Analyst-confirmed membership of this account "
                             "in resolved entity " + entity["entity_id"]
                             + ". The machine justification for the "
                             "underlying correlation is preserved in the "
                             "WhisperWard evidence store."),
            ))
        return identity, relationships

    # ----------------------------------------------------------- helpers

    @staticmethod
    def _latest_correlation(database, case_id: str) -> Optional[dict]:
        conn = database.get_connection()
        row = conn.execute(
            "SELECT raw_data FROM artifacts WHERE artifact_type = "
            "'identity_correlation' AND target_id IN "
            "(SELECT target_id FROM targets WHERE case_id = ?) "
            "ORDER BY artifact_id DESC LIMIT 1", (case_id,)).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row["raw_data"])
        except (ValueError, TypeError):
            return None


def canonical_bundle_json(bundle: stix2.Bundle) -> str:
    """Byte-stable serialization of a bundle: identical content produces
    identical bytes and therefore an identical SHA-256, so a STIX export can
    be sealed into an evidence package like any other artifact."""
    payload = json.loads(bundle.serialize())
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
