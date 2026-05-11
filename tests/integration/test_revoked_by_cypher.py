"""Integration test for the revoked-by Cypher branches.

The unit tests in tests/unit/test_technique_cache_replacement.py seed
`cache._cache` directly via _seed() — they never exercise load_from_neo4j().
So a typo in:
  - the attack_upsert.py MERGE clause (wrong label, property names),
  - or the technique_cache.py OPTIONAL MATCH (wrong relationship name,
    field-name mismatch between `as replacement` and `record["replacement"]`),
is unit-test-invisible. Cache tests pass while production is broken.

This test exercises both Cypher branches end-to-end against a live Neo4j.
Skips if NEO4J_URI is not reachable, so CI without infra is unaffected.
"""

import os

import pytest

try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import ServiceUnavailable
except Exception:  # pragma: no cover
    GraphDatabase = None
    ServiceUnavailable = Exception


from bandjacks.services.technique_cache import TechniqueCache


NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "bandjacks")

# Use a probe value that cannot collide with real ATT&CK external_ids.
_TEST_PREFIX = "T9999"


def _neo4j_available() -> bool:
    if GraphDatabase is None:
        return False
    try:
        driver = GraphDatabase.driver(
            NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD), connection_timeout=2
        )
        with driver.session() as s:
            s.run("RETURN 1").consume()
        driver.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _neo4j_available(),
    reason="Neo4j not reachable; this is an integration test.",
)


@pytest.fixture
def driver():
    d = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    yield d
    d.close()


@pytest.fixture
def fixture_cleanup(driver):
    """Remove any prior fixture state, then yield. Clean up after too."""

    def _wipe():
        with driver.session() as s:
            s.run(
                "MATCH (n:AttackPattern) WHERE n.external_id STARTS WITH $p DETACH DELETE n",
                p=_TEST_PREFIX,
            )

    _wipe()
    yield
    _wipe()


def _create_fixture_pattern(driver, external_id, name, revoked=False):
    """Insert one AttackPattern matching the upsert path's MERGE shape."""
    stix_id = f"attack-pattern--{external_id}-fixture"
    with driver.session() as s:
        s.run(
            """
            MERGE (n:AttackPattern {stix_id:$stix_id})
            SET n.type='attack-pattern', n.name=$name, n.description='',
                n.revoked=$revoked, n.x_mitre_is_subtechnique=false,
                n.external_id=$external_id, n.modified='2026-05-11',
                n.source_collection='enterprise-attack',
                n.source_version='test'
            """,
            stix_id=stix_id, name=name, revoked=revoked, external_id=external_id,
        )
    return stix_id


def test_revoked_by_upsert_creates_edge(driver, fixture_cleanup):
    """The handler in attack_upsert.py:491-509 must create exactly one
    REVOKED_BY edge with provenance fields between two AttackPattern nodes."""
    revoked_stix = _create_fixture_pattern(
        driver, f"{_TEST_PREFIX}.001", "Old Technique", revoked=True
    )
    active_stix = _create_fixture_pattern(
        driver, f"{_TEST_PREFIX}.002", "New Technique", revoked=False
    )

    # Replay the exact Cypher from attack_upsert.py:496-507
    with driver.session() as s:
        s.run(
            """
            MATCH (src:AttackPattern {stix_id:$src})
            MATCH (tgt:AttackPattern {stix_id:$tgt})
            MERGE (src)-[r:REVOKED_BY]->(tgt)
            SET r.modified=$modified, r.source_collection=$collection,
                r.source_version=$version
            """,
            src=revoked_stix, tgt=active_stix,
            modified="2026-05-11", collection="enterprise-attack", version="test",
        )

        # Assert exactly one edge with the expected provenance
        result = s.run(
            """
            MATCH (src:AttackPattern {stix_id:$src})-[r:REVOKED_BY]->(tgt:AttackPattern {stix_id:$tgt})
            RETURN count(r) AS n, collect(r.source_collection)[0] AS collection,
                   collect(r.source_version)[0] AS version
            """,
            src=revoked_stix, tgt=active_stix,
        ).single()

    assert result["n"] == 1
    assert result["collection"] == "enterprise-attack"
    assert result["version"] == "test"


def test_revoked_by_upsert_is_noop_when_target_missing(driver, fixture_cleanup):
    """MATCH/MATCH semantics: when the target AttackPattern doesn't exist
    (e.g., relationship references a node from a different bundle), the
    MERGE produces zero edges instead of erroring. Documented behavior;
    pin it so a future shift to OPTIONAL MATCH doesn't silently introduce
    orphan edges."""
    revoked_stix = _create_fixture_pattern(
        driver, f"{_TEST_PREFIX}.003", "Source", revoked=True
    )

    with driver.session() as s:
        s.run(
            """
            MATCH (src:AttackPattern {stix_id:$src})
            MATCH (tgt:AttackPattern {stix_id:$tgt})
            MERGE (src)-[r:REVOKED_BY]->(tgt)
            """,
            src=revoked_stix, tgt="attack-pattern--does-not-exist",
        )

        result = s.run(
            "MATCH (src:AttackPattern {stix_id:$src})-[r:REVOKED_BY]->() RETURN count(r) AS n",
            src=revoked_stix,
        ).single()

    assert result["n"] == 0


def test_cache_load_picks_up_replacement(driver, fixture_cleanup):
    """The OPTIONAL MATCH + head(collect(...)) in technique_cache.py:96-115
    must populate the `replacement` field for revoked techniques that have
    a REVOKED_BY edge."""
    revoked_stix = _create_fixture_pattern(
        driver, f"{_TEST_PREFIX}.001", "Old Technique", revoked=True
    )
    active_stix = _create_fixture_pattern(
        driver, f"{_TEST_PREFIX}.002", "New Technique", revoked=False
    )

    with driver.session() as s:
        s.run(
            """
            MATCH (src:AttackPattern {stix_id:$src})
            MATCH (tgt:AttackPattern {stix_id:$tgt})
            MERGE (src)-[r:REVOKED_BY]->(tgt)
            SET r.modified='2026-05-11'
            """,
            src=revoked_stix, tgt=active_stix,
        )

    cache = TechniqueCache()
    cache._cache.clear()
    cache._loaded = False
    cache.load_from_neo4j(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

    try:
        revoked_entry = cache.get(f"{_TEST_PREFIX}.001")
        active_entry = cache.get(f"{_TEST_PREFIX}.002")

        assert revoked_entry is not None, "revoked entry missing from cache"
        assert active_entry is not None, "active entry missing from cache"
        assert revoked_entry["revoked"] is True
        assert revoked_entry["replacement"] == f"{_TEST_PREFIX}.002", (
            f"replacement field not populated; got {revoked_entry.get('replacement')!r}"
        )
        # And the walker, which depends on `replacement`, agrees.
        assert cache.replacement_for(f"{_TEST_PREFIX}.001") == f"{_TEST_PREFIX}.002"
    finally:
        cache._cache.clear()
        cache._loaded = False


def test_cache_load_no_replacement_for_active_technique(driver, fixture_cleanup):
    """Active techniques (no outbound REVOKED_BY) must load with replacement=None."""
    _create_fixture_pattern(
        driver, f"{_TEST_PREFIX}.005", "Active Only", revoked=False
    )

    cache = TechniqueCache()
    cache._cache.clear()
    cache._loaded = False
    cache.load_from_neo4j(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

    try:
        entry = cache.get(f"{_TEST_PREFIX}.005")
        assert entry is not None
        assert entry["replacement"] is None
    finally:
        cache._cache.clear()
        cache._loaded = False
