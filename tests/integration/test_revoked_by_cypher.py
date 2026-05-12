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


@pytest.fixture(scope="session")
def _neo4j_or_skip():
    """Probe Neo4j once per pytest session. Lazy: only runs when a test
    that asks for it gets selected, so a normal `pytest tests/unit` run
    pays no probe cost. The 2s connection timeout means at most ~2s spent
    when Neo4j is unreachable, and the skip reason is loud (per-test) so
    silent-skip-the-whole-suite on a flapping DB is harder to miss."""
    if GraphDatabase is None:
        pytest.skip("neo4j driver not installed")
    try:
        d = GraphDatabase.driver(
            NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD), connection_timeout=2
        )
        with d.session() as s:
            s.run("RETURN 1").consume()
        d.close()
    except Exception as e:
        pytest.skip(f"Neo4j not reachable at {NEO4J_URI}: {type(e).__name__}")


@pytest.fixture
def driver(_neo4j_or_skip):
    d = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    yield d
    d.close()


@pytest.fixture
def isolated_cache():
    """Snapshot+restore the TechniqueCache singleton around tests that call
    load_from_neo4j. Without this, the singleton is left empty after the
    test, which silently breaks any later test that depends on a pre-warmed
    cache (e.g., the bandjacks API startup load)."""
    cache = TechniqueCache()
    saved_cache = dict(cache._cache)
    saved_loaded = cache._loaded
    yield cache
    cache._cache.clear()
    cache._cache.update(saved_cache)
    cache._loaded = saved_loaded


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
    """The handler in attack_upsert.py must create exactly one REVOKED_BY
    edge with provenance fields when processing a STIX bundle that contains
    a `revoked-by` relationship.

    Pre-creates the two AttackPattern nodes manually so the bundle can
    contain ONLY the relationship object — that lets us call the real
    `upsert_to_graph_and_vectors()` without an OpenSearch instance, since
    the bundle has no AttackPattern/Tactic/Group/Software objects that
    would trigger embedding bulk-indexing."""
    from bandjacks.loaders.attack_upsert import upsert_to_graph_and_vectors

    revoked_stix = _create_fixture_pattern(
        driver, f"{_TEST_PREFIX}.001", "Old Technique", revoked=True
    )
    active_stix = _create_fixture_pattern(
        driver, f"{_TEST_PREFIX}.002", "New Technique", revoked=False
    )

    # Minimal STIX bundle: just the relationship, no AttackPatterns to
    # avoid triggering embedding/OpenSearch code paths.
    bundle = {
        "type": "bundle",
        "id": "bundle--test-revoked-by",
        "objects": [
            {
                "type": "relationship",
                "id": "relationship--test-revoked-by",
                "relationship_type": "revoked-by",
                "source_ref": revoked_stix,
                "target_ref": active_stix,
                "modified": "2026-05-11T00:00:00.000Z",
            }
        ],
    }

    # Real production call. os_url/os_index are unused for this bundle
    # shape but the signature still requires them.
    upsert_to_graph_and_vectors(
        bundle=bundle,
        collection="enterprise-attack",
        version="test-v1",
        neo4j_uri=NEO4J_URI,
        neo4j_user=NEO4J_USER,
        neo4j_password=NEO4J_PASSWORD,
        os_url="http://localhost:9200",  # not contacted for this bundle
        os_index="bandjacks_attack_nodes-v1",  # not contacted for this bundle
    )

    with driver.session() as s:
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
    assert result["version"] == "test-v1"


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


def test_cache_load_picks_up_replacement(driver, fixture_cleanup, isolated_cache):
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

    cache = isolated_cache
    cache._cache.clear()
    cache._loaded = False
    cache.load_from_neo4j(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

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


def test_cache_load_no_replacement_for_active_technique(driver, fixture_cleanup, isolated_cache):
    """Active techniques (no outbound REVOKED_BY) must load with replacement=None."""
    _create_fixture_pattern(
        driver, f"{_TEST_PREFIX}.005", "Active Only", revoked=False
    )

    cache = isolated_cache
    cache._cache.clear()
    cache._loaded = False
    cache.load_from_neo4j(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

    entry = cache.get(f"{_TEST_PREFIX}.005")
    assert entry is not None
    assert entry["replacement"] is None
