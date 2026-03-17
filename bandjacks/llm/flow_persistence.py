"""Neo4j persistence for attack flows.

Extracted from FlowBuilder to separate persistence concerns.
"""

import json
import logging
import uuid
from typing import Any, Dict, List, Optional

from bandjacks.loaders.embedder import encode

logger = logging.getLogger(__name__)


class FlowPersistence:
    """Persist attack flows to Neo4j and embeddings to OpenSearch."""

    def __init__(self, driver, batch_helper, opensearch_client=None):
        """
        Args:
            driver: Neo4j driver instance
            batch_helper: BatchNeo4jHelper instance for batch operations
            opensearch_client: Optional OpenSearch client for embeddings
        """
        self.driver = driver
        self.batch_helper = batch_helper
        self.opensearch = opensearch_client

    def _get_current_attack_version(self, session) -> str:
        """Get the current ATT&CK version in use."""
        result = session.run(
            """
            MATCH (n:AttackPattern)
            WHERE n.source_version IS NOT NULL
            RETURN n.source_version as version, n.source_collection as collection
            ORDER BY n.modified DESC
            LIMIT 1
            """
        )
        record = result.single()
        if record:
            return f"{record['collection']}-{record['version']}"
        return "unknown"

    def persist_to_neo4j(self, flow_data: Dict[str, Any]) -> bool:
        """
        Persist flow to Neo4j.

        Args:
            flow_data: Complete flow data

        Returns:
            Success boolean
        """
        with self.driver.session() as session:
            try:
                # Get current ATT&CK version for version freeze
                attack_version = self._get_current_attack_version(session)

                # Create AttackFlow node (main flow container)
                session.run(
                    """
                    CREATE (f:AttackFlow {
                        flow_id: $flow_id,
                        name: $name,
                        description: $description,
                        flow_type: $flow_type,
                        source_id: $source_id,
                        created: datetime(),
                        modified: datetime(),
                        llm_synthesized: $llm_synthesized,
                        created_with_release: $attack_version,
                        attributed_group_id: $attributed_group_id,
                        attributed_group_name: $attributed_group_name,
                        sequence_inferred: $sequence_inferred
                    })
                    """,
                    flow_id=flow_data["flow_id"],
                    name=flow_data["name"],
                    description=flow_data.get("description", f"Attack flow with {len(flow_data['actions'])} steps"),
                    flow_type=flow_data.get("flow_type", "sequential"),
                    source_id=flow_data.get("source_id"),
                    llm_synthesized=flow_data.get("llm_synthesized", False),
                    attack_version=attack_version,
                    attributed_group_id=flow_data.get("attributed_group_id"),
                    attributed_group_name=flow_data.get("attributed_group_name"),
                    sequence_inferred=flow_data.get("sequence_inferred", False)
                )

                # Create AttackEpisode linked to the flow
                session.run(
                    """
                    MATCH (f:AttackFlow {flow_id: $flow_id})
                    CREATE (e:AttackEpisode {
                        episode_id: $episode_id,
                        name: $name,
                        source_id: $source_id,
                        created: datetime(),
                        strategy: $strategy
                    })
                    CREATE (f)-[:CONTAINS_EPISODE]->(e)
                    """,
                    flow_id=flow_data["flow_id"],
                    episode_id=flow_data["episode_id"],
                    name=flow_data["name"],
                    source_id=flow_data.get("source_id"),
                    strategy=flow_data.get("flow_type", "sequential")
                )

                # Batch create AttackActions and CONTAINS edges
                if not self.batch_helper.batch_create_attack_actions(
                    flow_data["episode_id"],
                    flow_data["actions"]
                ):
                    # Fallback to individual queries if batch fails
                    for action in flow_data["actions"]:
                        session.run(
                            """
                            MATCH (e:AttackEpisode {episode_id: $episode_id})
                            CREATE (a:AttackAction {
                                action_id: $action_id,
                                attack_pattern_ref: $attack_pattern_ref,
                                confidence: $confidence,
                                order: $order,
                                description: $description,
                                evidence: $evidence,
                                rationale: $rationale,
                                timestamp: datetime()
                            })
                            CREATE (e)-[:CONTAINS {order: $order}]->(a)
                            WITH a
                            MATCH (t:AttackPattern {stix_id: $attack_pattern_ref})
                            CREATE (a)-[:OF_TECHNIQUE]->(t)
                            """,
                            episode_id=flow_data["episode_id"],
                            action_id=action["action_id"],
                            attack_pattern_ref=action["attack_pattern_ref"],
                            confidence=action["confidence"],
                            order=action["order"],
                            description=action["description"],
                            evidence=json.dumps(action.get("evidence", [])),
                            rationale=action.get("reason", "")
                        )

                # Batch create NEXT edges
                if not self.batch_helper.batch_create_next_edges(flow_data["edges"]):
                    # Fallback to individual queries if batch fails
                    for edge in flow_data["edges"]:
                        session.run(
                            """
                            MATCH (a1:AttackAction {action_id: $source})
                            MATCH (a2:AttackAction {action_id: $target})
                            CREATE (a1)-[:NEXT {p: $probability, rationale: $rationale}]->(a2)
                            """,
                            source=edge["source"],
                            target=edge["target"],
                            probability=edge["probability"],
                            rationale=edge["rationale"]
                        )

                # Link to source if exists
                if flow_data.get("source_id"):
                    session.run(
                        """
                        MATCH (e:AttackEpisode {episode_id: $episode_id})
                        MATCH (s {stix_id: $source_id})
                        CREATE (e)-[:DERIVED_FROM]->(s)
                        """,
                        episode_id=flow_data["episode_id"],
                        source_id=flow_data["source_id"]
                    )

                # Add explicit actor attribution if provided
                if flow_data.get("attributed_group_id"):
                    session.run(
                        """
                        MATCH (e:AttackEpisode {episode_id: $episode_id})
                        MATCH (g:IntrusionSet {stix_id: $group_id})
                        CREATE (e)-[:ATTRIBUTED_TO]->(g)
                        """,
                        episode_id=flow_data["episode_id"],
                        group_id=flow_data["attributed_group_id"]
                    )

                return True

            except Exception as e:
                logger.error("Error persisting flow to Neo4j: %s", e)
                return False

    def generate_flow_embedding(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate embedding for flow (no truncation).

        Args:
            flow_data: Complete flow data

        Returns:
            Document for OpenSearch indexing
        """
        # Build comprehensive text representation
        flow_text_parts = [
            f"Attack Flow: {flow_data['name']}",
            f"Source: {flow_data.get('source_id', 'unknown')}",
            f"Created: {flow_data.get('created_at', '')}",
            ""
        ]

        # Add all steps with full details - NO TRUNCATION
        tactics_seen = set()
        techniques = []

        # Batch get tactics for all techniques
        technique_ids = [action["attack_pattern_ref"] for action in flow_data["actions"]]
        tactics_map = self.batch_helper.batch_get_technique_tactics(technique_ids)

        for action in flow_data["actions"]:
            flow_text_parts.append(
                f"Step {action['order']}: {action['name']}"
            )
            flow_text_parts.append(
                f"  Technique: {action['attack_pattern_ref']}"
            )
            flow_text_parts.append(
                f"  Description: {action['description']}"
            )
            flow_text_parts.append(
                f"  Confidence: {action['confidence']:.1f}%"
            )
            if action.get("reason"):
                flow_text_parts.append(
                    f"  Reason: {action['reason']}"
                )
            flow_text_parts.append("")  # Blank line

            techniques.append(action["attack_pattern_ref"])

            # Get tactics from batch results
            for tactic in tactics_map.get(action["attack_pattern_ref"], []):
                tactics_seen.add(tactic)

        # Add edge information
        if flow_data["edges"]:
            flow_text_parts.append("Flow transitions:")
            for edge in flow_data["edges"]:
                flow_text_parts.append(
                    f"  {edge['source'][-8:]} -> {edge['target'][-8:]}: "
                    f"p={edge['probability']:.2f} ({edge['rationale']})"
                )

        # NO TRUNCATION - use full text
        flow_text = "\n".join(flow_text_parts)

        # Generate embedding from full text
        embedding = encode(flow_text)

        if embedding is None:
            # Fallback to empty embedding if encoding fails
            embedding = [0.0] * 768

        return {
            "flow_id": flow_data["flow_id"],
            "episode_id": flow_data["episode_id"],
            "name": flow_data["name"],
            "source_id": flow_data.get("source_id"),
            "created": flow_data.get("created_at"),
            "flow_text": flow_text,  # Store full text, no truncation
            "flow_embedding": embedding,
            "techniques": techniques,
            "tactics": list(tactics_seen),
            "steps_count": len(flow_data["actions"]),
            "avg_confidence": flow_data["stats"]["avg_confidence"],
            "llm_synthesized": flow_data.get("llm_synthesized", False)
        }

    def _get_stored_text(self, report_id: str) -> Optional[str]:
        """
        Retrieve stored text from OpenSearch for a report.

        Args:
            report_id: Report/source ID

        Returns:
            Stored raw text or None
        """
        if not self.opensearch:
            return None

        try:
            from bandjacks.store.opensearch_report_store import OpenSearchReportStore
            store = OpenSearchReportStore(self.opensearch)
            report = store.get_report(report_id)

            if report:
                # Return raw text if available
                return report.get("raw_text")
        except Exception as e:
            logger.error("Error retrieving stored text: %s", e)

        return None
