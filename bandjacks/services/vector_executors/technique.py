"""Vector executor for MITRE ATT&CK techniques (AttackPattern nodes)."""

import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from bandjacks.services.vector_executors.base import BaseVectorExecutor

logger = logging.getLogger(__name__)
if TYPE_CHECKING:
    from bandjacks.services.vector_update_manager import VectorUpdateRequest


class TechniqueVectorExecutor(BaseVectorExecutor):
    """
    Executor for updating vectors of AttackPattern nodes.

    Handles MITRE ATT&CK techniques and sub-techniques.
    """

    async def fetch_entity_data(self, entity_id: str, entity_type: str) -> Optional[Dict[str, Any]]:
        """
        Fetch AttackPattern data from Neo4j.

        Args:
            entity_id: STIX ID of the technique
            entity_type: Should be "AttackPattern"

        Returns:
            Technique data dictionary or None
        """
        session = self.get_neo4j_session()

        try:
            query = """
            MATCH (t:AttackPattern {stix_id: $entity_id})
            OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tactic:Tactic)
            RETURN t {
                .*,
                tactics: collect(DISTINCT tactic.name)
            } as data
            """

            result = session.run(query, entity_id=entity_id)
            record = result.single()

            if record:
                return dict(record["data"])

            return None

        except Exception as e:
            logger.error(f"Error fetching technique data for {entity_id}: {e}")
            return None

    async def generate_text_representation(
        self,
        entity_data: Dict[str, Any],
        request: "VectorUpdateRequest"
    ) -> Optional[str]:
        """
        Generate text representation for technique embedding.

        Args:
            entity_data: Technique data from Neo4j
            request: Update request

        Returns:
            Text representation or None
        """
        try:
            # Extract key fields
            name = entity_data.get("name", "")
            description = entity_data.get("description", "")
            external_id = entity_data.get("external_id", "")
            tactics = entity_data.get("tactics", [])

            # Build comprehensive text representation
            text_parts = []

            # Add technique ID and name
            if external_id:
                text_parts.append(f"Technique {external_id}: {name}")
            else:
                text_parts.append(f"Technique: {name}")

            # Add tactics
            if tactics:
                text_parts.append(f"Tactics: {', '.join(tactics)}")

            # Add description
            if description:
                # Limit description length for better embedding quality
                desc_limit = 1000
                if len(description) > desc_limit:
                    description = description[:desc_limit] + "..."
                text_parts.append(f"Description: {description}")

            # Add platforms if available
            platforms = entity_data.get("x_mitre_platforms", [])
            if platforms:
                text_parts.append(f"Platforms: {', '.join(platforms)}")

            # Add data sources if available
            data_sources = entity_data.get("x_mitre_data_sources", [])
            if data_sources:
                # Limit to first 5 data sources
                sources_text = ", ".join(data_sources[:5])
                if len(data_sources) > 5:
                    sources_text += f" (+{len(data_sources) - 5} more)"
                text_parts.append(f"Data Sources: {sources_text}")

            # Combine all parts
            text = "\n".join(text_parts)

            if not text or len(text) < 10:
                logger.warning(f"Generated text too short for {entity_data.get('stix_id', 'unknown')}")
                return None

            return text

        except Exception as e:
            logger.error(f"Error generating text representation: {e}")
            return None

    async def batch_process_techniques(self, technique_ids: List[str]) -> int:
        """
        Process multiple techniques in batch.

        Args:
            technique_ids: List of technique STIX IDs

        Returns:
            Number of successful updates
        """
        session = self.get_neo4j_session()

        try:
            # Fetch all techniques in one query
            query = """
            UNWIND $technique_ids as tid
            MATCH (t:AttackPattern {stix_id: tid})
            OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tactic:Tactic)
            RETURN t {
                .*,
                tactics: collect(DISTINCT tactic.name)
            } as data
            """

            result = session.run(query, technique_ids=technique_ids)
            techniques = [dict(record["data"]) for record in result]

            if not techniques:
                return 0

            # Generate embeddings and prepare updates
            updates = []
            for tech_data in techniques:
                # Generate text representation
                text = await self.generate_text_representation(tech_data, None)
                if not text:
                    continue

                # Generate embedding
                embedding = await self.generate_embedding(text)
                if embedding is None:
                    continue

                # Prepare update document
                updates.append({
                    "id": tech_data["stix_id"],
                    "kb_type": "AttackPattern",
                    "text": text,
                    "embedding": embedding,
                    "name": tech_data.get("name", ""),
                    "description": tech_data.get("description", ""),
                    "external_id": tech_data.get("external_id", ""),
                    "attack_version": tech_data.get("attack_version", ""),
                    "updated_at": tech_data.get("modified", ""),
                })

            # Batch update OpenSearch
            if updates:
                return await self.batch_update_opensearch(updates)

            return 0

        except Exception as e:
            logger.error(f"Error in batch technique processing: {e}")
            return 0