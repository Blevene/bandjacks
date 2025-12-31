"""Vector executor for various entity types (IntrusionSet, Software, Campaign)."""

import logging
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from bandjacks.services.vector_executors.base import BaseVectorExecutor

logger = logging.getLogger(__name__)
if TYPE_CHECKING:
    from bandjacks.services.vector_update_manager import VectorUpdateRequest


class EntityVectorExecutor(BaseVectorExecutor):
    """
    Executor for updating vectors of various entity types.

    Handles IntrusionSet (threat actors), Software (malware/tools), and Campaign nodes.
    """

    async def fetch_entity_data(self, entity_id: str, entity_type: str) -> Optional[Dict[str, Any]]:
        """
        Fetch entity data from Neo4j.

        Args:
            entity_id: STIX ID of the entity
            entity_type: Type of entity (IntrusionSet, Software, Campaign)

        Returns:
            Entity data dictionary or None
        """
        session = self.get_neo4j_session()

        try:
            # Build query based on entity type
            if entity_type == "IntrusionSet":
                query = """
                MATCH (e:IntrusionSet {stix_id: $entity_id})
                OPTIONAL MATCH (e)-[:USES]->(t:AttackPattern)
                OPTIONAL MATCH (e)-[:USES]->(s:Software)
                RETURN e {
                    .*,
                    techniques_used: collect(DISTINCT t.external_id),
                    software_used: collect(DISTINCT s.name)
                } as data
                """
            elif entity_type == "Software":
                query = """
                MATCH (e:Software {stix_id: $entity_id})
                OPTIONAL MATCH (e)-[:USES]->(t:AttackPattern)
                OPTIONAL MATCH (g:IntrusionSet)-[:USES]->(e)
                RETURN e {
                    .*,
                    techniques_used: collect(DISTINCT t.external_id),
                    used_by_groups: collect(DISTINCT g.name)
                } as data
                """
            elif entity_type == "Campaign":
                query = """
                MATCH (e:Campaign {stix_id: $entity_id})
                OPTIONAL MATCH (e)-[:USES]->(t:AttackPattern)
                OPTIONAL MATCH (e)-[:ATTRIBUTED_TO]->(g:IntrusionSet)
                OPTIONAL MATCH (e)-[:USES]->(s:Software)
                RETURN e {
                    .*,
                    techniques_used: collect(DISTINCT t.external_id),
                    attributed_to: collect(DISTINCT g.name),
                    software_used: collect(DISTINCT s.name)
                } as data
                """
            else:
                logger.warning(f"Unsupported entity type: {entity_type}")
                return None

            result = session.run(query, entity_id=entity_id)
            record = result.single()

            if record:
                return dict(record["data"])

            return None

        except Exception as e:
            logger.error(f"Error fetching entity data for {entity_id}: {e}")
            return None

    async def generate_text_representation(
        self,
        entity_data: Dict[str, Any],
        request: "VectorUpdateRequest"
    ) -> Optional[str]:
        """
        Generate text representation for entity embedding.

        Args:
            entity_data: Entity data from Neo4j
            request: Update request

        Returns:
            Text representation or None
        """
        try:
            # Extract common fields
            name = entity_data.get("name", "")
            description = entity_data.get("description", "")
            entity_type = entity_data.get("type", "")
            aliases = entity_data.get("aliases", [])

            # Build text representation based on type
            text_parts = []

            # Add entity type and name
            if entity_type == "intrusion-set":
                text_parts.append(f"Threat Actor: {name}")
            elif entity_type == "malware":
                text_parts.append(f"Malware: {name}")
            elif entity_type == "tool":
                text_parts.append(f"Tool: {name}")
            elif entity_type == "campaign":
                text_parts.append(f"Campaign: {name}")
            else:
                text_parts.append(f"Entity: {name}")

            # Add aliases
            if aliases and len(aliases) > 1:
                # Exclude the main name from aliases
                other_aliases = [a for a in aliases if a != name]
                if other_aliases:
                    text_parts.append(f"Also known as: {', '.join(other_aliases[:5])}")

            # Add description
            if description:
                # Limit description length
                desc_limit = 800
                if len(description) > desc_limit:
                    description = description[:desc_limit] + "..."
                text_parts.append(f"Description: {description}")

            # Add techniques used
            techniques = entity_data.get("techniques_used", [])
            if techniques:
                tech_text = ", ".join(techniques[:10])
                if len(techniques) > 10:
                    tech_text += f" (+{len(techniques) - 10} more)"
                text_parts.append(f"Techniques: {tech_text}")

            # Add software used (for groups and campaigns)
            software = entity_data.get("software_used", [])
            if software:
                soft_text = ", ".join(software[:10])
                if len(software) > 10:
                    soft_text += f" (+{len(software) - 10} more)"
                text_parts.append(f"Software/Tools: {soft_text}")

            # Add groups that use this software
            used_by = entity_data.get("used_by_groups", [])
            if used_by:
                groups_text = ", ".join(used_by[:5])
                if len(used_by) > 5:
                    groups_text += f" (+{len(used_by) - 5} more)"
                text_parts.append(f"Used by: {groups_text}")

            # Add attribution (for campaigns)
            attributed = entity_data.get("attributed_to", [])
            if attributed:
                text_parts.append(f"Attributed to: {', '.join(attributed)}")

            # Add sophistication level if available
            sophistication = entity_data.get("sophistication", "")
            if sophistication:
                text_parts.append(f"Sophistication: {sophistication}")

            # Add first seen/last seen dates if available
            first_seen = entity_data.get("first_seen", "")
            last_seen = entity_data.get("last_seen", "")
            if first_seen or last_seen:
                date_text = []
                if first_seen:
                    date_text.append(f"First seen: {first_seen}")
                if last_seen:
                    date_text.append(f"Last seen: {last_seen}")
                text_parts.append(" | ".join(date_text))

            # Combine all parts
            text = "\n".join(text_parts)

            if not text or len(text) < 10:
                logger.warning(f"Generated text too short for {entity_data.get('stix_id', 'unknown')}")
                return None

            return text

        except Exception as e:
            logger.error(f"Error generating text representation: {e}")
            return None

    async def batch_process_entities(self, entities: List[Tuple[str, str]]) -> int:
        """
        Process multiple entities in batch.

        Args:
            entities: List of (entity_id, entity_type) tuples

        Returns:
            Number of successful updates
        """
        session = self.get_neo4j_session()
        updates = []

        try:
            # Process each entity type group
            by_type: Dict[str, List[str]] = {}
            for entity_id, entity_type in entities:
                if entity_type not in by_type:
                    by_type[entity_type] = []
                by_type[entity_type].append(entity_id)

            for entity_type, entity_ids in by_type.items():
                # Build appropriate query
                if entity_type == "IntrusionSet":
                    query = """
                    UNWIND $entity_ids as eid
                    MATCH (e:IntrusionSet {stix_id: eid})
                    OPTIONAL MATCH (e)-[:USES]->(t:AttackPattern)
                    OPTIONAL MATCH (e)-[:USES]->(s:Software)
                    RETURN e {
                        .*,
                        techniques_used: collect(DISTINCT t.external_id),
                        software_used: collect(DISTINCT s.name)
                    } as data
                    """
                elif entity_type == "Software":
                    query = """
                    UNWIND $entity_ids as eid
                    MATCH (e:Software {stix_id: eid})
                    OPTIONAL MATCH (e)-[:USES]->(t:AttackPattern)
                    OPTIONAL MATCH (g:IntrusionSet)-[:USES]->(e)
                    RETURN e {
                        .*,
                        techniques_used: collect(DISTINCT t.external_id),
                        used_by_groups: collect(DISTINCT g.name)
                    } as data
                    """
                elif entity_type == "Campaign":
                    query = """
                    UNWIND $entity_ids as eid
                    MATCH (e:Campaign {stix_id: eid})
                    OPTIONAL MATCH (e)-[:USES]->(t:AttackPattern)
                    OPTIONAL MATCH (e)-[:ATTRIBUTED_TO]->(g:IntrusionSet)
                    OPTIONAL MATCH (e)-[:USES]->(s:Software)
                    RETURN e {
                        .*,
                        techniques_used: collect(DISTINCT t.external_id),
                        attributed_to: collect(DISTINCT g.name),
                        software_used: collect(DISTINCT s.name)
                    } as data
                    """
                else:
                    continue

                # Fetch entities
                result = session.run(query, entity_ids=entity_ids)
                entities_data = [dict(record["data"]) for record in result]

                # Generate embeddings and prepare updates
                for entity_data in entities_data:
                    # Generate text representation
                    text = await self.generate_text_representation(entity_data, None)
                    if not text:
                        continue

                    # Generate embedding
                    embedding = await self.generate_embedding(text)
                    if embedding is None:
                        continue

                    # Prepare update document
                    updates.append({
                        "id": entity_data["stix_id"],
                        "kb_type": entity_type,
                        "text": text,
                        "embedding": embedding,
                        "name": entity_data.get("name", ""),
                        "description": entity_data.get("description", ""),
                        "external_id": entity_data.get("external_id", ""),
                        "attack_version": entity_data.get("attack_version", ""),
                        "updated_at": entity_data.get("modified", ""),
                    })

            # Batch update OpenSearch
            if updates:
                return await self.batch_update_opensearch(updates)

            return 0

        except Exception as e:
            logger.error(f"Error in batch entity processing: {e}")
            return 0