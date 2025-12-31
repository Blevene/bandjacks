#!/usr/bin/env python
"""
Migration script to generate initial vectors for all existing entities in the database.

This script will:
1. Query Neo4j for all entities (AttackPattern, IntrusionSet, Software, Campaign)
2. Submit vector update requests for each entity
3. Process them in batches for efficiency

Usage:
    python scripts/migrate_vectors.py [--entity-type TYPE] [--batch-size N] [--priority P]
"""

import asyncio
import argparse
import logging
import sys
from typing import List, Optional, Tuple
from pathlib import Path

# Add parent directory to path so we can import from bandjacks
sys.path.insert(0, str(Path(__file__).parent.parent))

from neo4j import GraphDatabase
from bandjacks.services.api.settings import settings
from bandjacks.services.vector_update_manager import get_vector_update_manager, UpdateAction
from bandjacks.services.vector_update_initializer import initialize_vector_updates, shutdown_vector_updates

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VectorMigration:
    """Handle migration of existing entities to vector embeddings."""

    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """Initialize migration with database connection."""
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.manager = get_vector_update_manager()

    def close(self):
        """Close database connection."""
        self.driver.close()

    def get_entity_count(self, entity_type: Optional[str] = None) -> dict:
        """Get count of entities by type."""
        with self.driver.session() as session:
            counts = {}

            if entity_type:
                # Count specific type
                query = f"MATCH (e:{entity_type}) RETURN count(e) as count"
                result = session.run(query)
                record = result.single()
                counts[entity_type] = record["count"] if record else 0
            else:
                # Count all types
                for etype in ["AttackPattern", "IntrusionSet", "Software", "Campaign"]:
                    query = f"MATCH (e:{etype}) RETURN count(e) as count"
                    result = session.run(query)
                    record = result.single()
                    counts[etype] = record["count"] if record else 0

            return counts

    def get_entities(self, entity_type: str, skip: int = 0, limit: int = 100) -> List[Tuple[str, str]]:
        """
        Get entities of a specific type with pagination.

        Returns:
            List of (stix_id, entity_type) tuples
        """
        with self.driver.session() as session:
            query = f"""
                MATCH (e:{entity_type})
                WHERE e.stix_id IS NOT NULL
                RETURN e.stix_id as stix_id
                ORDER BY e.stix_id
                SKIP $skip
                LIMIT $limit
            """

            result = session.run(query, skip=skip, limit=limit)
            entities = []
            for record in result:
                stix_id = record["stix_id"]
                if stix_id:
                    entities.append((stix_id, entity_type))

            return entities

    async def migrate_entity_type(
        self,
        entity_type: str,
        batch_size: int = 100,
        priority: int = 8,
        dry_run: bool = False
    ) -> dict:
        """
        Migrate all entities of a specific type.

        Args:
            entity_type: Type of entity to migrate
            batch_size: Number of entities to process in each batch
            priority: Priority for vector updates (1-10, lower is higher priority)
            dry_run: If True, only count entities without submitting updates

        Returns:
            Migration statistics
        """
        stats = {
            "entity_type": entity_type,
            "total": 0,
            "submitted": 0,
            "skipped": 0,
            "errors": 0,
            "batches": 0
        }

        # Get total count
        counts = self.get_entity_count(entity_type)
        total = counts.get(entity_type, 0)
        stats["total"] = total

        if total == 0:
            logger.info(f"No {entity_type} entities found to migrate")
            return stats

        logger.info(f"Starting migration for {total} {entity_type} entities")

        if dry_run:
            logger.info("DRY RUN mode - no updates will be submitted")
            return stats

        # Process in batches
        offset = 0
        while offset < total:
            try:
                # Get batch of entities
                entities = self.get_entities(entity_type, skip=offset, limit=batch_size)

                if not entities:
                    break

                # Submit vector updates for batch
                submitted = 0
                for stix_id, etype in entities:
                    try:
                        await self.manager.submit_update(
                            entity_id=stix_id,
                            entity_type=etype,
                            action=UpdateAction.CREATE,
                            priority=priority
                        )
                        submitted += 1
                    except Exception as e:
                        logger.error(f"Failed to submit update for {stix_id}: {e}")
                        stats["errors"] += 1

                stats["submitted"] += submitted
                stats["batches"] += 1

                logger.info(f"Batch {stats['batches']}: Submitted {submitted} updates "
                           f"({offset + len(entities)}/{total} total)")

                # Move to next batch
                offset += batch_size

                # Small delay between batches to avoid overwhelming the system
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"Error processing batch at offset {offset}: {e}")
                stats["errors"] += 1
                # Continue with next batch
                offset += batch_size

        logger.info(f"Completed migration for {entity_type}: {stats}")
        return stats

    async def migrate_all(
        self,
        batch_size: int = 100,
        priority: int = 8,
        dry_run: bool = False
    ) -> dict:
        """
        Migrate all entity types.

        Args:
            batch_size: Number of entities to process in each batch
            priority: Priority for vector updates
            dry_run: If True, only count entities without submitting updates

        Returns:
            Overall migration statistics
        """
        overall_stats = {
            "total_entities": 0,
            "total_submitted": 0,
            "total_errors": 0,
            "by_type": {}
        }

        # Get counts for all types
        counts = self.get_entity_count()
        overall_stats["total_entities"] = sum(counts.values())

        logger.info(f"Entity counts: {counts}")
        logger.info(f"Total entities to migrate: {overall_stats['total_entities']}")

        if dry_run:
            logger.info("DRY RUN mode - no updates will be submitted")
            return overall_stats

        # Migrate each entity type
        for entity_type in ["AttackPattern", "IntrusionSet", "Software", "Campaign"]:
            if counts.get(entity_type, 0) > 0:
                logger.info(f"\nMigrating {entity_type} entities...")
                stats = await self.migrate_entity_type(
                    entity_type=entity_type,
                    batch_size=batch_size,
                    priority=priority,
                    dry_run=dry_run
                )
                overall_stats["by_type"][entity_type] = stats
                overall_stats["total_submitted"] += stats["submitted"]
                overall_stats["total_errors"] += stats["errors"]

        return overall_stats

    async def process_pending_updates(self, max_wait: int = 300):
        """
        Wait for and process pending updates.

        Args:
            max_wait: Maximum time to wait in seconds
        """
        logger.info("Processing pending vector updates...")

        start_time = asyncio.get_event_loop().time()
        processed_total = 0

        while (asyncio.get_event_loop().time() - start_time) < max_wait:
            # Check queue status
            status = await self.manager.get_status()
            queue_depth = status.get("queue_depth", 0)

            if queue_depth == 0:
                logger.info("Queue is empty, all updates processed")
                break

            logger.info(f"Queue depth: {queue_depth}, processing batch...")

            # Process a batch
            processed = await self.manager.process_batch()
            processed_total += processed

            logger.info(f"Processed {processed} updates (total: {processed_total})")

            # Small delay before checking again
            await asyncio.sleep(2)

        # Get final metrics
        metrics = self.manager.get_metrics()
        logger.info(f"Final metrics: {metrics}")

        return processed_total


async def main():
    """Main migration function."""
    parser = argparse.ArgumentParser(
        description="Generate initial vectors for existing entities"
    )
    parser.add_argument(
        "--entity-type",
        choices=["AttackPattern", "IntrusionSet", "Software", "Campaign"],
        help="Migrate only a specific entity type"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Number of entities to process in each batch (default: 100)"
    )
    parser.add_argument(
        "--priority",
        type=int,
        default=8,
        choices=range(1, 11),
        help="Priority for vector updates, 1-10 (default: 8)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Count entities without submitting updates"
    )
    parser.add_argument(
        "--process-queue",
        action="store_true",
        help="Process the queue after submitting updates"
    )
    parser.add_argument(
        "--max-wait",
        type=int,
        default=300,
        help="Maximum time to wait for queue processing in seconds (default: 300)"
    )

    args = parser.parse_args()

    # Initialize vector update system
    logger.info("Initializing vector update system...")
    await initialize_vector_updates()

    # Check if system is enabled
    manager = get_vector_update_manager()
    if not manager.enabled:
        logger.error("Vector update system is disabled. Enable it in settings to run migration.")
        sys.exit(1)

    # Create migration instance
    migration = VectorMigration(
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password
    )

    try:
        # Run migration
        if args.entity_type:
            # Migrate specific type
            stats = await migration.migrate_entity_type(
                entity_type=args.entity_type,
                batch_size=args.batch_size,
                priority=args.priority,
                dry_run=args.dry_run
            )
            logger.info(f"\nMigration complete for {args.entity_type}: {stats}")
        else:
            # Migrate all types
            stats = await migration.migrate_all(
                batch_size=args.batch_size,
                priority=args.priority,
                dry_run=args.dry_run
            )
            logger.info(f"\nMigration complete: {stats}")

        # Process queue if requested
        if args.process_queue and not args.dry_run:
            logger.info("\nProcessing pending updates...")
            processed = await migration.process_pending_updates(max_wait=args.max_wait)
            logger.info(f"Processed {processed} updates from queue")

    finally:
        # Cleanup
        migration.close()
        await shutdown_vector_updates()
        logger.info("Migration script complete")


if __name__ == "__main__":
    asyncio.run(main())