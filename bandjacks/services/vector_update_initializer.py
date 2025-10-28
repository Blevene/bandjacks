"""Initialize vector update system with executors and start batch processing."""

import logging
from typing import Optional

from bandjacks.services.vector_update_manager import get_vector_update_manager
from bandjacks.services.vector_executors import (
    TechniqueVectorExecutor,
    EntityVectorExecutor
)

logger = logging.getLogger(__name__)


async def initialize_vector_updates() -> None:
    """
    Initialize the vector update system during application startup.

    This function:
    1. Gets the singleton VectorUpdateManager instance
    2. Registers executors for different entity types
    3. Starts the background batch processor
    """
    try:
        # Get the manager instance
        manager = get_vector_update_manager()

        if not manager.enabled:
            logger.info("Vector update system is disabled in configuration")
            return

        logger.info("Initializing vector update system...")

        # Create and register executors
        # Single TechniqueVectorExecutor handles all AttackPattern nodes
        technique_executor = TechniqueVectorExecutor()
        manager.register_executor("AttackPattern", technique_executor)

        # Single EntityVectorExecutor handles all entity types
        entity_executor = EntityVectorExecutor()
        manager.register_executor("IntrusionSet", entity_executor)
        manager.register_executor("Software", entity_executor)
        manager.register_executor("Campaign", entity_executor)

        logger.info("Registered executors for: AttackPattern, IntrusionSet, Software, Campaign")

        # Start the batch processor background task
        await manager.start_batch_processor()

        logger.info("Vector update system initialized successfully")

        # Log initial status
        status = await manager.get_status()
        logger.info(f"Vector update system status: queue_depth={status['queue_depth']}, "
                   f"batch_processor={status['batch_processor_running']}")

    except Exception as e:
        logger.error(f"Failed to initialize vector update system: {e}")
        # Don't raise - allow app to start even if vector system fails
        # The system will operate without vector updates


async def shutdown_vector_updates() -> None:
    """
    Shutdown the vector update system gracefully.

    This function:
    1. Stops the batch processor
    2. Processes any remaining queued items
    3. Logs final metrics
    """
    try:
        manager = get_vector_update_manager()

        if not manager.enabled:
            return

        logger.info("Shutting down vector update system...")

        # Get final metrics before shutdown
        metrics = manager.get_metrics()
        logger.info(f"Final vector update metrics: total={metrics['total_requests']}, "
                   f"successful={metrics['successful_updates']}, "
                   f"failed={metrics['failed_updates']}")

        # Process any remaining items in queue
        queue_depth = await manager._get_queue_depth()
        if queue_depth > 0:
            logger.info(f"Processing {queue_depth} remaining items before shutdown...")
            processed = await manager.process_batch()
            logger.info(f"Processed {processed} items during shutdown")

        # Stop the batch processor
        await manager.stop_batch_processor()

        logger.info("Vector update system shutdown complete")

    except Exception as e:
        logger.error(f"Error during vector update shutdown: {e}")


def get_vector_update_status() -> dict:
    """
    Get the current status of the vector update system.

    Returns:
        Dictionary with system status and metrics
    """
    try:
        manager = get_vector_update_manager()

        if not manager.enabled:
            return {
                "enabled": False,
                "message": "Vector update system is disabled"
            }

        # This is synchronous for quick status checks
        metrics = manager.get_metrics()

        return {
            "enabled": True,
            "metrics": metrics,
            "config": {
                "immediate_threshold": manager.immediate_threshold,
                "batch_interval": manager.batch_interval,
                "max_batch_size": manager.max_batch_size,
                "parallelization": manager.parallelization
            }
        }

    except Exception as e:
        logger.error(f"Error getting vector update status: {e}")
        return {
            "enabled": False,
            "error": str(e)
        }