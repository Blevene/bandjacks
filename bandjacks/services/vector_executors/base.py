"""Base executor for vector update operations."""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from neo4j import Session
from opensearchpy import OpenSearch

from typing import TYPE_CHECKING

from bandjacks.loaders.embedder import encode
from bandjacks.services.api.deps import get_neo4j_session, get_opensearch_client
from bandjacks.services.api.settings import settings

if TYPE_CHECKING:
    from bandjacks.services.vector_update_manager import VectorUpdateRequest

logger = logging.getLogger(__name__)


class BaseVectorExecutor(ABC):
    """
    Abstract base class for vector update executors.

    Provides common functionality for generating embeddings and updating OpenSearch.
    """

    def __init__(
        self,
        neo4j_session: Optional[Session] = None,
        opensearch_client: Optional[OpenSearch] = None
    ):
        """
        Initialize the executor.

        Args:
            neo4j_session: Optional Neo4j session
            opensearch_client: Optional OpenSearch client
        """
        self.neo4j_session = neo4j_session
        self.opensearch_client = opensearch_client
        self.index_name = settings.os_index_nodes

    async def execute(self, request: "VectorUpdateRequest") -> bool:
        """
        Execute a vector update request.

        Args:
            request: Update request to process

        Returns:
            True if successful
        """
        try:
            # Get entity data from Neo4j
            entity_data = await self.fetch_entity_data(request.entity_id, request.entity_type)
            if not entity_data:
                logger.warning(f"Entity not found: {request.entity_type}:{request.entity_id}")
                return False

            # Generate text representation
            text = await self.generate_text_representation(entity_data, request)
            if not text:
                logger.warning(f"Could not generate text for {request.entity_type}:{request.entity_id}")
                return False

            # Generate embedding
            embedding = await self.generate_embedding(text)
            if embedding is None:
                logger.warning(f"Could not generate embedding for {request.entity_type}:{request.entity_id}")
                return False

            # Update OpenSearch
            success = await self.update_opensearch(
                entity_id=request.entity_id,
                entity_type=request.entity_type,
                embedding=embedding,
                text=text,
                metadata=entity_data
            )

            if success:
                logger.info(f"Successfully updated vector for {request.entity_type}:{request.entity_id}")
            else:
                logger.warning(f"Failed to update OpenSearch for {request.entity_type}:{request.entity_id}")

            return success

        except Exception as e:
            logger.error(f"Error executing vector update for {request.entity_id}: {e}")
            return False

    @abstractmethod
    async def fetch_entity_data(self, entity_id: str, entity_type: str) -> Optional[Dict[str, Any]]:
        """
        Fetch entity data from Neo4j.

        Args:
            entity_id: Entity identifier
            entity_type: Type of entity

        Returns:
            Entity data dictionary or None
        """
        pass

    @abstractmethod
    async def generate_text_representation(
        self,
        entity_data: Dict[str, Any],
        request: "VectorUpdateRequest"
    ) -> Optional[str]:
        """
        Generate text representation for embedding.

        Args:
            entity_data: Entity data from Neo4j
            request: Update request

        Returns:
            Text representation or None
        """
        pass

    async def generate_embedding(self, text: str) -> Optional[List[float]]:
        """
        Generate embedding vector for text.

        Args:
            text: Text to embed

        Returns:
            Embedding vector or None
        """
        try:
            embedding = encode(text)
            if embedding is None:
                logger.warning(f"Failed to generate embedding for text: {text[:100]}...")
                return None

            return embedding

        except Exception as e:
            logger.error(f"Error generating embedding: {e}")
            return None

    async def update_opensearch(
        self,
        entity_id: str,
        entity_type: str,
        embedding: List[float],
        text: str,
        metadata: Dict[str, Any]
    ) -> bool:
        """
        Update OpenSearch with new embedding.

        Args:
            entity_id: Entity identifier
            entity_type: Type of entity
            embedding: Embedding vector
            text: Text representation
            metadata: Additional metadata

        Returns:
            True if successful
        """
        if not self.opensearch_client:
            self.opensearch_client = get_opensearch_client()

        try:
            # Prepare document
            doc = {
                "id": entity_id,
                "kb_type": entity_type,
                "text": text,
                "embedding": embedding,
                "name": metadata.get("name", ""),
                "description": metadata.get("description", ""),
                "external_id": metadata.get("external_id", ""),
                "attack_version": metadata.get("attack_version", ""),
                "updated_at": metadata.get("modified", ""),
            }

            # Update or create document
            response = self.opensearch_client.index(
                index=self.index_name,
                id=entity_id,
                body=doc,
                refresh=False  # Don't wait for refresh
            )

            return response.get("result") in ["created", "updated"]

        except Exception as e:
            logger.error(f"Error updating OpenSearch: {e}")
            return False

    async def batch_update_opensearch(
        self,
        updates: List[Dict[str, Any]]
    ) -> int:
        """
        Batch update OpenSearch documents.

        Args:
            updates: List of document updates

        Returns:
            Number of successful updates
        """
        if not self.opensearch_client:
            self.opensearch_client = get_opensearch_client()

        if not updates:
            return 0

        try:
            # Prepare bulk operations
            bulk_body = []
            for update in updates:
                # Index operation
                bulk_body.append({
                    "index": {
                        "_index": self.index_name,
                        "_id": update["id"]
                    }
                })
                # Document
                bulk_body.append(update)

            # Execute bulk update
            response = self.opensearch_client.bulk(
                body=bulk_body,
                refresh=False
            )

            # Count successful updates
            successful = 0
            if not response.get("errors"):
                successful = len(updates)
            else:
                for item in response.get("items", []):
                    if item.get("index", {}).get("status") in [200, 201]:
                        successful += 1

            return successful

        except Exception as e:
            logger.error(f"Error in batch OpenSearch update: {e}")
            return 0

    def get_neo4j_session(self) -> Session:
        """
        Get or create Neo4j session.

        Returns:
            Neo4j session
        """
        if not self.neo4j_session:
            self.neo4j_session = get_neo4j_session()
        return self.neo4j_session