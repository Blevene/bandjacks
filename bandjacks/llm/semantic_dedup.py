"""Semantic deduplication module for techniques and entities using embeddings."""

import numpy as np
import time
from typing import List, Tuple, Dict, Any, Optional
from bandjacks.loaders.embedder import batch_encode
import logging
import os
import hashlib
from functools import lru_cache

logger = logging.getLogger(__name__)


class SemanticDeduplicator:
    """Unified semantic deduplication for techniques, entities, and evidence."""

    def __init__(self, similarity_threshold: float = None, entity_threshold: float = None):
        """
        Initialize semantic deduplicator.

        Args:
            similarity_threshold: Threshold for technique/evidence similarity (default 0.95 from env or 0.85)
            entity_threshold: Threshold for entity similarity (default 0.95 from env or 0.90)
        """
        # Use environment variables with higher defaults to prevent over-merging
        self.similarity_threshold = similarity_threshold or float(os.getenv("SEMANTIC_DEDUP_THRESHOLD", "0.95"))
        self.entity_threshold = entity_threshold or float(os.getenv("ENTITY_DEDUP_THRESHOLD", "0.95"))

        # Performance settings
        self.max_items = int(os.getenv("SEMANTIC_DEDUP_MAX_ITEMS", "50"))
        self.cache_size = int(os.getenv("SEMANTIC_DEDUP_CACHE_SIZE", "1000"))
        self.batch_size = int(os.getenv("SEMANTIC_DEDUP_BATCH_SIZE", "20"))

        # Embedding cache to avoid recalculation
        self._embedding_cache = {}  # Text hash -> embedding
        self._cache_hits = 0
        self._cache_misses = 0

        logger.info(f"SemanticDeduplicator initialized with thresholds: techniques={self.similarity_threshold}, entities={self.entity_threshold}, max_items={self.max_items}")
    
    def _get_text_hash(self, text: str) -> str:
        """Get a hash for text to use as cache key."""
        return hashlib.md5(text.encode()).hexdigest()

    def _get_embeddings(self, texts: List[str]) -> List[np.ndarray]:
        """
        Get embeddings for texts with caching.

        Args:
            texts: List of texts to embed

        Returns:
            List of embedding vectors
        """
        embeddings = []
        texts_to_encode = []
        text_indices = []

        # Check cache first
        for i, text in enumerate(texts):
            text_hash = self._get_text_hash(text)
            if text_hash in self._embedding_cache:
                embeddings.append(self._embedding_cache[text_hash])
                self._cache_hits += 1
            else:
                embeddings.append(None)
                texts_to_encode.append(text)
                text_indices.append(i)
                self._cache_misses += 1

        # Batch encode uncached texts
        if texts_to_encode:
            new_embeddings = batch_encode(texts_to_encode)
            for idx, embedding in zip(text_indices, new_embeddings):
                text_hash = self._get_text_hash(texts[idx])
                # Limit cache size
                if len(self._embedding_cache) >= self.cache_size:
                    # Remove oldest entry (simple FIFO)
                    self._embedding_cache.pop(next(iter(self._embedding_cache)))
                self._embedding_cache[text_hash] = embedding
                embeddings[idx] = embedding

        if self._cache_hits + self._cache_misses > 0:
            hit_rate = self._cache_hits / (self._cache_hits + self._cache_misses) * 100
            logger.debug(f"Embedding cache hit rate: {hit_rate:.1f}% ({self._cache_hits} hits, {self._cache_misses} misses)")

        return embeddings

    def cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """
        Calculate cosine similarity between two vectors.
        
        Args:
            vec1: First vector
            vec2: Second vector
            
        Returns:
            Cosine similarity between 0 and 1
        """
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)
    
    def deduplicate_evidence(self, evidence_list: List[str]) -> List[str]:
        """
        Deduplicate evidence using semantic similarity.

        Args:
            evidence_list: List of evidence strings

        Returns:
            Deduplicated list of evidence
        """
        if len(evidence_list) <= 1:
            return evidence_list

        # Circuit breaker: Skip semantic dedup for large collections
        if len(evidence_list) > self.max_items:
            logger.warning(f"Evidence list too large ({len(evidence_list)} > {self.max_items}), skipping semantic deduplication")
            # Fallback to simple deduplication by exact match
            return list(dict.fromkeys(evidence_list))

        start_time = time.time()

        # Get embeddings with caching
        embeddings = self._get_embeddings(evidence_list)
        embedding_time = time.time() - start_time
        logger.debug(f"Evidence embedding took {embedding_time:.2f}s for {len(evidence_list)} items")

        # Track which evidence to keep
        keep_indices = []
        merged_groups = []

        for i, emb1 in enumerate(embeddings):
            if emb1 is None:
                continue

            is_duplicate = False
            emb1_np = np.array(emb1)

            # Early termination: Skip if we already found enough unique items
            if len(keep_indices) >= self.max_items:
                break

            for j in keep_indices:
                emb2 = embeddings[j]
                if emb2 is None:
                    continue

                emb2_np = np.array(emb2)
                similarity = self.cosine_similarity(emb1_np, emb2_np)

                if similarity > self.similarity_threshold:
                    is_duplicate = True
                    # Keep the longer evidence (more context)
                    if len(evidence_list[i]) > len(evidence_list[j]):
                        # Replace j with i in keep_indices
                        idx = keep_indices.index(j)
                        keep_indices[idx] = i
                    merged_groups.append((i, j, similarity))
                    break
            
            if not is_duplicate:
                keep_indices.append(i)
        
        if merged_groups:
            logger.debug(f"Merged {len(merged_groups)} similar evidence pairs using embeddings")
        
        # Sort by original order to maintain reading flow
        return [evidence_list[i] for i in sorted(keep_indices)]
    
    def deduplicate_entities(self, entities: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deduplicate entities based on semantic similarity.
        Handles aliases like APT29/Cozy Bear/NOBELIUM.

        Args:
            entities: Dictionary of entity_id -> entity_data

        Returns:
            Deduplicated entities with aliases tracked
        """
        if len(entities) <= 1:
            return entities

        # Circuit breaker: Skip semantic dedup for large collections
        if len(entities) > self.max_items:
            logger.warning(f"Entity collection too large ({len(entities)} > {self.max_items}), skipping semantic deduplication")
            return entities  # Return as-is

        # Build text representations for each entity
        entity_texts = {}
        for entity_id, entity_data in entities.items():
            # Combine name, type, and evidence for similarity
            name = entity_data.get("name", "")
            entity_type = entity_data.get("type", "")
            # Use first 3 evidence pieces for context
            evidence = " ".join(entity_data.get("evidence", [])[:3])

            # Create a representation that captures entity essence
            entity_text = f"{entity_type}: {name}. {evidence}"
            entity_texts[entity_id] = entity_text

        # Get embeddings with caching
        entity_ids = list(entity_texts.keys())
        texts = list(entity_texts.values())
        embeddings = self._get_embeddings(texts)

        # Find similar entities
        merged_entities = {}
        processed = set()
        comparisons = 0
        max_comparisons = self.max_items * 10  # Limit total comparisons

        for i, eid1 in enumerate(entity_ids):
            if eid1 in processed:
                continue

            emb1 = embeddings[i]
            if emb1 is None:
                merged_entities[eid1] = entities[eid1]
                processed.add(eid1)
                continue

            emb1_np = np.array(emb1)
            similar_entities = [(eid1, entities[eid1])]

            # Find all similar entities with early termination
            for j, eid2 in enumerate(entity_ids):
                if i >= j or eid2 in processed:
                    continue

                # Pre-filter: Skip if names are very different in length
                name1 = entities[eid1].get("name", "")
                name2 = entities[eid2].get("name", "")
                if len(name1) > 0 and len(name2) > 0:
                    len_diff = abs(len(name1) - len(name2)) / max(len(name1), len(name2))
                    if len_diff > 0.7:  # Names differ by more than 70% in length
                        continue

                comparisons += 1
                if comparisons > max_comparisons:
                    logger.warning(f"Reached max comparisons limit ({max_comparisons}), stopping entity deduplication")
                    break

                emb2 = embeddings[j]
                if emb2 is None:
                    continue

                emb2_np = np.array(emb2)
                similarity = self.cosine_similarity(emb1_np, emb2_np)

                # Higher threshold for entities to avoid false merges
                if similarity > self.entity_threshold:
                    similar_entities.append((eid2, entities[eid2]))
                    processed.add(eid2)
                    logger.debug(f"Entity similarity {similarity:.3f}: {entities[eid1]['name']} ~ {entities[eid2]['name']}")

            # Merge similar entities
            if len(similar_entities) > 1:
                merged = self._merge_similar_entities(similar_entities)
                merged_entities[eid1] = merged
                entity_names = [e[1].get("name", e[0]) for e in similar_entities]
                logger.info(f"Merged entities: {entity_names} (semantic similarity)")
            else:
                merged_entities[eid1] = entities[eid1]

            processed.add(eid1)

        logger.debug(f"Entity deduplication: {len(entities)} -> {len(merged_entities)} entities, {comparisons} comparisons")
        return merged_entities
    
    def deduplicate_techniques(self, techniques: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deduplicate techniques based on semantic similarity of evidence.
        Preserves parent/subtechnique relationships.

        Args:
            techniques: Dictionary of technique_id -> technique_data

        Returns:
            Deduplicated techniques
        """
        if len(techniques) <= 1:
            return techniques

        # Circuit breaker: Skip semantic dedup for large collections
        if len(techniques) > self.max_items:
            logger.warning(f"Technique collection too large ({len(techniques)} > {self.max_items}), using fallback deduplication")
            # Fallback to simple exact match on technique IDs
            return techniques

        start_time = time.time()

        # Build evidence strings for each technique
        tech_evidence_map = {}
        for tid, tech_data in techniques.items():
            # Use first 5 evidence pieces for efficiency
            evidence_text = " ".join(tech_data.get("evidence", [])[:5])
            if evidence_text:
                tech_evidence_map[tid] = evidence_text
        
        if not tech_evidence_map:
            return techniques

        # Get embeddings with caching
        tech_ids = list(tech_evidence_map.keys())
        evidence_texts = list(tech_evidence_map.values())
        embeddings = self._get_embeddings(evidence_texts)
        embedding_time = time.time() - start_time
        logger.info(f"Technique embedding took {embedding_time:.2f}s for {len(tech_ids)} techniques")

        # Find similar techniques
        merged_techniques = {}
        processed = set()
        comparisons = 0
        max_comparisons = self.max_items * 10  # Limit total comparisons

        for i, tid1 in enumerate(tech_ids):
            if tid1 in processed:
                continue

            emb1 = embeddings[i]
            if emb1 is None:
                merged_techniques[tid1] = techniques[tid1]
                processed.add(tid1)
                continue

            emb1_np = np.array(emb1)
            similar_techs = [(tid1, techniques[tid1])]

            # Find all similar techniques with early termination
            for j, tid2 in enumerate(tech_ids):
                if i >= j or tid2 in processed:
                    continue

                # Pre-filter: Skip if evidence lengths are very different
                len1 = len(tech_evidence_map[tid1])
                len2 = len(tech_evidence_map[tid2])
                if len1 > 0 and len2 > 0:
                    len_diff = abs(len1 - len2) / max(len1, len2)
                    if len_diff > 0.7:  # Evidence differs by more than 70% in length
                        continue

                comparisons += 1
                if comparisons > max_comparisons:
                    logger.warning(f"Reached max comparisons limit ({max_comparisons}), stopping technique deduplication")
                    break

                emb2 = embeddings[j]
                if emb2 is None:
                    continue

                emb2_np = np.array(emb2)
                similarity = self.cosine_similarity(emb1_np, emb2_np)
                
                # Don't merge parent with subtechnique (e.g., T1055 with T1055.001)
                tid1_base = tid1.split('.')[0]
                tid2_base = tid2.split('.')[0]
                if tid1_base == tid2_base and ('.' in tid1) != ('.' in tid2):
                    logger.debug(f"Preserving parent/subtechnique: {tid1} and {tid2} (similarity {similarity:.3f})")
                    continue
                
                # Don't merge different technique families even if evidence is similar
                if tid1_base != tid2_base and similarity < 0.98:  # Very high threshold for different families
                    continue
                
                if similarity > self.similarity_threshold:
                    similar_techs.append((tid2, techniques[tid2]))
                    processed.add(tid2)
                    logger.debug(f"Technique similarity {similarity:.3f}: {tid1} ~ {tid2}")
            
            # Merge similar techniques
            if len(similar_techs) > 1:
                merged, primary_key = self._merge_similar_techniques(similar_techs)
                merged_techniques[primary_key] = merged
                tech_ids_list = [t[0] for t in similar_techs]
                logger.info(f"Merged techniques: {tech_ids_list} → {primary_key} (semantic similarity)")
            else:
                merged_techniques[tid1] = techniques[tid1]
            
            processed.add(tid1)
        
        dedup_time = time.time() - start_time
        logger.info(f"Technique deduplication completed in {dedup_time:.2f}s: {len(techniques)} → {len(merged_techniques)} techniques")
        return merged_techniques
    
    def _merge_similar_entities(self, entity_list: List[Tuple[str, Dict]]) -> Dict:
        """
        Merge similar entities, tracking aliases.
        
        Args:
            entity_list: List of (entity_id, entity_data) tuples
            
        Returns:
            Merged entity with aliases tracked
        """
        primary_id, primary_data = entity_list[0]
        merged = dict(primary_data)
        
        # Collect all unique names as aliases
        all_names = [primary_data.get("name")]
        for eid, edata in entity_list[1:]:
            name = edata.get("name")
            if name and name not in all_names:
                all_names.append(name)
        
        # Set primary name and aliases
        merged["name"] = all_names[0]
        if len(all_names) > 1:
            # Preserve existing aliases and add new ones
            existing_aliases = merged.get("aliases", [])
            all_aliases = list(set(existing_aliases + all_names[1:]))
            merged["aliases"] = all_aliases
        
        # Combine all evidence
        all_evidence = []
        for _, edata in entity_list:
            all_evidence.extend(edata.get("evidence", []))
        
        # Deduplicate evidence using semantic similarity
        merged["evidence"] = self.deduplicate_evidence(all_evidence)
        
        # Combine line refs
        all_line_refs = set()
        for _, edata in entity_list:
            line_refs = edata.get("line_refs", [])
            if isinstance(line_refs, set):
                all_line_refs.update(line_refs)
            else:
                all_line_refs.update(line_refs)
        merged["line_refs"] = sorted(all_line_refs)
        
        # Take highest confidence
        merged["confidence"] = max(e[1].get("confidence", 50) for e in entity_list)
        
        # Track what was merged
        merged["merged_from"] = [e[0] for e in entity_list[1:]]
        
        return merged
    
    def _merge_similar_techniques(self, tech_list: List[Tuple[str, Dict]]) -> Tuple[Dict, str]:
        """
        Merge similar techniques, combining evidence.

        Args:
            tech_list: List of (technique_id, technique_data) tuples

        Returns:
            (merged_technique_data, primary_technique_id)
        """
        # Prefer a non-revoked technique as the primary ID when merging.
        # Revoked/deprecated IDs should not survive as the representative.
        from bandjacks.services.technique_cache import technique_cache
        primary_id, primary_data = tech_list[0]
        for tid, tdata in tech_list:
            cached = technique_cache.get(tid)
            if cached and not cached.get("revoked") and not cached.get("deprecated"):
                primary_id, primary_data = tid, tdata
                break
        merged = dict(primary_data)
        
        # Combine all evidence
        all_evidence = []
        for _, tdata in tech_list:
            all_evidence.extend(tdata.get("evidence", []))
        
        # Deduplicate evidence using semantic similarity
        merged["evidence"] = self.deduplicate_evidence(all_evidence)
        
        # Combine line refs
        all_line_refs = set()
        for _, tdata in tech_list:
            line_refs = tdata.get("line_refs", [])
            if isinstance(line_refs, set):
                all_line_refs.update(line_refs)
            else:
                all_line_refs.update(line_refs)
        merged["line_refs"] = sorted(all_line_refs)
        
        # Take highest confidence
        merged["confidence"] = max(t[1].get("confidence", 50) for t in tech_list)
        
        # Track what was merged
        merged["merged_from"] = [t[0] for t in tech_list if t[0] != primary_id]

        return merged, primary_id