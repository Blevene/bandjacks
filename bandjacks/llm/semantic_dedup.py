"""Semantic deduplication module for techniques and entities using embeddings."""

import numpy as np
from typing import List, Tuple, Dict, Any, Optional
from bandjacks.loaders.embedder import batch_encode
import logging

logger = logging.getLogger(__name__)


class SemanticDeduplicator:
    """Unified semantic deduplication for techniques, entities, and evidence."""
    
    def __init__(self, similarity_threshold: float = 0.85, entity_threshold: float = 0.90):
        """
        Initialize semantic deduplicator.
        
        Args:
            similarity_threshold: Threshold for technique/evidence similarity (default 0.85)
            entity_threshold: Threshold for entity similarity (default 0.90, higher to avoid false merges)
        """
        self.similarity_threshold = similarity_threshold
        self.entity_threshold = entity_threshold
        self._embedding_cache = {}
    
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
        
        # Get embeddings for all evidence
        embeddings = batch_encode(evidence_list)
        
        # Track which evidence to keep
        keep_indices = []
        merged_groups = []
        
        for i, emb1 in enumerate(embeddings):
            if emb1 is None:
                continue
                
            is_duplicate = False
            emb1_np = np.array(emb1)
            
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
        
        # Get embeddings
        entity_ids = list(entity_texts.keys())
        texts = list(entity_texts.values())
        embeddings = batch_encode(texts)
        
        # Find similar entities
        merged_entities = {}
        processed = set()
        
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
            
            # Find all similar entities
            for j, eid2 in enumerate(entity_ids):
                if i >= j or eid2 in processed:
                    continue
                    
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
        
        # Build evidence strings for each technique
        tech_evidence_map = {}
        for tid, tech_data in techniques.items():
            # Use first 5 evidence pieces for efficiency
            evidence_text = " ".join(tech_data.get("evidence", [])[:5])
            if evidence_text:
                tech_evidence_map[tid] = evidence_text
        
        if not tech_evidence_map:
            return techniques
        
        # Get embeddings
        tech_ids = list(tech_evidence_map.keys())
        evidence_texts = list(tech_evidence_map.values())
        embeddings = batch_encode(evidence_texts)
        
        # Find similar techniques
        merged_techniques = {}
        processed = set()
        
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
            
            # Find all similar techniques
            for j, tid2 in enumerate(tech_ids):
                if i >= j or tid2 in processed:
                    continue
                    
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
                
                if similarity > self.similarity_threshold:
                    similar_techs.append((tid2, techniques[tid2]))
                    processed.add(tid2)
                    logger.debug(f"Technique similarity {similarity:.3f}: {tid1} ~ {tid2}")
            
            # Merge similar techniques
            if len(similar_techs) > 1:
                merged = self._merge_similar_techniques(similar_techs)
                merged_techniques[tid1] = merged
                tech_ids_list = [t[0] for t in similar_techs]
                logger.info(f"Merged techniques: {tech_ids_list} (semantic similarity)")
            else:
                merged_techniques[tid1] = techniques[tid1]
            
            processed.add(tid1)
        
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
    
    def _merge_similar_techniques(self, tech_list: List[Tuple[str, Dict]]) -> Dict:
        """
        Merge similar techniques, combining evidence.
        
        Args:
            tech_list: List of (technique_id, technique_data) tuples
            
        Returns:
            Merged technique with combined evidence
        """
        primary_id, primary_data = tech_list[0]
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
        merged["merged_from"] = [t[0] for t in tech_list[1:]]
        
        return merged