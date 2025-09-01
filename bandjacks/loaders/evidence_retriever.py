"""Evidence retrieval from OpenSearch for provenance tracking."""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
from opensearchpy import OpenSearch
import json

logger = logging.getLogger(__name__)


@dataclass
class EvidenceSnippet:
    """Evidence snippet from source document."""
    evidence_id: str
    document_id: str
    text: str
    confidence_score: float
    line_numbers: Optional[List[int]] = None
    technique_refs: Optional[List[str]] = None
    extraction_method: Optional[str] = None
    timestamp: Optional[datetime] = None


class EvidenceRetriever:
    """Retrieves evidence snippets from OpenSearch for provenance."""
    
    def __init__(
        self,
        opensearch_url: str = "http://localhost:9200",
        evidence_index: str = "evidence_store",
        extraction_index: str = "extraction_runs"
    ):
        """
        Initialize evidence retriever.
        
        Args:
            opensearch_url: OpenSearch cluster URL
            evidence_index: Index storing evidence snippets
            extraction_index: Index storing extraction run metadata
        """
        self.client = OpenSearch(
            hosts=[opensearch_url],
            use_ssl=False,
            verify_certs=False
        )
        self.evidence_index = evidence_index
        self.extraction_index = extraction_index
        self._cache = {}  # Simple cache for frequently accessed evidence
        
    def get_evidence_by_id(
        self,
        evidence_id: str,
        use_cache: bool = True
    ) -> Optional[EvidenceSnippet]:
        """
        Retrieve evidence snippet by ID.
        
        Args:
            evidence_id: Evidence document ID
            use_cache: Whether to use cached results
            
        Returns:
            Evidence snippet if found
        """
        # Check cache first
        if use_cache and evidence_id in self._cache:
            return self._cache[evidence_id]
        
        try:
            response = self.client.get(
                index=self.evidence_index,
                id=evidence_id
            )
            
            if response and response.get('found'):
                snippet = self._parse_evidence_document(
                    evidence_id,
                    response['_source']
                )
                
                # Cache the result
                if use_cache:
                    self._cache[evidence_id] = snippet
                
                return snippet
                
        except Exception as e:
            logger.warning(f"Failed to retrieve evidence {evidence_id}: {e}")
            return None
    
    def get_evidence_for_technique(
        self,
        technique_id: str,
        limit: int = 5
    ) -> List[EvidenceSnippet]:
        """
        Get evidence snippets for a specific technique.
        
        Args:
            technique_id: STIX ID of technique
            limit: Maximum number of snippets
            
        Returns:
            List of evidence snippets
        """
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"technique_refs.keyword": technique_id}}
                        ]
                    }
                },
                "sort": [
                    {"confidence_score": {"order": "desc"}},
                    {"timestamp": {"order": "desc"}}
                ],
                "size": limit
            }
            
            response = self.client.search(
                index=self.evidence_index,
                body=query
            )
            
            snippets = []
            for hit in response.get('hits', {}).get('hits', []):
                snippet = self._parse_evidence_document(
                    hit['_id'],
                    hit['_source']
                )
                if snippet:
                    snippets.append(snippet)
            
            return snippets
            
        except Exception as e:
            logger.error(f"Failed to search evidence for technique {technique_id}: {e}")
            return []
    
    def get_evidence_for_extraction(
        self,
        extraction_id: str,
        min_confidence: float = 0.6
    ) -> List[EvidenceSnippet]:
        """
        Get all evidence from a specific extraction run.
        
        Args:
            extraction_id: Extraction run ID
            min_confidence: Minimum confidence threshold
            
        Returns:
            List of evidence snippets
        """
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"extraction_id.keyword": extraction_id}},
                            {"range": {"confidence_score": {"gte": min_confidence}}}
                        ]
                    }
                },
                "sort": [
                    {"line_numbers": {"order": "asc"}},
                    {"confidence_score": {"order": "desc"}}
                ],
                "size": 100
            }
            
            response = self.client.search(
                index=self.evidence_index,
                body=query
            )
            
            snippets = []
            for hit in response.get('hits', {}).get('hits', []):
                snippet = self._parse_evidence_document(
                    hit['_id'],
                    hit['_source']
                )
                if snippet:
                    snippets.append(snippet)
            
            return snippets
            
        except Exception as e:
            logger.error(f"Failed to get evidence for extraction {extraction_id}: {e}")
            return []
    
    def store_evidence(
        self,
        evidence: EvidenceSnippet,
        extraction_id: Optional[str] = None
    ) -> bool:
        """
        Store evidence snippet in OpenSearch.
        
        Args:
            evidence: Evidence snippet to store
            extraction_id: Optional extraction run ID
            
        Returns:
            Success status
        """
        try:
            doc = {
                "document_id": evidence.document_id,
                "text": evidence.text,
                "confidence_score": evidence.confidence_score,
                "line_numbers": evidence.line_numbers,
                "technique_refs": evidence.technique_refs,
                "extraction_method": evidence.extraction_method,
                "timestamp": evidence.timestamp or datetime.utcnow(),
                "extraction_id": extraction_id
            }
            
            response = self.client.index(
                index=self.evidence_index,
                id=evidence.evidence_id,
                body=doc
            )
            
            return response.get('result') in ['created', 'updated']
            
        except Exception as e:
            logger.error(f"Failed to store evidence: {e}")
            return False
    
    def search_evidence(
        self,
        query_text: str,
        technique_filter: Optional[List[str]] = None,
        confidence_threshold: float = 0.5,
        limit: int = 20
    ) -> List[EvidenceSnippet]:
        """
        Search for evidence snippets.
        
        Args:
            query_text: Text to search for
            technique_filter: Filter by technique IDs
            confidence_threshold: Minimum confidence
            limit: Maximum results
            
        Returns:
            List of matching evidence snippets
        """
        try:
            must_clauses = [
                {"match": {"text": query_text}},
                {"range": {"confidence_score": {"gte": confidence_threshold}}}
            ]
            
            if technique_filter:
                must_clauses.append({
                    "terms": {"technique_refs.keyword": technique_filter}
                })
            
            query = {
                "query": {
                    "bool": {
                        "must": must_clauses
                    }
                },
                "highlight": {
                    "fields": {
                        "text": {
                            "fragment_size": 150,
                            "number_of_fragments": 3
                        }
                    }
                },
                "size": limit
            }
            
            response = self.client.search(
                index=self.evidence_index,
                body=query
            )
            
            snippets = []
            for hit in response.get('hits', {}).get('hits', []):
                snippet = self._parse_evidence_document(
                    hit['_id'],
                    hit['_source']
                )
                
                # Add highlighted text if available
                if snippet and 'highlight' in hit:
                    highlighted = hit['highlight'].get('text', [])
                    if highlighted:
                        snippet.text = ' ... '.join(highlighted)
                
                if snippet:
                    snippets.append(snippet)
            
            return snippets
            
        except Exception as e:
            logger.error(f"Failed to search evidence: {e}")
            return []
    
    def get_evidence_context(
        self,
        evidence_id: str,
        context_lines: int = 3
    ) -> Optional[Dict[str, Any]]:
        """
        Get evidence with surrounding context.
        
        Args:
            evidence_id: Evidence ID
            context_lines: Lines of context before/after
            
        Returns:
            Evidence with context
        """
        evidence = self.get_evidence_by_id(evidence_id)
        if not evidence:
            return None
        
        # Get surrounding evidence from same document
        if evidence.line_numbers:
            min_line = max(1, min(evidence.line_numbers) - context_lines)
            max_line = max(evidence.line_numbers) + context_lines
            
            try:
                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"document_id.keyword": evidence.document_id}},
                                {"range": {
                                    "line_numbers": {
                                        "gte": min_line,
                                        "lte": max_line
                                    }
                                }}
                            ]
                        }
                    },
                    "sort": [{"line_numbers": {"order": "asc"}}],
                    "size": 50
                }
                
                response = self.client.search(
                    index=self.evidence_index,
                    body=query
                )
                
                context_snippets = []
                for hit in response.get('hits', {}).get('hits', []):
                    snippet = self._parse_evidence_document(
                        hit['_id'],
                        hit['_source']
                    )
                    if snippet:
                        context_snippets.append(snippet)
                
                return {
                    "main_evidence": evidence,
                    "context": context_snippets,
                    "document_id": evidence.document_id,
                    "line_range": [min_line, max_line]
                }
                
            except Exception as e:
                logger.error(f"Failed to get evidence context: {e}")
                return {"main_evidence": evidence, "context": []}
        
        return {"main_evidence": evidence, "context": []}
    
    def _parse_evidence_document(
        self,
        doc_id: str,
        source: Dict[str, Any]
    ) -> Optional[EvidenceSnippet]:
        """
        Parse OpenSearch document into evidence snippet.
        
        Args:
            doc_id: Document ID
            source: Document source
            
        Returns:
            Parsed evidence snippet
        """
        try:
            return EvidenceSnippet(
                evidence_id=doc_id,
                document_id=source.get('document_id', ''),
                text=source.get('text', ''),
                confidence_score=source.get('confidence_score', 0.0),
                line_numbers=source.get('line_numbers'),
                technique_refs=source.get('technique_refs'),
                extraction_method=source.get('extraction_method'),
                timestamp=source.get('timestamp')
            )
        except Exception as e:
            logger.error(f"Failed to parse evidence document: {e}")
            return None
    
    def create_evidence_index(self):
        """Create evidence index with appropriate mappings."""
        if self.client.indices.exists(index=self.evidence_index):
            logger.info(f"Evidence index {self.evidence_index} already exists")
            return
        
        mapping = {
            "mappings": {
                "properties": {
                    "evidence_id": {"type": "keyword"},
                    "document_id": {"type": "keyword"},
                    "extraction_id": {"type": "keyword"},
                    "text": {
                        "type": "text",
                        "fields": {
                            "keyword": {"type": "keyword", "ignore_above": 512}
                        }
                    },
                    "confidence_score": {"type": "float"},
                    "line_numbers": {"type": "integer"},
                    "technique_refs": {"type": "keyword"},
                    "extraction_method": {"type": "keyword"},
                    "timestamp": {"type": "date"}
                }
            }
        }
        
        self.client.indices.create(index=self.evidence_index, body=mapping)
        logger.info(f"Created evidence index: {self.evidence_index}")
    
    def clear_cache(self):
        """Clear evidence cache."""
        self._cache.clear()
        logger.info("Evidence cache cleared")
    
    def close(self):
        """Close OpenSearch connection."""
        if self.client:
            self.client.close()