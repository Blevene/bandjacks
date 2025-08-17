"""Track and manage provenance metadata for extracted CTI data."""

import hashlib
import json
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path


class ProvenanceTracker:
    """Track provenance metadata for CTI extraction and processing."""
    
    def __init__(self):
        """Initialize provenance tracker."""
        self.sources = {}  # Track source documents
        self.extractions = {}  # Track extraction runs
        self.lineage = {}  # Track object lineage
    
    def register_source(
        self,
        content: str,
        url: Optional[str] = None,
        title: Optional[str] = None,
        source_type: str = "report",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Register a source document and generate its ID.
        
        Args:
            content: Raw content of the source
            url: Optional URL of the source
            title: Optional title
            source_type: Type of source (report, blog, pdf, etc)
            metadata: Additional metadata
            
        Returns:
            Source ID (hash-based)
        """
        # Generate content hash as ID
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        source_id = f"source--{content_hash[:16]}"
        
        # Create source record
        self.sources[source_id] = {
            "id": source_id,
            "hash": content_hash,
            "url": url,
            "title": title or "Untitled Document",
            "type": source_type,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "content_length": len(content),
            "metadata": metadata or {}
        }
        
        return source_id
    
    def start_extraction(
        self,
        source_id: str,
        method: str = "llm",
        model: str = "gemini-2.5-flash",
        parameters: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Start an extraction run and generate extraction ID.
        
        Args:
            source_id: ID of source document
            method: Extraction method (llm, vector, hybrid)
            model: Model used for extraction
            parameters: Extraction parameters
            
        Returns:
            Extraction ID
        """
        extraction_id = f"extraction--{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        self.extractions[extraction_id] = {
            "id": extraction_id,
            "source_id": source_id,
            "method": method,
            "model": model,
            "parameters": parameters or {},
            "started_at": datetime.utcnow().isoformat() + "Z",
            "completed_at": None,
            "status": "in_progress",
            "stats": {}
        }
        
        return extraction_id
    
    def complete_extraction(
        self,
        extraction_id: str,
        stats: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ):
        """
        Mark an extraction as complete.
        
        Args:
            extraction_id: ID of extraction run
            stats: Extraction statistics
            error: Error message if failed
        """
        if extraction_id in self.extractions:
            self.extractions[extraction_id]["completed_at"] = datetime.utcnow().isoformat() + "Z"
            self.extractions[extraction_id]["status"] = "failed" if error else "completed"
            self.extractions[extraction_id]["stats"] = stats or {}
            if error:
                self.extractions[extraction_id]["error"] = error
    
    def create_object_provenance(
        self,
        object_id: str,
        object_type: str,
        source_id: str,
        extraction_id: str,
        confidence: float,
        evidence: str,
        line_refs: List[int],
        additional_metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create provenance metadata for an extracted object.
        
        Args:
            object_id: STIX ID of the object
            object_type: STIX type
            source_id: Source document ID
            extraction_id: Extraction run ID
            confidence: Confidence score (0-100)
            evidence: Supporting evidence text
            line_refs: Line numbers in source
            additional_metadata: Extra metadata
            
        Returns:
            Provenance dictionary
        """
        provenance = {
            "object_id": object_id,
            "object_type": object_type,
            "source": self.sources.get(source_id, {"id": source_id}),
            "extraction": self.extractions.get(extraction_id, {"id": extraction_id}),
            "confidence": confidence,
            "evidence": {
                "text": evidence,
                "line_refs": line_refs
            },
            "created_at": datetime.utcnow().isoformat() + "Z",
            "metadata": additional_metadata or {}
        }
        
        # Track in lineage
        if object_id not in self.lineage:
            self.lineage[object_id] = []
        self.lineage[object_id].append(provenance)
        
        return provenance
    
    def create_stix_provenance_extension(
        self,
        object_id: str,
        source_id: str,
        extraction_id: str,
        confidence: float,
        evidence: str,
        line_refs: List[int]
    ) -> Dict[str, Any]:
        """
        Create STIX-compatible provenance extension.
        
        Returns:
            Dictionary suitable for x_bj_provenance field
        """
        source = self.sources.get(source_id, {})
        extraction = self.extractions.get(extraction_id, {})
        
        return {
            "source": {
                "type": source.get("type", "report"),
                "id": source_id,
                "url": source.get("url"),
                "title": source.get("title"),
                "hash": source.get("hash"),
                "timestamp": source.get("timestamp")
            },
            "extraction": {
                "id": extraction_id,
                "method": extraction.get("method", "llm"),
                "model": extraction.get("model"),
                "timestamp": extraction.get("started_at"),
                "confidence": confidence
            },
            "evidence": {
                "text": evidence,
                "line_refs": line_refs
            },
            "validation": {
                "adm_compliant": None,  # To be filled by validator
                "kb_matched": None,  # To be filled by entity resolver
                "review_status": "pending"
            }
        }
    
    def get_object_lineage(self, object_id: str) -> List[Dict[str, Any]]:
        """
        Get complete lineage for an object.
        
        Args:
            object_id: STIX ID of object
            
        Returns:
            List of provenance records
        """
        return self.lineage.get(object_id, [])
    
    def merge_provenance(
        self,
        existing_provenance: List[Dict[str, Any]],
        new_provenance: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Merge new provenance with existing provenance history.
        
        Args:
            existing_provenance: Existing provenance list
            new_provenance: New provenance to add
            
        Returns:
            Merged provenance list
        """
        # Check for duplicate sources
        for prov in existing_provenance:
            if (prov.get("source", {}).get("hash") == 
                new_provenance.get("source", {}).get("hash")):
                # Same source, update confidence if higher
                if new_provenance.get("confidence", 0) > prov.get("confidence", 0):
                    prov["confidence"] = new_provenance["confidence"]
                    prov["evidence"] = new_provenance.get("evidence")
                    prov["updated_at"] = datetime.utcnow().isoformat() + "Z"
                return existing_provenance
        
        # Add as new provenance entry
        merged = existing_provenance.copy()
        merged.append(new_provenance)
        return merged
    
    def calculate_aggregate_confidence(
        self,
        provenance_list: List[Dict[str, Any]]
    ) -> float:
        """
        Calculate aggregate confidence from multiple provenance sources.
        
        Args:
            provenance_list: List of provenance records
            
        Returns:
            Aggregate confidence score (0-100)
        """
        if not provenance_list:
            return 0.0
        
        confidences = []
        for prov in provenance_list:
            conf = prov.get("confidence", 0)
            extraction = prov.get("extraction", {})
            
            # Weight by extraction method
            method = extraction.get("method", "unknown")
            if method == "hybrid":
                weight = 1.0
            elif method == "llm":
                weight = 0.9
            elif method == "vector":
                weight = 0.7
            else:
                weight = 0.5
            
            confidences.append(conf * weight)
        
        # Use weighted average with diminishing returns for multiple sources
        if len(confidences) == 1:
            return confidences[0]
        
        # Sort by confidence
        confidences.sort(reverse=True)
        
        # Apply diminishing weights
        weighted_sum = 0
        weight_sum = 0
        for i, conf in enumerate(confidences):
            weight = 1.0 / (i + 1)  # 1, 0.5, 0.33, 0.25, ...
            weighted_sum += conf * weight
            weight_sum += weight
        
        aggregate = weighted_sum / weight_sum if weight_sum > 0 else 0
        return min(100, aggregate)  # Cap at 100
    
    def export_provenance_report(
        self,
        output_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Export complete provenance report.
        
        Args:
            output_path: Optional path to save report
            
        Returns:
            Provenance report dictionary
        """
        report = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "sources": self.sources,
            "extractions": self.extractions,
            "object_lineage": self.lineage,
            "statistics": {
                "total_sources": len(self.sources),
                "total_extractions": len(self.extractions),
                "total_objects_tracked": len(self.lineage),
                "extraction_methods": self._count_extraction_methods(),
                "confidence_distribution": self._calculate_confidence_distribution()
            }
        }
        
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
        
        return report
    
    def _count_extraction_methods(self) -> Dict[str, int]:
        """Count extractions by method."""
        counts = {}
        for extraction in self.extractions.values():
            method = extraction.get("method", "unknown")
            counts[method] = counts.get(method, 0) + 1
        return counts
    
    def _calculate_confidence_distribution(self) -> Dict[str, int]:
        """Calculate confidence score distribution."""
        bins = {
            "0-25": 0,
            "26-50": 0,
            "51-75": 0,
            "76-100": 0
        }
        
        for lineage_list in self.lineage.values():
            for prov in lineage_list:
                conf = prov.get("confidence", 0)
                if conf <= 25:
                    bins["0-25"] += 1
                elif conf <= 50:
                    bins["26-50"] += 1
                elif conf <= 75:
                    bins["51-75"] += 1
                else:
                    bins["76-100"] += 1
        
        return bins
    
    def validate_provenance_chain(
        self,
        object_id: str
    ) -> Tuple[bool, List[str]]:
        """
        Validate the provenance chain for an object.
        
        Args:
            object_id: STIX ID to validate
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        lineage = self.lineage.get(object_id, [])
        if not lineage:
            return False, ["No provenance found for object"]
        
        for prov in lineage:
            # Check source exists
            source_id = prov.get("source", {}).get("id")
            if source_id and source_id not in self.sources:
                issues.append(f"Source {source_id} not found in registry")
            
            # Check extraction exists
            extraction_id = prov.get("extraction", {}).get("id")
            if extraction_id and extraction_id not in self.extractions:
                issues.append(f"Extraction {extraction_id} not found in registry")
            
            # Check required fields
            if not prov.get("confidence"):
                issues.append("Missing confidence score")
            
            if not prov.get("evidence", {}).get("text"):
                issues.append("Missing evidence text")
        
        return len(issues) == 0, issues