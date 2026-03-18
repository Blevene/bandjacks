"""OpenSearch-based report storage service."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError
import json
import logging

logger = logging.getLogger(__name__)


class OpenSearchReportStore:
    """Store and retrieve reports from OpenSearch."""
    
    def __init__(self, opensearch_client: OpenSearch):
        """Initialize with OpenSearch client."""
        self.client = opensearch_client
        self.index_name = "bandjacks_reports"
    
    def save_report(
        self,
        report_id: str,
        job_id: str,
        report_data: Dict[str, Any],
        extraction_result: Dict[str, Any],
        source_info: Optional[Dict[str, Any]] = None,
        raw_text: Optional[str] = None,
        text_chunks: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Save a new report to OpenSearch.
        
        Args:
            report_id: Unique report ID (STIX ID)
            job_id: Associated job ID
            report_data: Report metadata (name, description, etc.)
            extraction_result: Extraction results including techniques and claims
            source_info: Information about the report source
            raw_text: Full text content of the report
            text_chunks: List of text chunks with metadata
        
        Returns:
            OpenSearch response
        """
        # Extract technique IDs for searchability
        techniques = []
        if extraction_result.get("bundle_preview", {}).get("objects"):
            for obj in extraction_result["bundle_preview"]["objects"]:
                if obj.get("type") == "attack-pattern":
                    techniques.append(obj.get("id"))
        
        # Calculate average confidence
        confidence_scores = []
        for claim in extraction_result.get("extraction_claims", []):
            if claim.get("confidence"):
                confidence_scores.append(claim["confidence"])
        confidence_avg = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        # Generate embeddings if text is provided
        text_embedding = None
        chunk_embeddings_list = []
        
        if raw_text:
            try:
                from bandjacks.loaders.embedder import encode
                # Generate full document embedding (use first 5000 chars for efficiency)
                text_embedding = encode(raw_text[:5000])
                
                # Generate embeddings for chunks
                if text_chunks:
                    for chunk in text_chunks:
                        chunk_emb = encode(chunk.get("text", "")[:1000])  # Use first 1000 chars of chunk
                        if chunk_emb:
                            chunk_embeddings_list.append({
                                "chunk_id": chunk.get("chunk_id"),
                                "embedding": chunk_emb
                            })
            except Exception as e:
                logger.warning(f"Failed to generate embeddings: {e}")
        
        document = {
            "report_id": report_id,
            "job_id": job_id,
            "name": report_data.get("name", "Untitled Report"),
            "description": report_data.get("description", ""),
            "created": report_data.get("created", datetime.utcnow().isoformat()),
            "modified": report_data.get("modified", datetime.utcnow().isoformat()),
            "published": report_data.get("published"),
            "ingested_at": datetime.utcnow().isoformat(),
            "status": "pending_review",
            "extraction_status": "completed",
            "raw_text": raw_text,  # Store full text
            "text_chunks": text_chunks,  # Store chunks
            "extraction": {
                "techniques_count": extraction_result.get("techniques_count", 0),
                "claims_count": extraction_result.get("claims_count", 0),
                "confidence_avg": confidence_avg,
                "metrics": extraction_result.get("extraction_metrics", {}),
                "bundle": extraction_result.get("bundle_preview", {}),
                "claims": extraction_result.get("extraction_claims", []),
                "entities": extraction_result.get("entities", {}),  # Include extracted entities
                "flow": extraction_result.get("flow"),  # Legacy single-flow compat
                "flows": extraction_result.get("flows", [])  # Dual flows list
            },
            "techniques": techniques,
            "source": source_info or {}
        }
        
        # Add embeddings if available
        if text_embedding:
            document["text_embedding"] = text_embedding
        if chunk_embeddings_list:
            document["chunk_embeddings"] = chunk_embeddings_list
        
        try:
            response = self.client.index(
                index=self.index_name,
                id=report_id,
                body=document
            )
            logger.info(f"Saved report {report_id} to OpenSearch")
            return response
        except Exception as e:
            logger.error(f"Failed to save report {report_id}: {e}")
            raise
    
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a report by ID.
        
        Args:
            report_id: Report ID to retrieve
        
        Returns:
            Report document or None if not found
        """
        try:
            response = self.client.get(
                index=self.index_name,
                id=report_id
            )
            return response["_source"]
        except NotFoundError:
            logger.info(f"Report {report_id} not found in OpenSearch")
            return None
        except Exception as e:
            if "index_not_found_exception" in str(e):
                logger.warning(f"Reports index does not exist")
            else:
                logger.error(f"Failed to get report {report_id}: {e}")
            return None
    
    def update_review(
        self,
        report_id: str,
        reviewer_id: str,
        technique_actions: List[Dict[str, Any]],
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update report with review decisions.
        
        Args:
            report_id: Report ID to update
            reviewer_id: ID of the reviewer
            technique_actions: List of review decisions for techniques
            notes: Optional review notes
        
        Returns:
            OpenSearch update response
        """
        # Calculate review stats
        approved_count = sum(1 for action in technique_actions if action["action"] == "approve")
        rejected_count = sum(1 for action in technique_actions if action["action"] == "reject")
        edited_count = sum(1 for action in technique_actions if action["action"] == "edit")
        
        # Build decisions map
        decisions = {
            action["technique_id"]: {
                "action": action["action"],
                "edited_data": action.get("edited_data"),
                "notes": action.get("notes")
            }
            for action in technique_actions
        }
        
        update_body = {
            "doc": {
                "status": "reviewed",
                "modified": datetime.utcnow().isoformat(),
                "review": {
                    "reviewer_id": reviewer_id,
                    "reviewed_at": datetime.utcnow().isoformat(),
                    "approved_count": approved_count,
                    "rejected_count": rejected_count,
                    "edited_count": edited_count,
                    "decisions": decisions,
                    "notes": notes
                }
            }
        }
        
        try:
            response = self.client.update(
                index=self.index_name,
                id=report_id,
                body=update_body
            )
            logger.info(f"Updated review for report {report_id}")
            return response
        except Exception as e:
            logger.error(f"Failed to update review for {report_id}: {e}")
            raise
    
    def approve_report(
        self,
        report_id: str,
        approver_id: str,
        upserted: bool = False
    ) -> Dict[str, Any]:
        """
        Mark report as approved.
        
        Args:
            report_id: Report ID to approve
            approver_id: ID of the approver
            upserted: Whether the report was upserted to Neo4j
        
        Returns:
            OpenSearch update response
        """
        update_body = {
            "doc": {
                "status": "approved",
                "modified": datetime.utcnow().isoformat(),
                "approval": {
                    "approver_id": approver_id,
                    "approved_at": datetime.utcnow().isoformat(),
                    "upserted": upserted,
                    "upserted_at": datetime.utcnow().isoformat() if upserted else None
                }
            }
        }
        
        try:
            response = self.client.update(
                index=self.index_name,
                id=report_id,
                body=update_body
            )
            logger.info(f"Approved report {report_id}")
            return response
        except Exception as e:
            logger.error(f"Failed to approve report {report_id}: {e}")
            raise
    
    def update_report_flow(
        self,
        report_id: str,
        flow_id: str,
        flow_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update report with generated attack flow information.
        
        Args:
            report_id: Report ID to update
            flow_id: Generated flow ID
            flow_data: Attack flow data
        
        Returns:
            OpenSearch update response
        """
        update_body = {
            "doc": {
                "modified": datetime.utcnow().isoformat(),
                "flow": {
                    "id": flow_id,
                    "generated_at": datetime.utcnow().isoformat(),
                    "episode_type": flow_data.get("episode_type", "intrusion-set"),
                    "actions_count": len(flow_data.get("actions", [])),
                    "edges_count": len(flow_data.get("edges", [])),
                    "flow_type": flow_data.get("flow_type", "sequential")
                }
            }
        }
        
        try:
            response = self.client.update(
                index=self.index_name,
                id=report_id,
                body=update_body
            )
            logger.info(f"Updated report {report_id} with flow {flow_id}")
            return response
        except Exception as e:
            logger.error(f"Failed to update report flow for {report_id}: {e}")
            raise
    
    def update_attribution(
        self,
        report_id: str,
        intrusion_sets: List[str],
        malware: List[str],
        confidence: float,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update report attribution with threat actors and malware.
        
        Args:
            report_id: Report ID to update
            intrusion_sets: List of intrusion set STIX IDs
            malware: List of malware/tool STIX IDs
            confidence: Attribution confidence score
            notes: Attribution notes
        
        Returns:
            OpenSearch update response
        """
        update_body = {
            "doc": {
                "modified": datetime.utcnow().isoformat(),
                "attribution": {
                    "intrusion_sets": intrusion_sets,
                    "malware": malware,
                    "confidence": confidence,
                    "notes": notes,
                    "updated_at": datetime.utcnow().isoformat()
                }
            }
        }
        
        try:
            response = self.client.update(
                index=self.index_name,
                id=report_id,
                body=update_body
            )
            logger.info(f"Updated attribution for report {report_id}")
            return response
        except Exception as e:
            logger.error(f"Failed to update attribution for {report_id}: {e}")
            raise
    
    def list_reports(
        self,
        limit: int = 100,
        offset: int = 0,
        status: Optional[str] = None,
        has_campaign: Optional[bool] = None,
        search_query: Optional[str] = None,
        sort_by: str = "ingested_at",
        sort_order: str = "desc"
    ) -> Dict[str, Any]:
        """
        List reports with optional filtering.
        
        Args:
            limit: Maximum number of reports to return
            offset: Number of reports to skip
            status: Filter by status (pending_review, reviewed, approved)
            has_campaign: Filter by campaign presence
            search_query: Full-text search query
            sort_by: Field to sort by
            sort_order: Sort order (asc or desc)
        
        Returns:
            Search results with reports and metadata
        """
        # Build query
        must_clauses = []
        
        if status:
            must_clauses.append({"term": {"status": status}})
        
        if has_campaign is not None:
            if has_campaign:
                must_clauses.append({"exists": {"field": "campaign.id"}})
            else:
                must_clauses.append({"bool": {"must_not": {"exists": {"field": "campaign.id"}}}})
        
        if search_query:
            must_clauses.append({
                "multi_match": {
                    "query": search_query,
                    "fields": ["name^2", "description", "review.notes"],
                    "type": "best_fields"
                }
            })
        
        # Build final query
        if must_clauses:
            query = {"bool": {"must": must_clauses}}
        else:
            query = {"match_all": {}}
        
        # Execute search
        search_body = {
            "query": query,
            "sort": [{sort_by: {"order": sort_order}}],
            "from": offset,
            "size": limit,
            "_source": {
                "excludes": ["extraction.bundle", "extraction.claims", "review.decisions"]
            }
        }
        
        try:
            response = self.client.search(
                index=self.index_name,
                body=search_body
            )
            
            # Extract results
            reports = []
            for hit in response["hits"]["hits"]:
                report = hit["_source"]
                report["_score"] = hit.get("_score")
                reports.append(report)
            
            return {
                "reports": reports,
                "total": response["hits"]["total"]["value"],
                "limit": limit,
                "offset": offset
            }
        except Exception as e:
            if "index_not_found_exception" in str(e):
                logger.warning(f"Reports index does not exist, returning empty results")
                return {
                    "reports": [],
                    "total": 0,
                    "limit": limit,
                    "offset": offset
                }
            logger.error(f"Failed to list reports: {e}")
            raise
    
    def dump_flows(
        self,
        report_ids: Optional[List[str]] = None,
        ingested_after: Optional[str] = None,
        ingested_before: Optional[str] = None,
        max_reports: int = 10000,
    ) -> tuple:
        """
        Fetch flows from report documents, unnested into a flat list.

        Returns:
            Tuple of (list of flow dicts with report metadata attached, truncated bool)
        """
        must_clauses: List[Dict[str, Any]] = []

        if report_ids:
            must_clauses.append({"terms": {"report_id": report_ids}})

        if ingested_after or ingested_before:
            range_filter: Dict[str, str] = {}
            if ingested_after:
                range_filter["gte"] = ingested_after
            if ingested_before:
                range_filter["lte"] = ingested_before
            must_clauses.append({"range": {"ingested_at": range_filter}})

        query = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}

        search_body = {
            "query": query,
            "sort": [{"ingested_at": {"order": "desc"}}, {"report_id": {"order": "asc"}}],
            "size": max_reports,
            "track_total_hits": True,
            "_source": {
                "includes": ["report_id", "name", "ingested_at", "extraction.flows"],
                "excludes": ["raw_text", "text_chunks", "chunk_embeddings", "extraction.bundle", "extraction.claims"],
            },
        }

        try:
            response = self.client.search(index=self.index_name, body=search_body)
        except Exception as e:
            if "index_not_found_exception" in str(e):
                logger.warning("Reports index does not exist")
                return [], False
            logger.error(f"Failed to dump flows: {e}")
            raise

        hits = response["hits"]["hits"]
        total_reports = response["hits"]["total"]["value"]
        truncated = total_reports > max_reports

        flows: List[Dict[str, Any]] = []
        for hit in hits:
            source = hit["_source"]
            report_id = source.get("report_id", "")
            report_name = source.get("name", "")
            ingested_at = source.get("ingested_at", "")
            report_flows = source.get("extraction", {}).get("flows", [])

            for flow in report_flows:
                if not isinstance(flow, dict):
                    continue
                # Copy to avoid mutating the OpenSearch response
                enriched = {**flow}
                enriched["source_id"] = report_id
                enriched["report_name"] = report_name
                enriched["ingested_at"] = ingested_at
                if "confidence" not in enriched or enriched["confidence"] is None:
                    enriched["confidence"] = 0.5
                flows.append(enriched)

        return flows, truncated

    def search_reports(
        self,
        query: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Full-text search across reports.
        
        Args:
            query: Search query
            limit: Maximum number of results
        
        Returns:
            List of matching reports
        """
        search_body = {
            "query": {
                "multi_match": {
                    "query": query,
                    "fields": [
                        "name^3",
                        "description^2",
                        "techniques",
                        "actors",
                        "software",
                        "review.notes"
                    ],
                    "type": "best_fields"
                }
            },
            "size": limit,
            "_source": {
                "excludes": ["extraction.bundle", "extraction.claims"]
            }
        }
        
        try:
            response = self.client.search(
                index=self.index_name,
                body=search_body
            )
            
            reports = []
            for hit in response["hits"]["hits"]:
                report = hit["_source"]
                report["_score"] = hit["_score"]
                reports.append(report)
            
            return reports
        except Exception as e:
            logger.error(f"Failed to search reports: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get aggregate statistics about reports.
        
        Returns:
            Statistics dictionary
        """
        aggs_body = {
            "size": 0,
            "aggs": {
                "by_status": {
                    "terms": {"field": "status"}
                },
                "with_campaigns": {
                    "filter": {"exists": {"field": "campaign.id"}}
                },
                "with_flows": {
                    "filter": {"exists": {"field": "flow.id"}}
                },
                "recent_7_days": {
                    "filter": {
                        "range": {
                            "ingested_at": {
                                "gte": "now-7d"
                            }
                        }
                    }
                },
                "avg_techniques": {
                    "avg": {"field": "extraction.techniques_count"}
                },
                "avg_confidence": {
                    "avg": {"field": "extraction.confidence_avg"}
                }
            }
        }
        
        try:
            response = self.client.search(
                index=self.index_name,
                body=aggs_body
            )
            
            aggs = response["aggregations"]
            
            # Parse status counts
            status_counts = {
                bucket["key"]: bucket["doc_count"]
                for bucket in aggs.get("by_status", {}).get("buckets", [])
            }
            
            return {
                "total_reports": response["hits"]["total"]["value"],
                "by_status": status_counts,
                "with_campaigns": aggs["with_campaigns"]["doc_count"],
                "with_flows": aggs["with_flows"]["doc_count"],
                "recent_7_days": aggs["recent_7_days"]["doc_count"],
                "avg_techniques": aggs["avg_techniques"]["value"] or 0,
                "avg_confidence": aggs["avg_confidence"]["value"] or 0
            }
        except Exception as e:
            if "index_not_found_exception" in str(e):
                logger.warning(f"Reports index does not exist")
                return {
                    "total_reports": 0,
                    "by_status": {},
                    "with_campaigns": 0,
                    "with_flows": 0,
                    "recent_7_days": 0,
                    "avg_techniques": 0,
                    "avg_confidence": 0
                }
            logger.error(f"Failed to get statistics: {e}")
            raise
    
    def delete_report(self, report_id: str) -> bool:
        """
        Delete a report from OpenSearch.
        
        Args:
            report_id: Report ID to delete
        
        Returns:
            True if deleted, False otherwise
        """
        try:
            response = self.client.delete(
                index=self.index_name,
                id=report_id
            )
            logger.info(f"Deleted report {report_id}")
            return True
        except Exception as e:
            if "404" in str(e):
                logger.warning(f"Report {report_id} not found for deletion")
                return False
            logger.error(f"Failed to delete report {report_id}: {e}")
            raise