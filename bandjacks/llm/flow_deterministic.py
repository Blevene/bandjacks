"""
Deterministic attack flow builder.

Generates attack flows using tactic ordering and narrative position
without LLM calls. Provides fast, reproducible flow generation based
on kill-chain progression and text position evidence.
"""

import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
from typing import Any, Dict, List, Optional

from bandjacks.llm.constants import get_tactic_order


_NO_POSITION = 999_999  # Sentinel for techniques without line references (sorts last, OpenSearch-safe)


class DeterministicFlowBuilder:
    """
    Builds attack flows deterministically from extraction claims.

    Uses MITRE ATT&CK tactic ordering combined with narrative position
    (earliest line reference) to produce a reproducible action sequence
    with three-tier confidence edges.
    """

    def __init__(self, technique_cache: Any) -> None:
        self._cache = technique_cache

    def build(
        self,
        claims: List[Dict[str, Any]],
        source_id: str = "",
        name: str = "Deterministic Flow",
    ) -> Optional[Dict[str, Any]]:
        """
        Build a deterministic attack flow from extraction claims.

        Args:
            claims: List of claim dicts with external_id, line_refs, confidence.
            source_id: Identifier for the source report.
            name: Human-readable flow name.

        Returns:
            Flow dict with actions, edges, and stats, or None if < 2 unique techniques.
        """
        deduped = self._deduplicate(claims)
        if len(deduped) < 2:
            return None

        actions = self._build_actions(deduped)
        edges = self._build_edges(actions)

        # Compute tier distribution
        tier_dist: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        for e in edges:
            tier_dist[e["tier"]] += 1

        techniques_without_position = sum(
            1 for a in actions if a["narrative_position"] == _NO_POSITION
        )

        return {
            "flow_id": str(uuid.uuid4()),
            "name": name,
            "source_id": source_id,
            "actions": actions,
            "edges": edges,
            "flow_type": "deterministic_full",
            "llm_synthesized": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "stats": {
                "steps_count": len(actions),
                "edges_count": len(edges),
                "tier_distribution": tier_dist,
                "techniques_without_position": techniques_without_position,
            },
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _deduplicate(
        self, claims: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Deduplicate claims by external_id.

        Keeps max confidence and min(line_refs) as narrative_position.
        Empty line_refs → narrative_position = _NO_POSITION (sorted last).
        """
        by_tid: Dict[str, Dict[str, Any]] = {}

        for c in claims:
            tid = c.get("external_id", "")
            if not tid:
                continue

            confidence = c.get("confidence", 0.0)
            line_refs = c.get("line_refs", [])
            narrative_pos = min(line_refs) if line_refs else _NO_POSITION

            if tid not in by_tid:
                by_tid[tid] = {
                    "external_id": tid,
                    "confidence": float(confidence),
                    "narrative_position": narrative_pos,
                    "name": c.get("name", ""),
                }
            else:
                existing = by_tid[tid]
                if confidence > existing["confidence"]:
                    existing["confidence"] = confidence
                if narrative_pos < existing["narrative_position"]:
                    existing["narrative_position"] = narrative_pos

        return list(by_tid.values())

    def _resolve_tactic(self, external_id: str) -> Optional[str]:
        """Resolve primary tactic from technique cache."""
        entry = self._cache.get(external_id)
        if entry and entry.get("tactic"):
            return entry["tactic"]
        return None

    def _build_actions(
        self, deduped: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Build sorted action list from deduplicated claims."""
        enriched = []
        for item in deduped:
            tid = item["external_id"]
            tactic = self._resolve_tactic(tid)
            tactic_rank = get_tactic_order(tactic) if tactic else 7

            cache_entry = self._cache.get(tid)
            resolved_name = (
                cache_entry["name"] if cache_entry else item.get("name", tid)
            )

            enriched.append(
                {
                    "external_id": tid,
                    "confidence": item["confidence"],
                    "narrative_position": item["narrative_position"],
                    "tactic": tactic,
                    "tactic_rank": tactic_rank,
                    "name": resolved_name,
                    "attack_pattern_ref": f"attack-pattern--{tid}",
                }
            )

        # Sort by (tactic_rank, narrative_position, external_id)
        enriched.sort(
            key=lambda x: (
                x["tactic_rank"],
                x["narrative_position"],
                x["external_id"],
            )
        )

        actions = []
        for i, item in enumerate(enriched):
            actions.append(
                {
                    "action_id": str(uuid.uuid4()),
                    "order": i,
                    "attack_pattern_ref": item["attack_pattern_ref"],
                    "name": item["name"],
                    "confidence": float(item["confidence"]),
                    "tactic": item["tactic"],
                    "tactic_rank": item["tactic_rank"],
                    "narrative_position": item["narrative_position"],
                    "description": "",
                    "evidence": [],
                    "reason": "",
                }
            )

        return actions

    def _build_edges(
        self, actions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Build edges between consecutive actions with three-tier confidence.

        - high (p=0.8): tactic_forward AND position_forward
        - medium (p=0.5): same_tactic
        - low (p=0.25): everything else
        - Self-loop guard: skip edge if same attack_pattern_ref
        """
        edges = []
        for i in range(len(actions) - 1):
            src = actions[i]
            dst = actions[i + 1]

            # Self-loop guard
            if src["attack_pattern_ref"] == dst["attack_pattern_ref"]:
                continue

            tactic_forward = dst["tactic_rank"] > src["tactic_rank"]
            same_tactic = dst["tactic_rank"] == src["tactic_rank"]
            position_forward = dst["narrative_position"] > src["narrative_position"]

            if tactic_forward and position_forward:
                tier = "high"
                probability = 0.8
            elif same_tactic:
                tier = "medium"
                probability = 0.5
            else:
                tier = "low"
                probability = 0.25

            edges.append(
                {
                    "edge_id": str(uuid.uuid4()),
                    "source_action_id": src["action_id"],
                    "target_action_id": dst["action_id"],
                    "probability": probability,
                    "tier": tier,
                    "source_ref": src["attack_pattern_ref"],
                    "target_ref": dst["attack_pattern_ref"],
                }
            )

        return edges


def build_dual_flows(
    claims: list,
    technique_cache,
    flow_builder=None,
    extraction_data: dict = None,
    report_text: str = "",
    source_id: str = None,
    flow_name: str = "Deterministic Attack Flow",
) -> list:
    """Build both deterministic and LLM flows.

    Args:
        claims: Extraction claims for deterministic flow
        technique_cache: TechniqueCache instance
        flow_builder: Optional FlowBuilder for LLM synthesis
        extraction_data: Extraction data dict for LLM flow
        report_text: Report text for LLM flow context
        source_id: Report ID
        flow_name: Name for deterministic flow

    Returns:
        List of flow dicts (1-2 flows). Deterministic first, then LLM if successful.
    """
    flows = []

    # Always: deterministic full flow
    det_builder = DeterministicFlowBuilder(technique_cache)
    det_flow = det_builder.build(claims, source_id or "", flow_name)
    if det_flow:
        flows.append(det_flow)
        logger.info(
            "Deterministic flow: %d steps, tiers: %s",
            det_flow["stats"]["steps_count"],
            det_flow["stats"]["tier_distribution"],
        )

    # Attempt: LLM synthesis (if flow_builder provided)
    if flow_builder and extraction_data:
        try:
            llm_flow = flow_builder.build_from_extraction(
                extraction_data=extraction_data,
                source_id=source_id,
                report_text=report_text,
                use_stored_text=False,
            )
            if llm_flow:
                flows.append(llm_flow)
                logger.info("LLM flow: %d steps", len(llm_flow.get("actions", [])))
        except Exception as e:
            logger.warning("LLM flow synthesis failed: %s", e)

    logger.info("build_dual_flows produced %d flow(s)", len(flows))
    return flows
