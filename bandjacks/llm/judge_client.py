"""LLM Judge client for technique pair direction disambiguation."""

import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from bandjacks.llm.client import LLMClient, call_llm, validate_json_response
from bandjacks.llm.evidence_pack import EvidencePack

logger = logging.getLogger(__name__)


class VerdictType(Enum):
    """Possible verdict types for technique pair direction."""
    FORWARD = "i->j"  # from_technique precedes to_technique
    REVERSE = "j->i"  # to_technique precedes from_technique  
    BIDIRECTIONAL = "bidirectional"  # both directions valid
    UNKNOWN = "unknown"  # insufficient evidence


@dataclass
class JudgeVerdict:
    """Structured verdict from LLM judge."""
    from_technique: str
    to_technique: str
    verdict: VerdictType
    confidence: float  # 0.0 to 1.0
    evidence_ids: List[str]  # Citation to evidence snippets
    rationale_summary: str  # Brief explanation (1-2 sentences)
    
    # Metadata
    model_name: str = ""
    retrieval_hash: str = ""  # Evidence pack hash for reproducibility
    judge_version: str = "1.0"
    judged_at: datetime = field(default_factory=datetime.utcnow)
    cost_tokens: int = 0  # For budget tracking


@dataclass
class JudgeConfig:
    """Configuration for LLM judge."""
    model_name: str = "gemini/gemini-2.5-flash"  # Primary model
    fallback_model: str = "gpt-4o-mini"  # Fallback if primary fails
    temperature: float = 0.1  # Low temperature for consistent results
    max_tokens: int = 2000  # Sufficient for structured responses
    timeout_seconds: int = 30
    
    # Quality controls
    require_evidence_citations: bool = True  # Must cite evidence_ids
    min_rationale_words: int = 10  # Minimum explanation length
    max_retries: int = 2  # Retry failed judgments
    
    # Budget controls
    max_cost_per_judgment: int = 100  # Max tokens per judgment
    enable_caching: bool = True  # Cache by retrieval_hash


class JudgeClient:
    """Client for LLM-based technique pair direction judging."""
    
    def __init__(
        self, 
        config: Optional[JudgeConfig] = None,
        cache: Optional[Any] = None  # Type hint as Any to avoid circular import
    ):
        """
        Initialize judge client.
        
        Args:
            config: Judge configuration (uses defaults if None)
            cache: Optional judge verdict cache for performance (JudgeVerdictCache instance)
        """
        self.config = config or JudgeConfig()
        self.llm_client = LLMClient()
        self.cache = cache
        
        # Override model if specified in config
        if self.config.model_name != "gemini/gemini-2.5-flash":
            self.llm_client.model = self.config.model_name
        
        # Judgment schema for validation
        self.verdict_schema = {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["i->j", "j->i", "bidirectional", "unknown"]
                },
                "confidence": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0
                },
                "evidence_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 0
                },
                "rationale_summary": {
                    "type": "string",
                    "minLength": 10
                }
            },
            "required": ["verdict", "confidence", "evidence_ids", "rationale_summary"],
            "additionalProperties": False
        }
        
        # Judgment statistics
        self.judgments_made = 0
        self.total_cost_tokens = 0
        self.cache_hits = 0
        
    def judge_pair(
        self,
        evidence_pack: EvidencePack,
        scope_context: Optional[str] = None
    ) -> JudgeVerdict:
        """
        Judge a technique pair using provided evidence.
        
        Args:
            evidence_pack: Complete evidence package for the pair
            scope_context: Optional scope context (e.g., "APT29 intrusion set")
            
        Returns:
            Structured verdict with reasoning
            
        Raises:
            RuntimeError: If judgment fails after retries
        """
        from_tech = evidence_pack.pair["from_technique"]
        to_tech = evidence_pack.pair["to_technique"]
        
        logger.debug(f"Judging pair {from_tech} -> {to_tech}")
        
        # Check cache first if enabled
        if self.cache and self.config.enable_caching:
            cached_verdict = self.cache.get_cached_verdict(
                from_tech, to_tech, evidence_pack.retrieval_hash
            )
            if cached_verdict:
                self.cache_hits += 1
                logger.debug(f"Using cached verdict for {from_tech}->{to_tech}")
                return cached_verdict
        
        # Build context-rich prompt
        judgment_prompt = self._build_judgment_prompt(evidence_pack, scope_context)
        
        # Attempt judgment with retries
        for attempt in range(self.config.max_retries + 1):
            try:
                response = self._call_llm_judge(judgment_prompt)
                verdict = self._parse_and_validate_verdict(response, evidence_pack)
                
                # Apply quality controls
                if self._passes_quality_checks(verdict, evidence_pack):
                    self.judgments_made += 1
                    
                    # Cache the verdict if caching is enabled
                    if self.cache and self.config.enable_caching:
                        try:
                            self.cache.cache_verdict(verdict)
                        except Exception as e:
                            logger.warning(f"Failed to cache verdict: {e}")
                    
                    logger.info(f"Judgment complete: {verdict.verdict.value} (confidence: {verdict.confidence:.2f})")
                    return verdict
                else:
                    logger.warning(f"Quality check failed on attempt {attempt + 1}")
                    if attempt < self.config.max_retries:
                        continue
                    else:
                        # Return unknown verdict if quality checks keep failing
                        return self._create_unknown_verdict(evidence_pack)
                        
            except Exception as e:
                logger.warning(f"Judge attempt {attempt + 1} failed: {e}")
                if attempt < self.config.max_retries:
                    continue
                else:
                    logger.error(f"All judge attempts failed for {from_tech}->{to_tech}")
                    raise RuntimeError(f"Judgment failed after {self.config.max_retries + 1} attempts: {e}")
    
    def batch_judge_pairs(
        self,
        evidence_packs: List[EvidencePack],
        scope_context: Optional[str] = None,
        parallel: bool = False
    ) -> List[JudgeVerdict]:
        """
        Judge multiple pairs in batch.
        
        Args:
            evidence_packs: List of evidence packages to judge
            scope_context: Optional scope context
            parallel: Whether to process in parallel (not implemented yet)
            
        Returns:
            List of verdicts in same order as input
        """
        verdicts = []
        
        for i, evidence_pack in enumerate(evidence_packs):
            try:
                verdict = self.judge_pair(evidence_pack, scope_context)
                verdicts.append(verdict)
                
                logger.debug(f"Batch progress: {i + 1}/{len(evidence_packs)}")
                
            except Exception as e:
                logger.error(f"Batch judgment failed for pack {i}: {e}")
                # Add unknown verdict for failed judgments
                verdicts.append(self._create_unknown_verdict(evidence_pack))
        
        logger.info(f"Batch judgment complete: {len(verdicts)} verdicts")
        return verdicts
    
    def _build_judgment_prompt(
        self,
        evidence_pack: EvidencePack,
        scope_context: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Build context-rich prompt for LLM judge."""
        
        from_tech = evidence_pack.pair["from_technique"]
        to_tech = evidence_pack.pair["to_technique"]
        
        # System prompt with clear instructions
        system_prompt = """You are a cybersecurity expert analyzing attack technique sequences. 
        
Your task is to determine the temporal relationship between two MITRE ATT&CK techniques based on provided evidence.

VERDICT OPTIONS:
- "i->j": Technique i typically precedes technique j in attack sequences
- "j->i": Technique j typically precedes technique i in attack sequences  
- "bidirectional": Both directions are valid depending on context
- "unknown": Insufficient evidence to determine relationship

REQUIREMENTS:
1. Base your verdict on the provided evidence snippets
2. MUST cite specific evidence_ids that support your conclusion
3. If no evidence supports a directional claim, return "unknown"
4. Provide a concise rationale (1-2 sentences)
5. Confidence should reflect evidence strength (0.0 = no confidence, 1.0 = very confident)

RESPOND ONLY WITH VALID JSON:
{
  "verdict": "i->j" | "j->i" | "bidirectional" | "unknown",
  "confidence": 0.0-1.0,
  "evidence_ids": ["snippet-1", "snippet-2", ...],
  "rationale_summary": "Brief explanation based on evidence"
}"""
        
        # Build evidence context
        evidence_text = self._format_evidence_for_prompt(evidence_pack)
        
        # Scope context if provided
        scope_text = ""
        if scope_context:
            scope_text = f"\nSCOPE: This analysis is focused on {scope_context}.\n"
        
        user_prompt = f"""Analyze the temporal relationship between these techniques:

TECHNIQUE i: {from_tech}
TECHNIQUE j: {to_tech}
{scope_text}
{evidence_text}

Determine whether i precedes j, j precedes i, both are valid, or there's insufficient evidence."""
        
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    
    def _format_evidence_for_prompt(self, evidence_pack: EvidencePack) -> str:
        """Format evidence pack for LLM consumption."""
        
        sections = []
        
        # Statistical evidence
        if evidence_pack.statistics:
            stats = evidence_pack.statistics
            sections.append(f"""STATISTICAL EVIDENCE:
- Asymmetry score: {stats.get('asymmetry', 0):.3f}
- Forward probability P(j|i): {stats.get('forward_prob', 0):.3f}  
- Reverse probability P(i|j): {stats.get('reverse_prob', 0):.3f}
- Co-occurrence count: {stats.get('co_occurrence_count', 0)}""")
        
        # Tactic context
        if evidence_pack.tactic_context:
            tactic = evidence_pack.tactic_context
            sections.append(f"""TACTIC CONTEXT:
- From tactic: {tactic.get('from_tactic', 'unknown')}
- To tactic: {tactic.get('to_tactic', 'unknown')}
- Tactic distance: {tactic.get('tactic_distance', 'unknown')}
- Kill chain progression: {tactic.get('kill_chain_progression', 'unknown')}""")
        
        # Technique details
        details_text = []
        for tech_id, details in evidence_pack.technique_details.items():
            details_text.append(f"- {tech_id}: {details.name} ({details.tactic})")
        
        if details_text:
            sections.append(f"TECHNIQUE DETAILS:\n" + "\n".join(details_text))
        
        # Graph hints
        if evidence_pack.graph_hints:
            hints_text = "\n".join(f"- {hint}" for hint in evidence_pack.graph_hints)
            sections.append(f"KNOWLEDGE GRAPH HINTS:\n{hints_text}")
        
        # Evidence snippets (most important)
        snippets_text = []
        if evidence_pack.evidence_snippets:
            for snippet in evidence_pack.evidence_snippets[:10]:  # Limit to top 10
                snippets_text.append(
                    f"[{snippet.doc_id}] {snippet.text[:200]}... (score: {snippet.score:.2f})"
                )
            
            sections.append(f"""EVIDENCE SNIPPETS:
{chr(10).join(snippets_text)}

Available evidence_ids: {[s.doc_id for s in evidence_pack.evidence_snippets]}""")
        else:
            sections.append("EVIDENCE SNIPPETS:\nNo evidence snippets available.\n\nAvailable evidence_ids: []")
        
        # Historical flows
        if evidence_pack.historical_flows:
            flow_text = []
            for flow in evidence_pack.historical_flows[:3]:  # Limit to top 3
                flow_text.append(f"- Flow {flow.get('flow_id', 'unknown')}: {len(flow.get('techniques', []))} techniques")
            
            sections.append(f"HISTORICAL FLOWS:\n" + "\n".join(flow_text))
        
        return "\n\n".join(sections)
    
    def _call_llm_judge(self, messages: List[Dict[str, str]]) -> str:
        """Call LLM with judgment prompt."""
        
        try:
            # Use primary model with structured output
            response = self.llm_client.call(
                messages=messages,
                response_format={
                    "type": "json_schema",
                    "json_schema": self.verdict_schema
                },
                use_cache=self.config.enable_caching
            )
            
            content = response.get("content", "")
            if not content:
                raise RuntimeError("Empty response from LLM")
            
            # Track token usage
            self.total_cost_tokens += len(content) // 4  # Rough estimate
            
            return content
            
        except Exception as e:
            # Try fallback model if primary fails
            if self.config.fallback_model and self.llm_client.model != self.config.fallback_model:
                logger.warning(f"Primary model failed, trying fallback: {e}")
                
                original_model = self.llm_client.model
                self.llm_client.model = self.config.fallback_model
                
                try:
                    response = self.llm_client.call(
                        messages=messages,
                        response_format={
                            "type": "json_schema",
                            "json_schema": self.verdict_schema
                        },
                        use_cache=False
                    )
                    content = response.get("content", "")
                    if content:
                        return content
                finally:
                    self.llm_client.model = original_model
            
            raise RuntimeError(f"LLM judge call failed: {e}")
    
    def _parse_and_validate_verdict(
        self,
        response: str,
        evidence_pack: EvidencePack
    ) -> JudgeVerdict:
        """Parse and validate LLM response into structured verdict."""
        
        # Validate JSON structure
        try:
            verdict_data = validate_json_response(response, self.verdict_schema)
        except ValueError as e:
            raise RuntimeError(f"Invalid verdict JSON: {e}")
        
        # Convert to structured verdict
        try:
            verdict = JudgeVerdict(
                from_technique=evidence_pack.pair["from_technique"],
                to_technique=evidence_pack.pair["to_technique"],
                verdict=VerdictType(verdict_data["verdict"]),
                confidence=float(verdict_data["confidence"]),
                evidence_ids=verdict_data["evidence_ids"],
                rationale_summary=verdict_data["rationale_summary"],
                model_name=self.llm_client.model,
                retrieval_hash=evidence_pack.retrieval_hash,
                cost_tokens=len(response) // 4  # Rough estimate
            )
            
            return verdict
            
        except (ValueError, KeyError) as e:
            raise RuntimeError(f"Failed to create verdict object: {e}")
    
    def _passes_quality_checks(
        self,
        verdict: JudgeVerdict,
        evidence_pack: EvidencePack
    ) -> bool:
        """Apply quality controls to verdict."""
        
        # Check evidence citations requirement
        if self.config.require_evidence_citations and verdict.verdict != VerdictType.UNKNOWN:
            if not verdict.evidence_ids:
                logger.warning("Verdict missing required evidence citations")
                return False
            
            # Verify evidence IDs are valid
            available_ids = {s.doc_id for s in evidence_pack.evidence_snippets}
            for evidence_id in verdict.evidence_ids:
                if evidence_id not in available_ids:
                    logger.warning(f"Invalid evidence ID: {evidence_id}")
                    return False
        
        # Check minimum rationale length
        rationale_words = len(verdict.rationale_summary.split())
        if rationale_words < self.config.min_rationale_words:
            logger.warning(f"Rationale too short: {rationale_words} words")
            return False
        
        # Check confidence bounds
        if not (0.0 <= verdict.confidence <= 1.0):
            logger.warning(f"Confidence out of bounds: {verdict.confidence}")
            return False
        
        return True
    
    def _create_unknown_verdict(self, evidence_pack: EvidencePack) -> JudgeVerdict:
        """Create default unknown verdict for failed cases."""
        return JudgeVerdict(
            from_technique=evidence_pack.pair["from_technique"],
            to_technique=evidence_pack.pair["to_technique"],
            verdict=VerdictType.UNKNOWN,
            confidence=0.0,
            evidence_ids=[],
            rationale_summary="Insufficient evidence to determine temporal relationship.",
            model_name=self.llm_client.model,
            retrieval_hash=evidence_pack.retrieval_hash
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get judgment statistics."""
        return {
            "judgments_made": self.judgments_made,
            "total_cost_tokens": self.total_cost_tokens,
            "cache_hits": self.cache_hits,
            "avg_cost_per_judgment": self.total_cost_tokens / max(self.judgments_made, 1),
            "config": {
                "model_name": self.config.model_name,
                "fallback_model": self.config.fallback_model,
                "require_evidence_citations": self.config.require_evidence_citations,
                "max_retries": self.config.max_retries
            }
        }


def judge_technique_pairs(
    evidence_packs: List[EvidencePack],
    config: Optional[JudgeConfig] = None,
    scope_context: Optional[str] = None
) -> List[JudgeVerdict]:
    """
    Convenience function to judge multiple technique pairs.
    
    Args:
        evidence_packs: List of evidence packages to judge
        config: Judge configuration
        scope_context: Optional scope context
        
    Returns:
        List of judge verdicts
    """
    judge = JudgeClient(config)
    
    try:
        verdicts = judge.batch_judge_pairs(evidence_packs, scope_context)
        
        # Log summary statistics
        stats = judge.get_statistics()
        logger.info(f"Batch judgment complete: {stats}")
        
        return verdicts
        
    except Exception as e:
        logger.error(f"Batch judgment failed: {e}")
        raise