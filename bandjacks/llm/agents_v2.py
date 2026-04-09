"""Core extraction agents for the LLM pipeline.

Module Status: PRODUCTION
Contains all primary extraction agents used in the production pipeline:
SpanFinderAgent, BatchRetrieverAgent, DiscoveryAgent, BatchMapperAgent,
EvidenceVerifierAgent, ConsolidatorAgent, and AssemblerAgent.
"""

import re
import json
import logging
import time
from typing import Any, Dict, List

from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.tools import list_tactics
from bandjacks.llm.flow_builder import FlowBuilder
from bandjacks.llm.consolidator_base import ConsolidatorBase
from bandjacks.llm.keyword_index import KeywordIndex
from bandjacks.llm.technique_pairs import TechniquePairValidator
from bandjacks.llm.client import record_usage_to_tracker

logger = logging.getLogger(__name__)

TECH_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Section-aware priors (used to weight spans from likely TTP sections)
SECTIONS = [("ttp", 1.2), ("technique", 1.15), ("procedure", 1.15), ("analysis", 1.1)]

def _section_weight(line: str) -> float:
    lower = line.lower()
    for key, w in SECTIONS:
        if key in lower:
            return w
    return 1.0


class SpanFinderAgent:
    """Find spans likely to contain TTPs using comprehensive behavioral patterns."""
    
    def __init__(self):
        # Explicit technique ID pattern
        self.technique_pattern = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
        
        # Reconnaissance patterns
        self.recon_patterns = re.compile(
            r"\b(scan|enumerat|discover|reconnaissan|fingerprint|probe|collect\s+information|" +
            r"gather\s+data|osint|dns\s+query|whois|nmap|shodan|search\s+for)\b", re.I
        )
        
        # Initial Access patterns
        self.initial_access = re.compile(
            r"\b(phishing|spearphish|attach|malicious\s+link|exploit|vulnerability|cve-|" +
            r"watering\s+hole|supply\s+chain|trojan|backdoor|remote\s+desktop|rdp|ssh)\b", re.I
        )
        
        # Execution patterns
        self.execution = re.compile(
            r"\b(powershell|cmd|bash|script|execute|run|launch|invoke|eval|exec|" +
            r"wmic|schtasks|rundll32|regsvr32|mshta|cscript|wscript|python|perl)\b", re.I
        )
        
        # Persistence patterns
        self.persistence = re.compile(
            r"\b(persistence|startup|registry|scheduled\s+task|service|autorun|boot|" +
            r"logon\s+script|backdoor|implant|rootkit|bootkit|create\s+account)\b", re.I
        )
        
        # Privilege Escalation patterns
        self.priv_esc = re.compile(
            r"\b(privilege|escalat|elevat|admin|root|sudo|uac|bypass|token|" +
            r"impersonat|credentials|lsass|sam|ntds|mimikatz|kerberos)\b", re.I
        )
        
        # Defense Evasion patterns
        self.defense_evasion = re.compile(
            r"\b(evad|evasi|obfuscat|encrypt|encod|pack|compress|hide|masquerad|" +
            r"disable\s+security|bypass\s+detection|anti-virus|amsi|etw|clear\s+log)\b", re.I
        )
        
        # Credential Access patterns
        self.cred_access = re.compile(
            r"\b(credential|password|hash|dump|steal|harvest|keylog|brute\s+force|" +
            r"dictionary\s+attack|rainbow|crack|extract\s+credentials)\b", re.I
        )
        
        # Discovery patterns
        self.discovery = re.compile(
            r"\b(discover|enumerat|list|query|reconnaissance|scan\s+network|" +
            r"find\s+files|locate|search|dir|ls|net\s+view|net\s+user|whoami)\b", re.I
        )
        
        # Lateral Movement patterns
        self.lateral = re.compile(
            r"\b(lateral|move|spread|propagat|pivot|jump|hop|remote\s+exec|psexec|" +
            r"wmi|winrm|ssh|rdp|smb|share|net\s+use)\b", re.I
        )
        
        # Collection patterns
        self.collection = re.compile(
            r"\b(collect|gather|harvest|steal|exfiltrat|archive|compress|zip|rar|" +
            r"screenshot|keylog|clipboard|record|capture)\b", re.I
        )
        
        # Command and Control patterns
        self.c2 = re.compile(
            r"\b(c2|command\s+and\s+control|c&c|beacon|callback|phone\s+home|" +
            r"bot|zombie|http|https|dns|tunnel|covert\s+channel|telegram|discord)\b", re.I
        )
        
        # Exfiltration patterns
        self.exfil = re.compile(
            r"\b(exfiltrat|transfer|upload|send\s+data|leak|steal\s+data|" +
            r"data\s+theft|ftp|sftp|cloud\s+storage|dropbox|gdrive)\b", re.I
        )
        
        # Impact patterns
        self.impact = re.compile(
            r"\b(ransom|encrypt|wipe|destroy|delete|corrupt|deface|dos|ddos|" +
            r"denial\s+of\s+service|sabotage|disrupt)\b", re.I
        )
        
        # All patterns for scoring
        self.all_patterns = [
            (self.recon_patterns, "reconnaissance", 0.7),
            (self.initial_access, "initial-access", 0.9),
            (self.execution, "execution", 0.85),
            (self.persistence, "persistence", 0.85),
            (self.priv_esc, "privilege-escalation", 0.8),
            (self.defense_evasion, "defense-evasion", 0.8),
            (self.cred_access, "credential-access", 0.85),
            (self.discovery, "discovery", 0.6),
            (self.lateral, "lateral-movement", 0.85),
            (self.collection, "collection", 0.75),
            (self.c2, "command-and-control", 0.9),
            (self.exfil, "exfiltration", 0.85),
            (self.impact, "impact", 0.95)
        ]

        # Keyword index for direct keyword→technique matching
        try:
            self.keyword_index = KeywordIndex()
        except FileNotFoundError:
            self.keyword_index = None
            logger.warning("Keyword index not available — running without keyword hints")

    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        """Find behavioral spans with sentence-based context extraction."""
        
        # Build full text for sentence extraction
        full_text = '\n'.join(mem.line_index) if mem.line_index else mem.document_text
        
        # Process each line and extract sentence-based evidence
        for idx, line in enumerate(mem.line_index):
            if not line.strip():
                continue
                
            # Score line for TTP likelihood
            score = 0.0
            tactics = []
            
            # Check for explicit technique IDs first (highest priority)
            if self.technique_pattern.search(line):
                score = 2.0  # Guaranteed inclusion
                tactics.append("explicit-technique")
            
            for pattern, tactic, weight in self.all_patterns:
                if pattern.search(line):
                    score += weight
                    tactics.append(tactic)

            # Keyword index matching — direct keyword→technique hints
            keyword_hints = []
            if self.keyword_index:
                kw_matches = self.keyword_index.match_text(line, max_matches=10)
                if kw_matches:
                    keyword_hints = kw_matches
                    kw_boost = min(len(kw_matches) * 0.3, 1.0)
                    score += kw_boost
                    tactics.append("keyword-match")

            # Add span if score threshold met
            if score >= 0.6:
                # Use sentence-based extraction instead of single line
                evidence = ConsolidatorBase.extract_sentence_for_line(
                    full_text,
                    mem.line_index,
                    idx + 1,  # 1-indexed line number
                    context_sentences=1  # Include 1 sentence before/after
                )
                
                # Only add if we got meaningful evidence
                if evidence.get("quote"):
                    mem.spans.append({
                        "text": evidence["quote"],
                        "line_refs": evidence["line_refs"],
                        "score": min(score, 1.0),
                        "tactics": tactics,
                        "prior": _section_weight(line),
                        "type": "sentence_based",
                        "keyword_hints": keyword_hints,
                    })
        
        # Multi-line context aggregation for complex behaviors
        self._aggregate_context_spans(mem)
        
        # Entity-based spans (actor -> action sequences)
        self._create_entity_spans(mem)
        
        # Sort spans by score
        mem.spans.sort(key=lambda x: x.get("score", 0), reverse=True)
    
    def _aggregate_context_spans(self, mem: WorkingMemory):
        """Aggregate consecutive lines that form behavioral sequences using sentence extraction."""

        # Build full text for sentence extraction
        full_text = '\n'.join(mem.line_index) if mem.line_index else mem.document_text

        # Precompute cumulative character offsets
        char_offsets = [0]
        for line in mem.line_index:
            char_offsets.append(char_offsets[-1] + len(line) + 1)

        # Look for multi-step sequences
        window_size = 5
        for i in range(len(mem.line_index) - window_size + 1):
            window_text = " ".join(mem.line_index[i:i+window_size])

            # Check for attack chains
            if ("download" in window_text.lower() and "execute" in window_text.lower()) or \
               ("encrypt" in window_text.lower() and "ransom" in window_text.lower()) or \
               ("credential" in window_text.lower() and "lateral" in window_text.lower()):

                # Calculate character position for middle of window
                char_pos = char_offsets[i + window_size // 2]
                
                # Extract sentence-based evidence for this window
                evidence = ConsolidatorBase.extract_sentence_evidence(
                    full_text,
                    char_pos,
                    context_sentences=2  # More context for multi-stage attacks
                )
                
                if evidence.get("quote"):
                    mem.spans.append({
                        "text": evidence["quote"],
                        "line_refs": evidence["line_refs"],
                        "score": 0.9,
                        "tactics": ["multi-stage"],
                        "prior": 1.05,
                        "type": "sentence_based_aggregate"
                    })
    
    def _create_entity_spans(self, mem: WorkingMemory):
        """Create spans based on entity mentions and their actions using sentence extraction."""

        # Build full text for sentence extraction
        full_text = '\n'.join(mem.line_index) if mem.line_index else mem.document_text

        # Precompute cumulative character offsets
        char_offsets = [0]
        for line in mem.line_index:
            char_offsets.append(char_offsets[-1] + len(line) + 1)

        # Find entity mentions - expanded to include more threat actors and malware
        entity_pattern = re.compile(
            r"\b(APT\d+|TA\d+|FIN\d+|UNC\d+|" +  # Standard threat actor naming
            r"threat actor|attacker|adversary|threat group|intrusion set|" +  # Generic terms
            r"malware|trojan|ransomware|backdoor|RAT|rootkit|worm|virus)\b", re.I  # Specific malware
        )

        for idx, line in enumerate(mem.line_index):
            if entity_pattern.search(line):
                # Calculate character position for this line
                char_pos = char_offsets[idx]
                
                # Find position of entity mention in line
                match = entity_pattern.search(line)
                if match:
                    char_pos += match.start()
                
                # Extract sentence-based context around entity mention
                evidence = ConsolidatorBase.extract_sentence_evidence(
                    full_text,
                    char_pos,
                    context_sentences=2  # Include surrounding context for entity actions
                )
                
                if evidence.get("quote") and len(evidence["quote"]) > 50:  # Meaningful context
                    mem.spans.append({
                        "text": evidence["quote"],
                        "line_refs": evidence["line_refs"],
                        "score": 0.8,
                        "tactics": ["entity-action"],
                        "prior": 1.05,
                        "type": "sentence_based_entity"
                    })


class DiscoveryAgent:
    """Use LLM to discover techniques not found by retrieval."""

    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        logger.debug(f"DiscoveryAgent: Processing {len(mem.spans)} spans")
        max_props = int(config.get("max_discovery_per_span", 3))

        from bandjacks.llm.client import get_llm_client
        from bandjacks.llm.tools import resolve_technique_by_external_id
        client = get_llm_client()
        discovery_model = config.get("discovery_model", "gemini/gemini-2.5-flash")

        # Collect spans that need discovery (local index → original index)
        needs_discovery: List[tuple] = []  # (local_idx, original_idx, span)
        for i, span in enumerate(mem.spans):
            existing_candidates = mem.candidates.get(i, [])
            if len(existing_candidates) >= 5 and any(c.get("score", 0) > 0.7 for c in existing_candidates):
                continue
            needs_discovery.append((len(needs_discovery), i, span))

        if not needs_discovery:
            logger.debug("DiscoveryAgent: All spans have sufficient candidates, skipping")
            return

        logger.debug(f"DiscoveryAgent: Batching {len(needs_discovery)} spans into single LLM call")

        # Build numbered span list (truncated to 300 chars each)
        span_lines = []
        for local_idx, orig_idx, span in needs_discovery:
            text = span["text"][:300].replace("\n", " ")
            span_lines.append(f"{local_idx}: {text}")
        spans_block = "\n".join(span_lines)

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a MITRE ATT&CK expert. For each numbered text span, identify ATT&CK "
                    "technique IDs that are mentioned or clearly implied. "
                    'Output ONLY valid JSON matching: {"discoveries": [{"span": 0, "techniques": ["T1055"]}]}'
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Analyze these {len(needs_discovery)} text spans and identify ATT&CK techniques:\n\n"
                    f"{spans_block}\n\n"
                    "Return a discoveries array with one entry per span (use the span number as the key)."
                ),
            },
        ]

        discovery_schema = {
            "type": "object",
            "properties": {
                "discoveries": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "span": {"type": "integer"},
                            "techniques": {
                                "type": "array",
                                "items": {
                                    "type": "string",
                                    "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$",
                                },
                            },
                        },
                        "required": ["span", "techniques"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["discoveries"],
            "additionalProperties": False,
        }

        try:
            tracker = config.get("_tracker")
            _start = time.time()
            response = client.call(
                messages,
                model=discovery_model,
                response_format={
                    "type": "json_schema",
                    "json_schema": discovery_schema,
                },
                max_tokens=4000,
            )
            record_usage_to_tracker(response, tracker, int((time.time() - _start) * 1000))

            content = response.get("content", "")
            if not content:
                logger.warning("DiscoveryAgent: Empty response from LLM batch call")
                return

            result = json.loads(content.strip())
            discoveries = result.get("discoveries", [])

            # Build a lookup from local_idx → original_idx
            local_to_orig = {local_idx: orig_idx for local_idx, orig_idx, _ in needs_discovery}

            for entry in discoveries:
                local_idx = entry.get("span")
                techniques = entry.get("techniques", [])
                if local_idx not in local_to_orig:
                    continue
                orig_idx = local_to_orig[local_idx]

                mem.candidates.setdefault(orig_idx, [])
                seen = {c.get("external_id") for c in mem.candidates[orig_idx]}

                for tech_id in techniques[:max_props]:
                    if not isinstance(tech_id, str) or not TECH_ID_RE.match(tech_id):
                        continue
                    if tech_id in seen:
                        continue

                    meta = resolve_technique_by_external_id(tech_id)
                    mem.candidates[orig_idx].append({
                        "external_id": tech_id,
                        "name": meta.get("name", "") if meta else "",
                        "score": 0.5,
                        "meta": meta,
                        "source": "discovery",
                    })
                    seen.add(tech_id)
                    logger.debug(f"  DiscoveryAgent: Added {tech_id} to span {orig_idx}")

        except Exception as e:
            logger.warning(f"DiscoveryAgent: Batch LLM call failed: {e}")


from bandjacks.llm.tools import resolve_technique_by_external_id


class EvidenceVerifierAgent:
    """Verify evidence quality and semantic relevance."""

    # Default minimum cosine similarity between span text and technique *name*
    # for a claim to be considered semantically relevant.  Can be overridden
    # via config["relevance_threshold"].  Cloud models (Gemini, GPT) produce
    # richer span text that scores higher — use 0.20.  Local/smaller models
    # produce shorter spans — use 0.10 or lower.
    DEFAULT_RELEVANCE_THRESHOLD = 0.20

    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        logger.debug(f"EvidenceVerifierAgent: Starting with {len(mem.claims)} claims")
        valid = []
        rejected = []
        min_quotes = config.get("min_quotes", 2)
        relevance_threshold = config.get("relevance_threshold", self.DEFAULT_RELEVANCE_THRESHOLD)
        WINDOW = 2

        # Pre-compute semantic relevance scores for all claims in one batch
        relevance_scores = self._batch_relevance_scores(mem.claims, config)

        for idx, claim in enumerate(mem.claims):
            # Check technique resolution
            meta = resolve_technique_by_external_id(claim["external_id"])
            if not meta:
                continue

            # Verify quotes exist and are relevant
            valid_quotes = []
            for q in claim["quotes"]:
                if not q or q.strip() == "":
                    continue
                # Check present in document (case-insensitive allowed)
                if (q in mem.document_text) or (q.lower() in mem.document_text.lower()):
                    valid_quotes.append(q)

            # Verify line references with a small window around each line
            valid_lines = []
            for ln in claim["line_refs"]:
                if not (1 <= ln <= len(mem.line_index)):
                    continue
                start = max(0, ln - 1 - WINDOW)
                end = min(len(mem.line_index), ln - 1 + WINDOW + 1)
                window_text = "\n".join(mem.line_index[start:end])
                if any((q in window_text or q.lower() in window_text.lower()) for q in valid_quotes):
                    valid_lines.append(ln)

            # Score evidence quality
            evidence_score = self._score_evidence(
                valid_quotes,
                valid_lines,
                meta,
                claim.get("confidence", 50),
            )

            # Semantic relevance check: does the span text actually describe
            # the claimed technique?  A low score means the LLM mapped a span
            # to a technique whose description doesn't match the span content.
            sem_score = relevance_scores.get(idx, 1.0)
            if sem_score < relevance_threshold:
                rejected.append({
                    "id": claim["external_id"],
                    "quotes": len(valid_quotes),
                    "score": evidence_score,
                    "conf": claim.get("confidence", 0),
                    "reason": f"semantic_relevance={sem_score:.3f}",
                })
                logger.debug(
                    f"  ✗ Rejected {claim['external_id']}: semantic relevance "
                    f"{sem_score:.3f} < {relevance_threshold}"
                )
                continue

            # Accept if meets minimum quality - relaxed constraints
            if len(valid_quotes) >= min_quotes and evidence_score >= 40:
                claim["quotes"] = valid_quotes
                claim["line_refs"] = valid_lines
                claim["evidence_score"] = evidence_score
                claim["semantic_relevance"] = sem_score
                claim["technique_meta"] = meta
                valid.append(claim)
                logger.debug(f"  ✓ Accepted {claim['external_id']}: {len(valid_quotes)} quotes, score={evidence_score}, rel={sem_score:.3f}")
            elif len(valid_quotes) >= 1 and evidence_score >= 50:  # Relaxed from 60
                claim["quotes"] = valid_quotes
                claim["line_refs"] = valid_lines
                claim["evidence_score"] = evidence_score
                claim["semantic_relevance"] = sem_score
                claim["technique_meta"] = meta
                valid.append(claim)
                logger.debug(f"  ✓ Accepted (relaxed) {claim['external_id']}: 1 quote, score={evidence_score}, rel={sem_score:.3f}")
            elif claim.get("confidence", 0) >= 80 and len(valid_quotes) >= 1 and evidence_score >= 30:
                # High confidence fallback — still require minimal evidence quality
                # to prevent hallucinated techniques from passing on confidence alone
                claim["quotes"] = valid_quotes
                claim["line_refs"] = valid_lines
                claim["evidence_score"] = evidence_score
                claim["semantic_relevance"] = sem_score
                claim["technique_meta"] = meta
                valid.append(claim)
                logger.debug(f"  ✓ Accepted (high conf) {claim['external_id']}: conf={claim['confidence']}, score={evidence_score}, rel={sem_score:.3f}")
            else:
                rejected.append({
                    "id": claim['external_id'],
                    "quotes": len(valid_quotes),
                    "score": evidence_score,
                    "conf": claim.get("confidence", 0)
                })
                logger.debug(f"  ✗ Rejected {claim['external_id']}: quotes={len(valid_quotes)}, score={evidence_score}, conf={claim.get('confidence', 0)}")

        logger.info(f"EvidenceVerifierAgent: {len(valid)} claims passed verification (rejected {len(rejected)})")
        if rejected:
            logger.debug(f"  Rejected details: {rejected[:5]}...")  # Show first 5
        mem.claims = valid

    def _batch_relevance_scores(
        self, claims: list, config: Dict[str, Any]
    ) -> Dict[int, float]:
        """Compute semantic relevance between each claim's span text and technique description.

        Returns a dict mapping claim index → cosine similarity (0-1).
        Scores are computed in a single batch for efficiency.
        """
        if config.get("skip_relevance_check", False):
            return {}  # returns empty → default 1.0 in caller

        try:
            import numpy as np
            from bandjacks.loaders.embedder import batch_encode
            from bandjacks.services.technique_cache import technique_cache
        except ImportError:
            logger.warning("Embedder or numpy not available, skipping relevance check")
            return {}

        try:
            # Collect (span_text, technique_text) pairs for each claim
            pairs: list = []  # (claim_idx, span_text, technique_text)
            for idx, claim in enumerate(claims):
                span_text = " ".join(claim.get("quotes", []))[:500]
                if not span_text.strip():
                    continue
                tid = claim.get("external_id", "")
                cached = technique_cache.get(tid)
                if cached:
                    # Use technique name only — short keyword-like text gives much
                    # cleaner separation than name + long description against short
                    # behavioural span snippets.
                    tech_text = cached.get("name", tid)
                else:
                    tech_text = claim.get("name", tid)
                if tech_text.strip():
                    pairs.append((idx, span_text, tech_text))

            if not pairs:
                return {}

            # Batch encode all texts at once (spans + technique descriptions)
            span_texts = [p[1] for p in pairs]
            tech_texts = [p[2] for p in pairs]
            all_texts = span_texts + tech_texts

            logger.debug(f"Computing semantic relevance for {len(pairs)} claims")
            embeddings = batch_encode(all_texts)

            # Compute cosine similarity for each pair
            scores: Dict[int, float] = {}
            n = len(pairs)
            for i, (claim_idx, _, _) in enumerate(pairs):
                span_emb = embeddings[i]
                tech_emb = embeddings[n + i]
                if span_emb is None or tech_emb is None:
                    continue
                a = np.array(span_emb)
                b = np.array(tech_emb)
                denom = np.linalg.norm(a) * np.linalg.norm(b)
                if denom > 0:
                    sim = float(np.dot(a, b) / denom)
                    scores[claim_idx] = sim

            if scores:
                logger.debug(
                    f"Semantic relevance: min={min(scores.values()):.3f}, "
                    f"max={max(scores.values()):.3f}, "
                    f"mean={sum(scores.values()) / len(scores):.3f}"
                )
            else:
                logger.debug("Semantic relevance: no scores computed")
            return scores

        except Exception as e:
            logger.warning(f"Semantic relevance check failed, skipping: {e}")
            return {}
    
    def _score_evidence(self, quotes: list, lines: list, meta: dict, confidence: int) -> int:
        """Score evidence quality based on multiple factors."""
        score = 0
        
        # Quote quality (up to 40 points)
        if quotes:
            avg_quote_len = sum(len(q) for q in quotes) / len(quotes)
            if avg_quote_len > 50:  # Substantial quotes
                score += 20
            elif avg_quote_len > 20:
                score += 10
            
            # Multiple quotes bonus
            if len(quotes) >= 3:
                score += 20
            elif len(quotes) >= 2:
                score += 10
        
        # Line reference quality (up to 20 points)
        if lines:
            if len(lines) >= 2:  # Multiple line refs
                score += 10
            # Check if lines are close together (context)
            if len(lines) > 1 and max(lines) - min(lines) <= 5:
                score += 10
        
        # Technique metadata quality (up to 20 points)
        if meta:
            if meta.get("name"):
                score += 10
            if meta.get("tactic"):
                score += 10
        
        # Confidence adjustment (up to 20 points)
        if confidence >= 80:
            score += 20
        elif confidence >= 60:
            score += 10
        
        return min(100, score)


def _calibrate_confidence(
    base: int,
    quotes_count: int,
    consensus: int,
    evidence_score: int,
    rank: int | None = None,
    prior: float = 1.0,
) -> int:
    """Calibrate confidence using evidence, consensus, candidate rank, and section prior."""
    score = base
    if quotes_count >= 5:
        score += 15
    elif quotes_count >= 3:
        score += 10
    elif quotes_count >= 2:
        score += 5
    if consensus > 1:
        score += min(consensus - 1, 3) * 5
    if evidence_score >= 80:
        score += 20
    elif evidence_score >= 60:
        score += 10
    elif evidence_score >= 40:
        score += 5
    if rank is not None and rank <= 3:
        score += 5
    score = int(score * max(1.0, prior))
    return max(10, min(100, score))


from bandjacks.llm.consolidator_base import ConsolidatorBase


class ConsolidatorAgent(ConsolidatorBase):
    """Consolidate claims into unique techniques with intelligent evidence merging."""
    
    def __init__(self):
        """Initialize with base consolidator configuration."""
        super().__init__()
    
    # Methods inherited from ConsolidatorBase:
    # - _merge_evidence_intelligently() - uses semantic or Jaccard based on config
    # - _exact_dedup() - removes exact duplicates
    # - _jaccard_dedup() - Jaccard-based deduplication
    # - _calculate_similarity() - Jaccard similarity calculation
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        logger.debug(f"ConsolidatorAgent: Processing {len(mem.claims)} claims")
        by_tech: Dict[str, Dict[str, Any]] = {}
        
        for claim in mem.claims:
            tid = claim["external_id"]
            
            # Track if this is a subtechnique
            is_subtechnique = "." in tid
            
            entry = by_tech.setdefault(
                tid,
                {
                    "name": claim.get("technique_meta", {}).get("name", claim["name"]),
                    "evidence": [],
                    "line_refs": set(),
                    "base_conf": max(50, claim.get("confidence", 50)),
                    "evidence_scores": [],
                    "claim_count": 0,
                    "tactic": claim.get("technique_meta", {}).get("tactic"),
                    "is_subtechnique": is_subtechnique,
                    "chunks_found": set(),  # Track which chunks found this technique
                    "span_indices": set(),   # Track span indices for provenance
                },
            )
            entry["evidence"].extend(claim["quotes"])
            entry["line_refs"].update(claim["line_refs"])
            entry["evidence_scores"].append(claim.get("evidence_score", 50))
            entry["claim_count"] += 1
            
            # Track chunk ID if available (from chunk_id in claim or span metadata)
            if "chunk_id" in claim:
                entry["chunks_found"].add(claim["chunk_id"])
            elif claim.get("span_idx", -1) >= 0 and claim["span_idx"] < len(mem.spans):
                # Try to get chunk_id from span metadata
                span = mem.spans[claim["span_idx"]]
                if "chunk_id" in span:
                    entry["chunks_found"].add(span["chunk_id"])
                entry["span_indices"].add(claim["span_idx"])
        
        logger.debug(f"ConsolidatorAgent: Consolidating {len(by_tech)} unique techniques")
        
        # Consolidate into final techniques with intelligent evidence merging
        for tid, e in by_tech.items():
            # Calculate average evidence score
            avg_evidence_score = sum(e["evidence_scores"]) / len(e["evidence_scores"]) if e["evidence_scores"] else 50
            
            # Intelligent evidence deduplication with semantic similarity
            unique_evidence = self._merge_evidence_intelligently(e["evidence"])
            
            # Boost confidence based on multiple occurrences across chunks
            occurrence_boost = 0
            if len(e["chunks_found"]) > 1:
                # Significant boost for multi-chunk discovery (up to 20 points)
                occurrence_boost = min(20, len(e["chunks_found"]) * 5)
                logger.debug(f"  Technique {tid} found in {len(e['chunks_found'])} chunks, boost: {occurrence_boost}")
            elif e["claim_count"] > 1:
                # Smaller boost for multiple claims in same chunk (up to 10 points)
                occurrence_boost = min(10, e["claim_count"] * 3)
            
            # Derive prior and best candidate rank from contributing claims
            prior_val = 1.0
            best_rank_val = None
            for claim in mem.claims:
                if claim["external_id"] != tid:
                    continue
                if claim.get("span_idx", -1) >= 0:
                    prior_val = max(prior_val, mem.spans[claim["span_idx"]].get("prior", 1.0))
                    for c in mem.candidates.get(claim["span_idx"], []):
                        if c.get("external_id") == tid and c.get("rank") is not None:
                            cr = c["rank"]
                            best_rank_val = cr if best_rank_val is None else min(best_rank_val, cr)

            # Calculate base confidence then add occurrence boost
            base_confidence = _calibrate_confidence(
                e["base_conf"],
                len(unique_evidence),
                e["claim_count"],
                int(avg_evidence_score),
                best_rank_val or 3,
                prior_val,
            )
            final_confidence = min(100, base_confidence + occurrence_boost)
            
            mem.techniques[tid] = {
                "name": e["name"],
                "confidence": final_confidence,
                "evidence": unique_evidence[:10],  # Keep more evidence (up to 10)
                "line_refs": sorted(e["line_refs"]),
                "tactic": e["tactic"],
                "claim_count": e["claim_count"],
                "chunks_found": sorted(e["chunks_found"]) if e["chunks_found"] else [],
                "is_subtechnique": e["is_subtechnique"],
            }
            logger.debug(f"  → {tid}: {e['name']} (conf={final_confidence}, evidence={len(unique_evidence)}, chunks={len(e['chunks_found'])})")
        
        # Optionally deduplicate entire techniques based on similarity
        if self.use_semantic_dedup and hasattr(self, 'semantic_dedup'):
            try:
                from bandjacks.services.api.settings import settings
                if settings.deduplicate_techniques:
                    original_count = len(mem.techniques)
                    mem.techniques = self.semantic_dedup.deduplicate_techniques(mem.techniques)
                    if len(mem.techniques) < original_count:
                        logger.info(f"Semantic deduplication: {original_count} → {len(mem.techniques)} techniques")
            except Exception as e:
                logger.warning(f"Technique deduplication failed: {e}")
        
        logger.info(f"ConsolidatorAgent: Consolidated into {len(mem.techniques)} techniques")

        # Post-consolidation: check for missing technique pairs
        try:
            pair_validator = TechniquePairValidator()
            found_ids = set(mem.techniques.keys())
            suggestions = pair_validator.suggest_missing(found_ids)

            # Also check red flags and commonly missed in original text
            if mem.document_text:
                for rf in pair_validator.match_red_flags(mem.document_text):
                    for tid in rf["techniques"]:
                        if tid not in found_ids and not any(t.startswith(tid) for t in found_ids):
                            suggestions.append({
                                "technique_id": tid,
                                "reason": f"Red flag: '{rf['phrase']}' — {rf['reason']}",
                                "triggered_by": "red-flag",
                            })

                for cm in pair_validator.match_commonly_missed(mem.document_text):
                    for tid in cm["techniques"]:
                        if tid not in found_ids:
                            suggestions.append({
                                "technique_id": tid,
                                "reason": f"Commonly missed: '{cm['indicator']}'",
                                "triggered_by": "commonly-missed",
                            })

            # Deduplicate suggestions
            if suggestions:
                seen = set()
                unique = []
                for s in suggestions:
                    if s["technique_id"] not in seen:
                        seen.add(s["technique_id"])
                        unique.append(s)
                logger.info(f"Pair validator suggests {len(unique)} potentially missing techniques")
                mem.metadata["pair_suggestions"] = unique
        except Exception as e:
            logger.warning(f"Technique pair validation failed: {e}")

        # Kill-chain gap analysis: identify tactics not yet covered
        try:
            covered = set()
            for tid in mem.techniques.keys():
                meta = resolve_technique_by_external_id(tid)
                if meta and meta.get("tactic"):
                    covered.add(meta["tactic"])
            all_tactics = {t["shortname"] for t in list_tactics()}
            missing = sorted(all_tactics - covered)
            mem.notes.append(f"Missing tactics: {', '.join(missing)}")
            # Store suggestions placeholder for future targeted discovery (no commit)
            mem.inferred_suggestions = [{"tactic": t, "candidates": []} for t in missing]
        except Exception as e:
            logger.warning(f"Kill-chain gap analysis failed: {e}")


class AssemblerAgent:
    """Assemble extraction results into STIX bundle with proper structure."""
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> Dict[str, Any]:
        import uuid
        from datetime import datetime
        
        # Build proper STIX bundle
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects = []
        
        # Create report object
        report_id = f"report--{uuid.uuid4()}"
        report = {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": config.get("title", "Extracted Report"),
            "description": f"CTI extracted from {config.get('url', 'document')}",
            "published": datetime.utcnow().isoformat() + "Z",
            "object_refs": [],  # Will be populated
            "x_bj_source": {
                "url": config.get("url", ""),
                "title": config.get("title", "")
            },
            "x_bj_extraction": {
                "method": "agentic_v2",
                "model": config.get("model", "gemini/gemini-2.5-flash"),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        }
        objects.append(report)
        
        # Create attack-pattern objects for each technique
        for tid, info in mem.techniques.items():
            # Generate deterministic STIX ID for technique
            namespace = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')
            stix_id = f"attack-pattern--{uuid.uuid5(namespace, tid)}"
            
            # Build kill_chain_phases if tactic is known
            kill_chain_phases = []
            if info.get("tactic"):
                kill_chain_phases.append({
                    "kill_chain_name": "mitre-attack",
                    "phase_name": info["tactic"]
                })
            
            attack_pattern = {
                "type": "attack-pattern",
                "id": stix_id,
                "spec_version": "2.1",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": info["name"],
                "description": f"Extracted technique: {info['name']}",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tid,
                        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                    }
                ],
                "kill_chain_phases": kill_chain_phases,
                "x_bj_provenance": {
                    "report_id": report_id,
                    "extraction": {
                        "method": "agentic_v2",
                        "model": config.get("model", "gemini/gemini-2.5-flash"),
                        "confidence": info["confidence"]
                    },
                    "evidence": {
                        "text": info.get("evidence", []),
                        "lines": info.get("line_refs", [])
                    }
                },
                "x_bj_confidence": info["confidence"],
                "x_bj_evidence": "\n".join(info.get("evidence", [])),
                "x_bj_line_refs": info.get("line_refs", [])
            }
            
            objects.append(attack_pattern)
            report["object_refs"].append(stix_id)
        
        # Build final bundle
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "objects": objects
        }
        
        # Build attack flow if configured (skip if neo4j not configured)
        flow = None
        if config.get("build_flow", False) and config.get("neo4j_uri"):
            try:
                flowb = FlowBuilder(config["neo4j_uri"], config["neo4j_user"], config["neo4j_password"])
                flow = flowb.build_from_bundle(bundle)
            except Exception as e:
                logger.error(f"Flow building failed: {e}", exc_info=True)
                flow = {}
        else:
            flow = {}
        
        result = {
            "bundle": bundle,
            "flow": flow,
            "techniques": mem.techniques,
            "notes": mem.notes
        }

        # Include technique pair suggestions if available
        if mem.metadata.get("pair_suggestions"):
            result["pair_suggestions"] = mem.metadata["pair_suggestions"]

        return result


