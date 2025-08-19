"""Multi-factor confidence scoring for technique mappings."""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class ConfidenceFactors:
    """Factors that influence confidence scoring."""
    
    # Evidence factors
    evidence_strength: float = 0.0  # 0-40 points
    evidence_count: int = 0
    has_line_references: bool = False
    has_direct_quote: bool = False
    
    # Corroboration factors
    appears_multiple_times: int = 1
    corroborated_by_other_sources: bool = False
    
    # Context factors
    fits_kill_chain: bool = False
    fits_malware_type: bool = False
    related_techniques_found: bool = False
    
    # Search validation
    vector_similarity_score: float = 0.0
    technique_specificity: float = 0.0  # How unique is this evidence to this technique
    
    def calculate_total(self) -> float:
        """Calculate total confidence score."""
        total = 0.0
        
        # Evidence strength (0-40)
        total += self.evidence_strength
        
        # Evidence quality bonuses (0-15)
        if self.has_direct_quote:
            total += 10
        if self.has_line_references:
            total += 5
        
        # Corroboration (0-20)
        if self.appears_multiple_times > 1:
            total += min(self.appears_multiple_times * 5, 15)
        if self.corroborated_by_other_sources:
            total += 5
        
        # Context fit (0-15)
        if self.fits_kill_chain:
            total += 7
        if self.fits_malware_type:
            total += 5
        if self.related_techniques_found:
            total += 3
        
        # Search validation (0-10)
        if self.vector_similarity_score > 0.8:
            total += 10
        elif self.vector_similarity_score > 0.7:
            total += 7
        elif self.vector_similarity_score > 0.6:
            total += 4
        
        return min(total, 100)


class ConfidenceScorer:
    """Score confidence for technique mappings."""
    
    def __init__(self):
        """Initialize the confidence scorer."""
        self.technique_frequencies = defaultdict(int)
        self.technique_evidence = defaultdict(list)
        self.malware_type_techniques = {
            "stealer": ["T1555", "T1005", "T1041", "T1071"],
            "ransomware": ["T1486", "T1490", "T1489", "T1491"],
            "rat": ["T1071", "T1105", "T1055", "T1057"],
            "backdoor": ["T1071", "T1547", "T1105", "T1055"],
            "dropper": ["T1105", "T1055", "T1140", "T1027"],
            "botnet": ["T1071", "T1571", "T1573", "T1095"]
        }
        self.kill_chain_flow = {
            "initial-access": ["execution"],
            "execution": ["persistence", "defense-evasion"],
            "persistence": ["defense-evasion", "privilege-escalation"],
            "privilege-escalation": ["defense-evasion", "credential-access"],
            "defense-evasion": ["discovery", "lateral-movement"],
            "credential-access": ["discovery", "lateral-movement"],
            "discovery": ["collection", "lateral-movement"],
            "lateral-movement": ["collection"],
            "collection": ["exfiltration", "command-and-control"],
            "command-and-control": ["exfiltration"],
            "exfiltration": ["impact"],
            "impact": []
        }
    
    def score_mapping(
        self,
        mapping: Dict[str, Any],
        claim: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Score a technique mapping with multi-factor analysis.
        
        Args:
            mapping: Technique mapping with stix_id, external_id, confidence
            claim: Full claim with evidence, reasoning
            context: Extraction context with found_techniques, malware_type, etc.
            
        Returns:
            Enhanced mapping with confidence score and factors
        """
        factors = ConfidenceFactors()
        tech_id = mapping.get('external_id', '')
        
        # Analyze evidence strength
        factors.evidence_strength = self._assess_evidence_strength(
            claim.get('evidence', []),
            claim.get('reasoning', '')
        )
        
        # Count evidence
        factors.evidence_count = len(claim.get('evidence', []))
        factors.has_line_references = bool(claim.get('source_lines'))
        factors.has_direct_quote = any(
            '"' in str(e) or "'" in str(e) 
            for e in claim.get('evidence', [])
        )
        
        # Check frequency
        self.technique_frequencies[tech_id] += 1
        factors.appears_multiple_times = self.technique_frequencies[tech_id]
        
        # Check context fit
        factors.fits_kill_chain = self._check_kill_chain_fit(
            tech_id,
            context.get('found_techniques', [])
        )
        factors.fits_malware_type = self._check_malware_type_fit(
            tech_id,
            context.get('malware_type', '')
        )
        factors.related_techniques_found = self._check_related_techniques(
            tech_id,
            context.get('found_techniques', [])
        )
        
        # Vector similarity
        factors.vector_similarity_score = mapping.get('score', 0.0)
        
        # Calculate specificity
        factors.technique_specificity = self._assess_specificity(
            claim.get('evidence', []),
            tech_id
        )
        
        # Calculate final confidence
        confidence = factors.calculate_total()
        
        # Build enhanced mapping
        enhanced = mapping.copy()
        enhanced['confidence'] = confidence
        enhanced['confidence_factors'] = {
            'evidence_strength': factors.evidence_strength,
            'evidence_count': factors.evidence_count,
            'has_line_refs': factors.has_line_references,
            'has_quotes': factors.has_direct_quote,
            'frequency': factors.appears_multiple_times,
            'fits_kill_chain': factors.fits_kill_chain,
            'fits_malware_type': factors.fits_malware_type,
            'vector_score': factors.vector_similarity_score,
            'total_calculated': confidence
        }
        
        return enhanced
    
    def _assess_evidence_strength(self, evidence: List[str], reasoning: str) -> float:
        """Assess the strength of evidence (0-40 points)."""
        score = 0.0
        
        # Check for explicit technique mentions
        explicit_keywords = [
            'explicitly', 'directly', 'specifically', 'states',
            'mentions', 'describes', 'documents', 'reports'
        ]
        if any(keyword in reasoning.lower() for keyword in explicit_keywords):
            score += 15
        
        # Check evidence quality
        for e in evidence:
            e_lower = str(e).lower()
            
            # Technical details
            if any(term in e_lower for term in ['function', 'api', 'command', 'process']):
                score += 5
            
            # Specific tools/files
            if any(term in e_lower for term in ['.exe', '.dll', '.ps1', '.bat', '.sh']):
                score += 3
            
            # Network indicators
            if any(term in e_lower for term in ['http', 'tcp', 'udp', 'port', 'ip']):
                score += 3
        
        # Clear behavioral description
        behavioral_terms = [
            'downloads', 'executes', 'creates', 'modifies', 'deletes',
            'sends', 'receives', 'encrypts', 'decrypts', 'injects'
        ]
        matches = sum(1 for term in behavioral_terms if term in reasoning.lower())
        score += min(matches * 3, 12)
        
        return min(score, 40)
    
    def _check_kill_chain_fit(self, tech_id: str, found_techniques: List[str]) -> bool:
        """Check if technique fits the kill chain progression."""
        from bandjacks.loaders.enhanced_search import TECHNIQUE_TO_PHASE
        
        # Get phases of found techniques
        found_phases = set()
        for found_tech in found_techniques:
            base_tech = found_tech.split('.')[0]
            if base_tech in TECHNIQUE_TO_PHASE:
                found_phases.add(TECHNIQUE_TO_PHASE[base_tech])
        
        # Get phase of current technique
        current_tech = tech_id.split('.')[0]
        current_phase = TECHNIQUE_TO_PHASE.get(current_tech)
        
        if not current_phase or not found_phases:
            return False
        
        # Check if current phase logically follows found phases
        for found_phase in found_phases:
            expected_next = self.kill_chain_flow.get(found_phase, [])
            if current_phase in expected_next:
                return True
        
        # Check if current phase logically precedes found phases
        if current_phase in self.kill_chain_flow:
            expected_next = self.kill_chain_flow[current_phase]
            if any(phase in expected_next for phase in found_phases):
                return True
        
        return False
    
    def _check_malware_type_fit(self, tech_id: str, malware_type: str) -> bool:
        """Check if technique fits the malware type."""
        if not malware_type:
            return False
        
        malware_type_lower = malware_type.lower()
        
        # Check each malware type
        for mtype, expected_techniques in self.malware_type_techniques.items():
            if mtype in malware_type_lower:
                base_tech = tech_id.split('.')[0]
                if base_tech in expected_techniques:
                    return True
        
        return False
    
    def _check_related_techniques(self, tech_id: str, found_techniques: List[str]) -> bool:
        """Check if related techniques have been found."""
        from bandjacks.loaders.enhanced_search import TECHNIQUE_RELATIONSHIPS
        
        base_tech = tech_id.split('.')[0]
        
        # Check if this is related to any found technique
        for found_tech in found_techniques:
            found_base = found_tech.split('.')[0]
            
            # Check relationships
            if found_base in TECHNIQUE_RELATIONSHIPS:
                if base_tech in TECHNIQUE_RELATIONSHIPS[found_base]:
                    return True
            
            # Check if subtechnique of found technique
            if tech_id.startswith(found_base + '.'):
                return True
        
        return False
    
    def _assess_specificity(self, evidence: List[str], tech_id: str) -> float:
        """Assess how specific the evidence is to this technique (0-1)."""
        # This would ideally check how unique the evidence is
        # For now, use simple heuristics
        
        specificity = 0.5  # Default moderate specificity
        
        # Check for technique-specific indicators
        technique_specific = {
            "T1055": ["inject", "hollow", "process injection"],
            "T1059.001": ["powershell", "invoke-expression", "ps1"],
            "T1566": ["phishing", "spearphishing", "attachment"],
            "T1547": ["registry", "startup", "autostart", "persistence"],
            "T1555": ["credential", "password", "browser", "keychain"],
            "T1071": ["http", "https", "dns", "protocol"],
            "T1041": ["exfiltrat", "data out", "upload", "transmit"]
        }
        
        base_tech = tech_id.split('.')[0]
        if base_tech in technique_specific:
            keywords = technique_specific[base_tech]
            evidence_text = ' '.join(str(e).lower() for e in evidence)
            
            matches = sum(1 for keyword in keywords if keyword in evidence_text)
            if matches > 0:
                specificity = min(0.7 + (matches * 0.1), 1.0)
        
        return specificity
    
    def recalibrate_all(
        self,
        claims: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Recalibrate confidence for all claims based on complete context.
        
        Args:
            claims: All extracted claims
            context: Full extraction context
            
        Returns:
            Claims with recalibrated confidence scores
        """
        # First pass: collect all techniques
        all_techniques = []
        for claim in claims:
            for mapping in claim.get('mappings', []):
                if mapping.get('external_id'):
                    all_techniques.append(mapping['external_id'])
        
        context['found_techniques'] = all_techniques
        
        # Detect malware type if not provided
        if 'malware_type' not in context:
            context['malware_type'] = self._detect_malware_type(claims)
        
        # Second pass: recalibrate each mapping
        recalibrated_claims = []
        for claim in claims:
            new_mappings = []
            for mapping in claim.get('mappings', []):
                enhanced = self.score_mapping(mapping, claim, context)
                new_mappings.append(enhanced)
            
            claim['mappings'] = new_mappings
            recalibrated_claims.append(claim)
        
        return recalibrated_claims
    
    def _detect_malware_type(self, claims: List[Dict[str, Any]]) -> str:
        """Detect malware type from claims."""
        # Simple heuristic based on common patterns
        technique_ids = []
        for claim in claims:
            for mapping in claim.get('mappings', []):
                if mapping.get('external_id'):
                    technique_ids.append(mapping['external_id'])
        
        # Check for type indicators
        if any(t in ['T1555', 'T1555.003'] for t in technique_ids):
            if 'T1041' in technique_ids or 'T1048' in technique_ids:
                return 'stealer'
        
        if 'T1486' in technique_ids:
            return 'ransomware'
        
        if 'T1071' in technique_ids and 'T1105' in technique_ids:
            if 'T1055' in technique_ids:
                return 'rat'
            else:
                return 'backdoor'
        
        return 'malware'  # Generic