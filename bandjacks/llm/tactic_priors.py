"""Tactic-based priors for technique transition modeling."""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class TacticTransition:
    """Represents a tactic-to-tactic transition with probability."""
    from_tactic: str
    to_tactic: str
    probability: float
    rationale: str


class TacticPriors:
    """Manages tactic-based priors for technique sequence modeling."""
    
    # MITRE ATT&CK kill chain progression probabilities
    # Based on typical attack progression patterns
    KILL_CHAIN_TRANSITIONS = {
        # Initial Access -> Early execution/persistence  
        "initial-access": [
            ("execution", 0.8, "Attackers typically execute code after gaining access"),
            ("persistence", 0.6, "Common to establish persistence early"),
            ("defense-evasion", 0.4, "May need to evade detection systems")
        ],
        
        # Execution -> Establish foothold
        "execution": [
            ("persistence", 0.8, "Critical to maintain access after execution"),
            ("privilege-escalation", 0.6, "Often need elevated privileges"),
            ("defense-evasion", 0.7, "Common to evade detection after execution"),
            ("discovery", 0.5, "May discover environment during execution")
        ],
        
        # Persistence -> Expand access
        "persistence": [
            ("privilege-escalation", 0.7, "Natural progression to gain more access"),
            ("defense-evasion", 0.6, "Need to avoid detection of persistence"),
            ("discovery", 0.6, "Discover environment once persistent"),
            ("credential-access", 0.5, "Collect credentials for further access")
        ],
        
        # Privilege Escalation -> Expand capabilities
        "privilege-escalation": [
            ("defense-evasion", 0.8, "High-privilege actions need evasion"),
            ("credential-access", 0.7, "Admin access enables credential theft"),
            ("discovery", 0.6, "Elevated privileges enable better discovery"),
            ("lateral-movement", 0.5, "Can move laterally with admin rights")
        ],
        
        # Defense Evasion -> Continue operations
        "defense-evasion": [
            ("credential-access", 0.6, "Safe to collect credentials after evasion"),
            ("discovery", 0.6, "Can safely discover environment"),
            ("lateral-movement", 0.5, "Move laterally while evading detection"),
            ("collection", 0.4, "Collect data while detection is avoided")
        ],
        
        # Credential Access -> Lateral expansion
        "credential-access": [
            ("lateral-movement", 0.8, "Primary purpose of credential theft"),
            ("discovery", 0.6, "Discover targets for stolen credentials"),
            ("privilege-escalation", 0.4, "Stolen creds may provide higher privileges"),
            ("persistence", 0.3, "May establish new persistence with creds")
        ],
        
        # Discovery -> Target selection and movement
        "discovery": [
            ("lateral-movement", 0.7, "Discovery informs lateral movement"),
            ("collection", 0.6, "Identify data sources for collection"),
            ("credential-access", 0.5, "Find credential sources"),
            ("command-and-control", 0.4, "Establish C2 to discovered assets")
        ],
        
        # Lateral Movement -> Expand footprint  
        "lateral-movement": [
            ("persistence", 0.6, "Establish persistence on new systems"),
            ("discovery", 0.6, "Discover new environment after movement"),
            ("privilege-escalation", 0.5, "May need to escalate on new systems"),
            ("collection", 0.5, "Collect data from new systems"),
            ("credential-access", 0.4, "Harvest credentials from new systems")
        ],
        
        # Collection -> Exfiltration preparation
        "collection": [
            ("command-and-control", 0.7, "Stage data for exfiltration via C2"),
            ("exfiltration", 0.6, "Direct path to data theft"),
            ("defense-evasion", 0.5, "Hide collection activities")
        ],
        
        # Command and Control -> Final objectives
        "command-and-control": [
            ("exfiltration", 0.8, "Primary mechanism for data theft"),
            ("impact", 0.4, "May deploy destructive payloads"),
            ("collection", 0.3, "Continue collecting via C2 channel")
        ],
        
        # Exfiltration -> Mission completion or impact
        "exfiltration": [
            ("impact", 0.3, "May cause damage after stealing data"),
            ("command-and-control", 0.2, "May maintain C2 for future operations")
        ],
        
        # Impact -> End of chain (typically terminal)
        "impact": []
    }
    
    # Tactic groupings for fallback transitions
    TACTIC_GROUPS = {
        "early": ["initial-access", "execution", "persistence"],
        "expansion": ["privilege-escalation", "defense-evasion", "credential-access", "discovery"],  
        "movement": ["lateral-movement", "command-and-control"],
        "objectives": ["collection", "exfiltration", "impact"]
    }
    
    def __init__(self):
        """Initialize tactic priors system."""
        self.transition_cache = {}
        self._build_transition_cache()
    
    def _build_transition_cache(self):
        """Pre-compute all transition probabilities for fast lookup."""
        for from_tactic, transitions in self.KILL_CHAIN_TRANSITIONS.items():
            self.transition_cache[from_tactic] = {}
            
            for to_tactic, prob, rationale in transitions:
                self.transition_cache[from_tactic][to_tactic] = TacticTransition(
                    from_tactic=from_tactic,
                    to_tactic=to_tactic, 
                    probability=prob,
                    rationale=rationale
                )
        
        logger.info(f"Built tactic transition cache with {len(self.transition_cache)} tactics")
    
    def get_tactic_prior(self, from_tactic: str, to_tactic: str) -> float:
        """
        Get prior probability for a tactic-to-tactic transition.
        
        Args:
            from_tactic: Source tactic shortname
            to_tactic: Target tactic shortname
            
        Returns:
            Prior probability [0.0, 1.0] for this transition
        """
        if not from_tactic or not to_tactic:
            return 0.1  # Low default for unknown tactics
        
        # Direct transition lookup
        if from_tactic in self.transition_cache:
            if to_tactic in self.transition_cache[from_tactic]:
                return self.transition_cache[from_tactic][to_tactic].probability
        
        # Same tactic (techniques within same tactic)
        if from_tactic == to_tactic:
            return 0.3  # Moderate probability for intra-tactic transitions
        
        # Cross-group transitions (lower probability)
        from_group = self._get_tactic_group(from_tactic)
        to_group = self._get_tactic_group(to_tactic)
        
        if from_group and to_group:
            if from_group == to_group:
                return 0.2  # Same group
            elif self._is_progressive_transition(from_group, to_group):
                return 0.15  # Progressive across groups
            else:
                return 0.05  # Non-progressive transitions
        
        return 0.1  # Default fallback
    
    def _get_tactic_group(self, tactic: str) -> Optional[str]:
        """Get the group that a tactic belongs to."""
        for group, tactics in self.TACTIC_GROUPS.items():
            if tactic in tactics:
                return group
        return None
    
    def _is_progressive_transition(self, from_group: str, to_group: str) -> bool:
        """Check if this is a natural progression between tactic groups."""
        progressions = [
            ("early", "expansion"),
            ("expansion", "movement"),
            ("movement", "objectives"),
            ("early", "movement"),  # Direct early->movement (less common)
            ("expansion", "objectives")  # Direct expansion->objectives
        ]
        
        return (from_group, to_group) in progressions
    
    def get_technique_tactic_prior(
        self, 
        from_technique: str,
        to_technique: str,
        tactic_mapping: Dict[str, str]
    ) -> float:
        """
        Get tactic-based prior for a technique-to-technique transition.
        
        Args:
            from_technique: Source technique ID
            to_technique: Target technique ID  
            tactic_mapping: Mapping of technique_id -> primary_tactic
            
        Returns:
            Tactic-based prior probability
        """
        from_tactic = tactic_mapping.get(from_technique)
        to_tactic = tactic_mapping.get(to_technique)
        
        return self.get_tactic_prior(from_tactic, to_tactic)
    
    def get_all_transitions_from(self, tactic: str) -> List[TacticTransition]:
        """Get all possible transitions from a tactic."""
        if tactic not in self.transition_cache:
            return []
        
        return list(self.transition_cache[tactic].values())
    
    def get_transition_rationale(self, from_tactic: str, to_tactic: str) -> str:
        """Get rationale for why this transition is likely."""
        if from_tactic in self.transition_cache:
            if to_tactic in self.transition_cache[from_tactic]:
                return self.transition_cache[from_tactic][to_tactic].rationale
        
        # Generate fallback rationale
        if from_tactic == to_tactic:
            return f"Techniques within {from_tactic} tactic often occur together"
        
        from_group = self._get_tactic_group(from_tactic)
        to_group = self._get_tactic_group(to_tactic)
        
        if from_group and to_group and self._is_progressive_transition(from_group, to_group):
            return f"Natural progression from {from_group} to {to_group} phase"
        
        return f"Uncommon transition from {from_tactic} to {to_tactic}"
    
    def validate_kill_chain_order(self, techniques: List[str], tactic_mapping: Dict[str, str]) -> List[str]:
        """
        Validate and suggest corrections for technique order based on kill chain.
        
        Args:
            techniques: List of technique IDs
            tactic_mapping: Mapping of technique_id -> tactic
            
        Returns:
            List of warnings about order violations
        """
        warnings = []
        
        # Define typical tactic order progression
        tactic_order = [
            "initial-access", "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery", "lateral-movement", 
            "collection", "command-and-control", "exfiltration", "impact"
        ]
        
        # Create order mapping
        order_map = {tactic: i for i, tactic in enumerate(tactic_order)}
        
        prev_order = -1
        prev_tactic = None
        
        for i, technique in enumerate(techniques):
            tactic = tactic_mapping.get(technique)
            if not tactic:
                continue
                
            current_order = order_map.get(tactic, 999)
            
            # Check for significant backward progression (more than 2 steps back)
            if prev_order >= 0 and current_order < prev_order - 2:
                warnings.append(
                    f"Step {i+1}: {tactic} appears after {prev_tactic} "
                    f"(unusual backward progression in kill chain)"
                )
            
            # Check for very large forward jumps (skipping many tactics)
            elif prev_order >= 0 and current_order > prev_order + 4:
                warnings.append(
                    f"Step {i+1}: Jump from {prev_tactic} to {tactic} "
                    f"skips several typical kill chain phases"
                )
            
            prev_order = current_order
            prev_tactic = tactic
        
        return warnings
    
    def suggest_missing_tactics(self, techniques: List[str], tactic_mapping: Dict[str, str]) -> List[str]:
        """
        Suggest tactics that are commonly missing from a sequence.
        
        Args:
            techniques: List of technique IDs in sequence
            tactic_mapping: Mapping of technique_id -> tactic
            
        Returns:
            List of suggested tactics that may be missing
        """
        # Get tactics present in sequence
        present_tactics = set()
        for technique in techniques:
            tactic = tactic_mapping.get(technique)
            if tactic:
                present_tactics.add(tactic)
        
        suggestions = []
        
        # Check for common missing patterns
        if "initial-access" in present_tactics and "persistence" not in present_tactics:
            suggestions.append("persistence (commonly follows initial access)")
        
        if "credential-access" in present_tactics and "lateral-movement" not in present_tactics:
            suggestions.append("lateral-movement (typical use of stolen credentials)")
        
        if "collection" in present_tactics and "exfiltration" not in present_tactics:
            suggestions.append("exfiltration (natural follow-up to data collection)")
        
        if "lateral-movement" in present_tactics and "discovery" not in present_tactics:
            suggestions.append("discovery (often needed for effective lateral movement)")
        
        return suggestions


# Global instance for easy access
TACTIC_PRIORS = TacticPriors()


def get_tactic_prior(from_tactic: str, to_tactic: str) -> float:
    """Convenience function to get tactic prior."""
    return TACTIC_PRIORS.get_tactic_prior(from_tactic, to_tactic)


def get_technique_tactic_prior(
    from_technique: str,
    to_technique: str, 
    tactic_mapping: Dict[str, str]
) -> float:
    """Convenience function to get technique tactic prior."""
    return TACTIC_PRIORS.get_technique_tactic_prior(
        from_technique, to_technique, tactic_mapping
    )