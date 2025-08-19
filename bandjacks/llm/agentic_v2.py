from typing import Any, Dict

from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.agents_v2 import (
    SpanFinderAgent,
    RetrieverAgent,
    DiscoveryAgent,
    MapperAgent,
    EvidenceVerifierAgent,
    ConsolidatorAgent,
    KillChainSuggestionsAgent,
    AssemblerAgent,
)


def run_agentic_v2(report_text: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run the ADK-aligned, retrieval-first agentic extraction pipeline with multi-pass."""
    mem = WorkingMemory(document_text=report_text, line_index=report_text.splitlines())

    # Pass 1: Initial extraction
    SpanFinderAgent().run(mem, config)
    RetrieverAgent().run(mem, config)
    DiscoveryAgent().run(mem, config)
    MapperAgent().run(mem, config)
    EvidenceVerifierAgent().run(mem, config)
    ConsolidatorAgent().run(mem, config)
    
    # Pass 2: Fill kill chain gaps
    KillChainSuggestionsAgent().run(mem, config)
    
    # Check for missing tactics and run targeted extraction
    if hasattr(mem, "inferred_suggestions"):
        missing_tactics = [s["tactic"] for s in mem.inferred_suggestions]
        if missing_tactics:
            # Create targeted spans for missing tactics
            _run_targeted_extraction(mem, missing_tactics, config)
            
            # Re-run pipeline on new spans
            start_span_idx = len(mem.spans) - len(missing_tactics) * 3  # Approximate new spans
            RetrieverAgent().run(mem, config)
            DiscoveryAgent().run(mem, config) 
            MapperAgent().run(mem, config)
            EvidenceVerifierAgent().run(mem, config)
            ConsolidatorAgent().run(mem, config)
    
    # Pass 3: Final assembly
    return AssemblerAgent().run(mem, config)


def _run_targeted_extraction(mem: WorkingMemory, missing_tactics: list, config: Dict[str, Any]) -> None:
    """Run targeted extraction for missing tactics."""
    import re
    
    # Tactic-specific keywords for targeted search
    tactic_keywords = {
        "reconnaissance": ["scan", "enumerate", "discover", "gather", "osint"],
        "resource-development": ["infrastructure", "account", "capability", "develop"],
        "initial-access": ["phishing", "exploit", "supply chain", "trusted"],
        "execution": ["execute", "run", "script", "command", "invoke"],
        "persistence": ["persist", "startup", "registry", "scheduled", "backdoor"],
        "privilege-escalation": ["privilege", "escalate", "admin", "root", "bypass"],
        "defense-evasion": ["evade", "obfuscate", "hide", "disable", "bypass"],
        "credential-access": ["credential", "password", "hash", "dump", "steal"],
        "discovery": ["discover", "enumerate", "query", "list", "find"],
        "lateral-movement": ["lateral", "move", "spread", "pivot", "remote"],
        "collection": ["collect", "gather", "archive", "screenshot", "record"],
        "command-and-control": ["c2", "command", "control", "beacon", "callback"],
        "exfiltration": ["exfiltrate", "transfer", "upload", "send", "leak"],
        "impact": ["ransom", "encrypt", "wipe", "destroy", "disrupt"]
    }
    
    for tactic in missing_tactics:
        keywords = tactic_keywords.get(tactic, [])
        if not keywords:
            continue
            
        # Search for lines containing tactic keywords
        pattern = re.compile(r"\b(" + "|".join(keywords) + r")\b", re.I)
        
        for idx, line in enumerate(mem.line_index):
            if pattern.search(line):
                # Add as high-priority span
                mem.spans.append({
                    "text": line.strip(),
                    "line_refs": [idx + 1],
                    "score": 0.9,
                    "tactics": [tactic],
                    "targeted": True
                })


