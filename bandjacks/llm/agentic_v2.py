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
from bandjacks.llm.tracker import ExtractionTracker


def run_agentic_v2(report_text: str, config: Dict[str, Any], tracker: ExtractionTracker | None = None) -> Dict[str, Any]:
    """Run the ADK-aligned, retrieval-first agentic extraction pipeline with transparency tracking.

    If a tracker is provided, stage and progress will be recorded to that instance.
    """
    mem = WorkingMemory(document_text=report_text, line_index=report_text.splitlines())
    tracker = tracker or ExtractionTracker()

    # Pass 1: Initial extraction
    tracker.set_stage("SpanFinder")
    SpanFinderAgent().run(mem, config)
    tracker.set_spans_total(len(mem.spans))

    tracker.set_stage("Retriever")
    RetrieverAgent().run(mem, config)

    tracker.set_stage("Discovery")
    if not config.get("disable_discovery", False):
        DiscoveryAgent().run(mem, config)

    tracker.set_stage("Mapper")
    MapperAgent().run(mem, config)
    tracker.spans_processed = len({c.get("span_idx", -1) for c in mem.claims if c.get("span_idx", -1) >= 0})

    tracker.set_stage("Verifier")
    before = len(mem.claims)
    EvidenceVerifierAgent().run(mem, config)
    tracker.counters["verified_claims"] = len(mem.claims)
    tracker.log("info", "claims_verified", before=before, after=len(mem.claims))

    tracker.set_stage("Consolidator")
    ConsolidatorAgent().run(mem, config)
    tracker.counters["techniques"] = len(mem.techniques)

    # Pass 2: Fill kill chain gaps
    tracker.set_stage("Suggestions")
    KillChainSuggestionsAgent().run(mem, config)
    
    # Optional targeted extraction for missing tactics (kept as-is, but tracked)
    if hasattr(mem, "inferred_suggestions"):
        missing_tactics = [s["tactic"] for s in mem.inferred_suggestions]
        if missing_tactics:
            tracker.log("info", "targeted_extraction_start", missing=len(missing_tactics))
            _run_targeted_extraction(mem, missing_tactics, config)
            tracker.set_spans_total(len(mem.spans))
            tracker.set_stage("Retriever")
            RetrieverAgent().run(mem, config)
            tracker.set_stage("Discovery")
            if not config.get("disable_discovery", False):
                DiscoveryAgent().run(mem, config)
            tracker.set_stage("Mapper")
            MapperAgent().run(mem, config)
            tracker.set_stage("Verifier")
            EvidenceVerifierAgent().run(mem, config)
            tracker.set_stage("Consolidator")
            ConsolidatorAgent().run(mem, config)

    # Pass 3: Final assembly
    tracker.set_stage("Assembler")
    result = AssemblerAgent().run(mem, config)
    result["metrics"] = tracker.snapshot()
    return result


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


