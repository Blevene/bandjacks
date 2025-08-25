import re
import json
from typing import Any, Dict

from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.tools import (
    vector_search_ttx,
    graph_lookup,
    list_tactics,
    get_tool_definitions,
    get_tool_functions,
)
from bandjacks.llm.client import execute_tool_loop
from bandjacks.llm.stix_builder import STIXBuilder
from bandjacks.llm.flow_builder import FlowBuilder


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
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        """Find behavioral spans with multi-line context aggregation."""
        
        # Single-line spans with scoring
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
            
            # Add span if score threshold met
            if score >= 0.6:
                mem.spans.append({
                    "text": line.strip(),
                    "line_refs": [idx + 1],
                    "score": min(score, 1.0),
                    "tactics": tactics,
                    "prior": _section_weight(line)
                })
        
        # Multi-line context aggregation for complex behaviors
        self._aggregate_context_spans(mem)
        
        # Entity-based spans (actor -> action sequences)
        self._create_entity_spans(mem)
        
        # Sort spans by score
        mem.spans.sort(key=lambda x: x.get("score", 0), reverse=True)
    
    def _aggregate_context_spans(self, mem: WorkingMemory):
        """Aggregate consecutive lines that form behavioral sequences."""
        
        # Look for multi-step sequences
        window_size = 5
        for i in range(len(mem.line_index) - window_size + 1):
            window_text = " ".join(mem.line_index[i:i+window_size])
            
            # Check for attack chains
            if ("download" in window_text.lower() and "execute" in window_text.lower()) or \
               ("encrypt" in window_text.lower() and "ransom" in window_text.lower()) or \
               ("credential" in window_text.lower() and "lateral" in window_text.lower()):
                
                # Create aggregated span
                mem.spans.append({
                    "text": window_text[:500],  # Limit length
                    "line_refs": list(range(i+1, i+window_size+1)),
                    "score": 0.9,
                    "tactics": ["multi-stage"],
                    "prior": 1.05
                })
    
    def _create_entity_spans(self, mem: WorkingMemory):
        """Create spans based on entity mentions and their actions."""
        
        # Find entity mentions
        entity_pattern = re.compile(
            r"\b(APT\d+|TA\d+|FIN\d+|Lazarus|Cozy Bear|Fancy Bear|" +
            r"threat actor|attacker|adversary|malware|trojan|ransomware)\b", re.I
        )
        
        for idx, line in enumerate(mem.line_index):
            if entity_pattern.search(line):
                # Look for actions in surrounding context
                context_start = max(0, idx - 2)
                context_end = min(len(mem.line_index), idx + 3)
                context = " ".join(mem.line_index[context_start:context_end])
                
                if len(context) > 50:  # Meaningful context
                    mem.spans.append({
                        "text": context[:500],
                        "line_refs": list(range(context_start+1, context_end+1)),
                        "score": 0.8,
                        "tactics": ["entity-action"],
                        "prior": 1.05
                    })


LEX = ["powershell", "rundll32", "schtasks", "reg add", "wmic", "psexec", "lsass", "mimikatz", "wmi", "svc", "runkey"]

def _hinted_query(text: str) -> str:
    lower = text.lower()
    hits = [h for h in LEX if h in lower]
    return f"{text}\nHINTS: {', '.join(hits)}" if hits else text


class RetrieverAgent:
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        top_k = int(config.get("top_k", 8))
        for i, span in enumerate(mem.spans):
            results = vector_search_ttx(_hinted_query(span["text"]), kb_types=["AttackPattern"], top_k=top_k)
            mem.candidates.setdefault(i, [])
            seen = {c.get("external_id") for c in mem.candidates[i]}
            for rank, r in enumerate(results[:top_k], start=1):
                ext_id = r.get("external_id") or r.get("id")
                if not ext_id or ext_id in seen:
                    continue
                stix_id = r.get("stix_id") or ""
                meta = mem.graph_cache.get(ext_id)
                if not meta and stix_id:
                    meta = graph_lookup(stix_id)
                    if isinstance(meta, dict):
                        mem.graph_cache[ext_id] = meta
                mem.candidates[i].append({
                    "external_id": ext_id,
                    "name": r.get("name", ""),
                    "score": r.get("score", 0.0),
                    "rank": rank,
                    "meta": meta,
                    "source": "retrieval",
                })
                seen.add(ext_id)


class DiscoveryAgent:
    """Use LLM to discover techniques not found by retrieval."""
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        max_props = int(config.get("max_discovery_per_span", 10))  # Increased from 3
        # Provide more context for better discovery
        context_window = 3  # Lines before/after for context
        
        for i, span in enumerate(mem.spans):
            # Get surrounding context
            line_refs = span.get("line_refs", [])
            if line_refs:
                min_line = max(1, min(line_refs) - context_window)
                max_line = min(len(mem.line_index), max(line_refs) + context_window)
                context_lines = mem.line_index[min_line-1:max_line]
                context_text = "\n".join(context_lines)
            else:
                context_text = span["text"]
            
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are an expert in MITRE ATT&CK framework. Analyze the text and identify techniques being described. "
                        "Use chain-of-thought reasoning:\n"
                        "1. What behavior is being described?\n"
                        "2. What is the attacker trying to achieve?\n"
                        "3. What ATT&CK techniques match this behavior?\n\n"
                        "Return a JSON array of up to 10 techniques: [{external_id:'Txxxx[.xxx]',name:'technique name',reason:'why this matches'}]"
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps({
                        "span": span["text"],
                        "context": context_text,
                        "line_refs": span["line_refs"],
                        "span_tactics": span.get("tactics", []),
                        "max": max_props
                    }),
                },
            ]
            
            # Use Gemini 2.5 Flash for better discovery
            model = config.get("discovery_model", "gemini/gemini-2.5-flash")
            raw = execute_tool_loop(
                messages, 
                get_tool_definitions(), 
                get_tool_functions(), 
                max_iterations=5,
                model=model
            )
            try:
                props = json.loads(raw)
                if not isinstance(props, list):
                    continue
            except Exception:
                continue
            mem.candidates.setdefault(i, [])
            seen = {c.get("external_id") for c in mem.candidates[i]}
            for p in props[:max_props]:
                ext = (p or {}).get("external_id", "")
                name = (p or {}).get("name", "")
                if not TECH_ID_RE.match(ext) or ext in seen:
                    continue
                # Defer resolution to verifier; keep proposal visible
                mem.candidates[i].append({
                    "external_id": ext,
                    "name": name,
                    "score": 0.0,
                    "meta": None,
                    "source": "free_propose",
                })
                seen.add(ext)


class MapperAgent:
    """Map spans to techniques with high-quality evidence."""
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        for i, span in enumerate(mem.spans):
            cands = mem.candidates.get(i, [])
            
            # Get full context for evidence extraction
            line_refs = span.get("line_refs", [])
            evidence_lines = []
            for ref in line_refs:
                if 1 <= ref <= len(mem.line_index):
                    evidence_lines.append(f"Line {ref}: {mem.line_index[ref-1]}")
            
            messages = [
                {
                    "role": "system",
                    "content": (
                        "Analyze the span and map it to the BEST matching ATT&CK technique. "
                        "You can either:\n"
                        "1. Select from provided candidates\n"
                        "2. Propose a different technique if none match well\n\n"
                        "Requirements:\n"
                        "- Provide 2-5 direct quotes as evidence\n"
                        "- Each quote must be EXACT text from the document\n"
                        "- Include line numbers for each quote\n"
                        "- Score confidence 0-100 based on evidence strength\n\n"
                        "Return JSON: {selected:{external_id,name}|null, proposed:{external_id,name}|null, "
                        "evidence:{quotes:[string],line_refs:[int]}, confidence:int, rationale:string}"
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "span": span["text"],
                            "line_refs": span["line_refs"],
                            "evidence_lines": evidence_lines,
                            "candidates": [
                                {"external_id": c["external_id"], "name": c.get("name", ""), "score": c.get("score", 0)} 
                                for c in cands
                            ],
                        }
                    ),
                },
            ]
            
            # Use Gemini 2.5 Flash for evidence extraction
            model = config.get("mapper_model", "gemini/gemini-2.5-flash")
            raw = execute_tool_loop(
                messages, 
                get_tool_definitions(), 
                get_tool_functions(), 
                max_iterations=5,
                model=model
            )
            try:
                resp = json.loads(raw)
            except Exception:
                continue
            choice = resp.get("selected") or resp.get("proposed") or {}
            ev = resp.get("evidence") or {}
            # Prefer sub-technique if quotes explicitly mention a sub-tech name
            choice_id = choice.get("external_id", "")
            if choice_id and "." not in choice_id:
                subs = list_subtechniques(choice_id)
                if isinstance(subs, list) and subs:
                    for s in subs:
                        nm = (s.get("name", "") or "").lower()
                        if nm and any(nm in (q or "").lower() for q in ev.get("quotes", [])):
                            choice["external_id"] = s.get("external_id", choice_id)
                            choice["name"] = s.get("name", choice.get("name", ""))
                            break
            if choice.get("external_id") and ev.get("quotes") and ev.get("line_refs"):
                mem.claims.append(
                    {
                        "span_idx": i,
                        "external_id": choice["external_id"],
                        "name": choice.get("name", ""),
                        "quotes": ev["quotes"],
                        "line_refs": ev["line_refs"],
                        "confidence": int(resp.get("confidence", 60)),
                        "source": "candidate" if resp.get("selected") else "free_propose",
                    }
                )


from bandjacks.llm.tools import resolve_technique_by_external_id


class EvidenceVerifierAgent:
    """Verify evidence quality and semantic relevance."""
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        valid = []
        min_quotes = config.get("min_quotes", 2)
        WINDOW = 2

        for claim in mem.claims:
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

            # Accept if meets minimum quality
            if len(valid_quotes) >= min_quotes and evidence_score >= 40:
                claim["quotes"] = valid_quotes
                claim["line_refs"] = valid_lines
                claim["evidence_score"] = evidence_score
                claim["technique_meta"] = meta
                valid.append(claim)
            elif len(valid_quotes) >= 1 and evidence_score >= 60:
                claim["quotes"] = valid_quotes
                claim["line_refs"] = valid_lines
                claim["evidence_score"] = evidence_score
                claim["technique_meta"] = meta
                valid.append(claim)

        mem.claims = valid
    
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


class ConsolidatorAgent:
    """Consolidate claims into unique techniques with calibrated confidence."""
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        by_tech: Dict[str, Dict[str, Any]] = {}
        
        for claim in mem.claims:
            tid = claim["external_id"]
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
                },
            )
            entry["evidence"].extend(claim["quotes"])
            entry["line_refs"].update(claim["line_refs"])
            entry["evidence_scores"].append(claim.get("evidence_score", 50))
            entry["claim_count"] += 1
        
        # Consolidate into final techniques
        for tid, e in by_tech.items():
            # Calculate average evidence score
            avg_evidence_score = sum(e["evidence_scores"]) / len(e["evidence_scores"]) if e["evidence_scores"] else 50
            
            # Deduplicate evidence
            unique_evidence = []
            seen = set()
            for ev in e["evidence"]:
                ev_lower = ev.lower().strip()
                if ev_lower not in seen:
                    unique_evidence.append(ev)
                    seen.add(ev_lower)
            
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

            mem.techniques[tid] = {
                "name": e["name"],
                "confidence": _calibrate_confidence(
                    e["base_conf"],
                    len(unique_evidence),
                    e["claim_count"],
                    int(avg_evidence_score),
                    best_rank_val or 3,
                    prior_val,
                ),
                "evidence": unique_evidence[:5],  # Keep top 5 evidence
                "line_refs": sorted(e["line_refs"]),
                "tactic": e["tactic"],
                "claim_count": e["claim_count"],
            }


class KillChainSuggestionsAgent:
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        # Derive covered tactics from resolved techniques (lazy resolve)
        covered = set()
        for tid in mem.techniques.keys():
            meta = resolve_technique_by_external_id(tid)
            if meta and meta.get("tactic"):
                covered.add(meta["tactic"])
        all_tactics = {t["shortname"] for t in list_tactics()}
        missing = sorted(all_tactics - covered)
        mem.notes.append(f"Missing tactics: {', '.join(missing)}")
        # Store suggestions placeholder for future targeted discovery (no commit)
        setattr(mem, "inferred_suggestions", [{"tactic": t, "candidates": []} for t in missing])


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
                print(f"Flow building failed: {e}")
                flow = {}
        else:
            flow = {}
        
        return {
            "bundle": bundle,
            "flow": flow,
            "techniques": mem.techniques,
            "notes": mem.notes
        }


