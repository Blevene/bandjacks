"""Discovery-guided prompts for better extraction without prescription."""

DISCOVERY_SYSTEM_PROMPT = """You are an expert CTI analyst extracting threat techniques through behavioral analysis.

## Analytical Framework

Instead of looking for specific keywords, understand behaviors through these lenses:

**1. Capability Analysis**
- What capabilities does the threat demonstrate?
- What system resources does it access or manipulate?
- What security boundaries does it cross?

**2. Goal-Oriented Analysis**
- What is the threat trying to achieve at each step?
- How does each action contribute to the overall objective?
- What would happen if this step failed?

**3. Behavioral Patterns**
- Resource Creation: Files, processes, registry keys, network connections
- Resource Modification: Existing files, configurations, permissions
- Resource Access: Data reading, credential access, system information
- Resource Movement: Data transfer, process migration, lateral movement
- Resource Hiding: Obfuscation, encryption, rootkit behaviors

## Discovery Through Questions

For each section of text, ask yourself:

**Initial Contact**
- How does the threat first interact with the target environment?
- What triggers the initial execution?
- What user action (if any) is required?

**Execution Flow**
- What code/commands/scripts get executed?
- How is execution achieved (direct, indirect, scheduled)?
- What legitimate tools or processes are involved?

**Environmental Awareness**
- How does the threat learn about its environment?
- What information does it gather?
- How does it adapt its behavior?

**Persistence & Survival**
- How would the threat survive a reboot?
- What ensures continued execution?
- How does it recover from interruption?

**Data Operations**
- What data is accessed, read, or modified?
- How is sensitive information identified?
- Where does collected data go?

**Communication & Control**
- How does the threat receive instructions?
- What protocols or channels are used?
- How is communication hidden or secured?

**Impact & Objectives**
- What is the end goal of this threat?
- What damage or changes result?
- Who benefits from these actions?

## Evidence Requirements

For every technique you identify:
1. Provide specific evidence from the text
2. Explain the behavior (not just the keyword)
3. Map behavior to capability to technique
4. Include confidence based on evidence clarity

## Output Focus

- Prioritize behavioral understanding over keyword matching
- Include techniques even with moderate confidence (50%+)
- Explain your reasoning chain
- Note when behaviors suggest techniques not explicitly named"""


DISCOVERY_USER_TEMPLATE = """Analyze this threat intelligence through behavioral discovery.

## Context
{context}

## Text to Analyze
{text}

## Your Task

1. **Discover Behaviors**: What actions and capabilities are described?
2. **Understand Goals**: What is each behavior trying to achieve?
3. **Search for Techniques**: Find ATT&CK techniques that match these behaviors
4. **Provide Evidence**: Quote specific text that supports each finding
5. **Explain Reasoning**: Show how behavior → capability → technique

For each discovered technique, search multiple ways:
- Search for the behavior (e.g., "script execution")
- Search for the capability (e.g., "run code")
- Search for the goal (e.g., "achieve execution")
- Search for related techniques

Remember: A single paragraph might contain multiple techniques. A single technique might span multiple paragraphs."""


KILL_CHAIN_GUIDED_PROMPT = """Based on techniques found so far, identify likely missing techniques.

## Found Techniques
{found_techniques}

## Kill Chain Coverage
Covered phases: {covered_phases}
Missing phases: {missing_phases}

## Logical Analysis

Given what we've found, consider:

1. **Prerequisite Techniques**: What must happen before the found techniques?
   - If we see execution, how did the code arrive?
   - If we see persistence, what executed first?
   - If we see exfiltration, what was collected?

2. **Consequent Techniques**: What naturally follows from found techniques?
   - If we see collection, where does data go?
   - If we see credentials stolen, how are they used?
   - If we see discovery, what happens with that information?

3. **Supporting Techniques**: What enables the found techniques?
   - If we see advanced features, what provides privileges?
   - If we see network activity, what protocols are used?
   - If we see data movement, what channels exist?

## Search Strategy

For each gap identified:
1. Form a hypothesis about what technique fills the gap
2. Search for behavioral evidence of that technique
3. Consider alternative techniques that achieve the same goal
4. Look for subtle indicators often overlooked

Focus on logical flow, not exhaustive coverage."""


CONFIDENCE_CALIBRATION_PROMPT = """Assess confidence for this technique mapping.

## Technique
{technique_name} ({technique_id})

## Evidence
{evidence_list}

## Context
- Found in: {source_context}
- Related techniques found: {related_techniques}
- Kill chain phase: {kill_chain_phase}

## Confidence Factors

Evaluate each factor:

**Evidence Strength** (0-40 points)
- Explicit mention with technical details: 35-40
- Clear behavioral description: 25-34
- Implied by actions: 15-24
- Inferred from context: 5-14

**Corroboration** (0-30 points)
- Multiple independent evidence points: 25-30
- Confirmed by multiple sources: 20-24
- Single strong evidence: 10-19
- Single weak evidence: 0-9

**Context Fit** (0-20 points)
- Perfect fit with attack narrative: 18-20
- Logical progression from other techniques: 13-17
- Reasonable but not required: 7-12
- Possible but uncertain: 0-6

**Specificity** (0-10 points)
- Unique to this technique: 9-10
- Strongly indicative: 6-8
- Somewhat indicative: 3-5
- Could be multiple techniques: 0-2

Total confidence: {calculated_total}%

Provide adjusted confidence and reasoning."""


def get_discovery_messages(chunk_id: str, text: str, context: str = None) -> list:
    """
    Generate messages for discovery-based extraction.
    
    Args:
        chunk_id: Chunk identifier
        text: Chunk text to analyze
        context: Optional context about document and previous findings
        
    Returns:
        List of messages for LLM
    """
    # Add line numbers if not present
    if not text.startswith("("):
        lines = text.split("\n")
        numbered_lines = [f"({i+1}) {line}" for i, line in enumerate(lines)]
        text_with_lines = "\n".join(numbered_lines)
    else:
        text_with_lines = text
    
    # Build context string
    if not context:
        context = "Beginning of analysis - no prior context"
    
    user_content = DISCOVERY_USER_TEMPLATE.format(
        context=context,
        text=text_with_lines
    )
    
    return [
        {"role": "system", "content": DISCOVERY_SYSTEM_PROMPT},
        {"role": "user", "content": user_content}
    ]


def get_kill_chain_messages(
    found_techniques: list,
    covered_phases: list,
    missing_phases: list
) -> list:
    """
    Generate messages for kill chain gap analysis.
    
    Args:
        found_techniques: List of technique IDs found
        covered_phases: Kill chain phases covered
        missing_phases: Kill chain phases missing
        
    Returns:
        List of messages for LLM
    """
    user_content = KILL_CHAIN_GUIDED_PROMPT.format(
        found_techniques=", ".join(found_techniques),
        covered_phases=", ".join(covered_phases),
        missing_phases=", ".join(missing_phases)
    )
    
    return [
        {"role": "system", "content": DISCOVERY_SYSTEM_PROMPT},
        {"role": "user", "content": user_content}
    ]


def get_confidence_messages(
    technique_name: str,
    technique_id: str,
    evidence_list: list,
    source_context: str,
    related_techniques: list,
    kill_chain_phase: str
) -> list:
    """
    Generate messages for confidence calibration.
    
    Args:
        technique_name: Name of the technique
        technique_id: ATT&CK ID
        evidence_list: List of evidence strings
        source_context: Where this was found
        related_techniques: Other techniques found nearby
        kill_chain_phase: Phase in kill chain
        
    Returns:
        List of messages for LLM
    """
    # Calculate initial confidence
    base_confidence = 50
    if len(evidence_list) > 1:
        base_confidence += 10
    if any("explicit" in e.lower() for e in evidence_list):
        base_confidence += 20
    
    user_content = CONFIDENCE_CALIBRATION_PROMPT.format(
        technique_name=technique_name,
        technique_id=technique_id,
        evidence_list="\n".join(f"- {e}" for e in evidence_list),
        source_context=source_context,
        related_techniques=", ".join(related_techniques[:5]),
        kill_chain_phase=kill_chain_phase,
        calculated_total=base_confidence
    )
    
    return [
        {"role": "system", "content": "You are a CTI analyst calibrating confidence scores."},
        {"role": "user", "content": user_content}
    ]