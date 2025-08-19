from google.adk.agents import LlmAgent


span_finder_adk = LlmAgent(
    name="SpanFinder",
    model="gemini-2.0-flash",
    description="Identify TTP spans.",
)

retriever_adk = LlmAgent(
    name="Retriever",
    model="gemini-2.0-flash",
    description="Retrieve ATT&CK candidates.",
)

discovery_adk = LlmAgent(
    name="Discovery",
    model="gemini-2.0-flash",
    description="Free-propose techniques from text.",
)

mapper_adk = LlmAgent(
    name="Mapper",
    model="gemini-2.0-flash",
    description="Select candidate or propose new with evidence.",
)

verifier_adk = LlmAgent(
    name="EvidenceVerifier",
    model="gemini-2.0-flash",
    description="Validate quotes/line_refs & resolution.",
)

consolidator_adk = LlmAgent(
    name="Consolidator",
    model="gemini-2.0-flash",
    description="Merge & calibrate confidence.",
)

killchain_adk = LlmAgent(
    name="KillChainSuggestions",
    model="gemini-2.0-flash",
    description="Suggest missing tactics' techniques (no commit).",
)

assembler_adk = LlmAgent(
    name="Assembler",
    model="gemini-2.0-flash",
    description="Build STIX bundle and Attack Flow.",
)

coordinator_adk = LlmAgent(
    name="AgenticExtractorCoordinator",
    model="gemini-2.0-flash",
    description="Coordinate TTP extraction workflow.",
    sub_agents=[
        span_finder_adk,
        retriever_adk,
        discovery_adk,
        mapper_adk,
        verifier_adk,
        consolidator_adk,
        killchain_adk,
        assembler_adk,
    ],
)


