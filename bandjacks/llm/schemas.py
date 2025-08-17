"""JSON schemas for LLM input/output validation."""

# Schema for LLM output per chunk
LLM_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "chunk_id": {"type": "string"},
        "claims": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": ["activity", "capability", "tooluse"]
                    },
                    "span": {
                        "type": "object",
                        "properties": {
                            "start": {"type": "integer"},
                            "end": {"type": "integer"},
                            "text": {"type": "string"}
                        },
                        "required": ["text"]
                    },
                    "mappings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "stix_id": {"type": "string"},
                                "confidence": {
                                    "type": "integer",
                                    "minimum": 0,
                                    "maximum": 100
                                },
                                "rationale": {"type": "string"}
                            },
                            "required": ["stix_id", "confidence"]
                        }
                    },
                    "subjects": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "stix_id": {"type": "string"},
                                "confidence": {"type": "integer"}
                            }
                        }
                    },
                    "novel_hypothesis": {
                        "type": "object",
                        "properties": {
                            "propose": {"type": "boolean"},
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "tactic_shortnames": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "confidence": {"type": "integer"}
                        },
                        "required": ["propose"]
                    },
                    "citations": {
                        "type": "array",
                        "items": {"type": "string"}
                    }
                },
                "required": ["type", "span", "mappings"]
            }
        }
    },
    "required": ["chunk_id", "claims"]
}


# Schema for aggregated LLM extraction response
LLM_EXTRACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "chunks": {
            "type": "array",
            "items": LLM_OUTPUT_SCHEMA
        },
        "metadata": {
            "type": "object",
            "properties": {
                "llm_model": {"type": "string"},
                "prompt_version": {"type": "string"},
                "total_tool_calls": {"type": "integer"},
                "extraction_time_ms": {"type": "integer"}
            }
        }
    },
    "required": ["chunks"]
}