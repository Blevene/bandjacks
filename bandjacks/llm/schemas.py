"""JSON schemas for LLM input/output validation."""

# Enhanced schema for LLM output per chunk with evidence requirements
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
                        "enum": ["uses-technique", "uses-tool", "uses-malware", "targets", 
                                "exploits", "communicates-with", "drops", "downloads"]
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
                    "line_refs": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Line numbers where evidence appears"
                    },
                    "actor": {
                        "type": ["string", "null"],
                        "description": "Threat actor if identified"
                    },
                    "technique": {
                        "type": ["string", "null"],
                        "description": "Technique name"
                    },
                    "tool": {
                        "type": ["string", "null"],
                        "description": "Tool or malware name"
                    },
                    "mappings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "stix_id": {"type": "string"},
                                "name": {"type": "string"},
                                "external_id": {"type": "string"},
                                "confidence": {
                                    "type": "integer",
                                    "minimum": 0,
                                    "maximum": 100
                                },
                                "rationale": {"type": "string"}
                            },
                            "required": ["stix_id", "confidence", "rationale"]
                        }
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Direct quotes with line numbers"
                    },
                    "source": {
                        "type": "string",
                        "description": "One-line summary of core evidence"
                    },
                    "citations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tool calls that supported this claim"
                    }
                },
                "required": ["type", "span", "mappings"]
            }
        },
        "entities": {
            "type": "object",
            "properties": {
                "threat_actors": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "malware": {
                    "type": "array", 
                    "items": {"type": "string"}
                },
                "tools": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "campaigns": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "vulnerabilities": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "infrastructure": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "value": {"type": "string"},
                            "type": {
                                "type": "string",
                                "enum": ["ipv4", "ipv6", "domain", "url", "hash"]
                            }
                        }
                    }
                }
            }
        },
        "temporal": {
            "type": "object",
            "properties": {
                "first_seen": {"type": ["string", "null"]},
                "last_seen": {"type": ["string", "null"]},
                "campaign_dates": {
                    "type": "array",
                    "items": {"type": "string"}
                }
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


# Schema for detection opportunities
DETECTION_OPPORTUNITY_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {
            "type": "string",
            "pattern": "^opp-[a-f0-9-]+$"
        },
        "name": {
            "type": "string",
            "description": "Descriptive name for the detection"
        },
        "technique_id": {
            "type": "string",
            "pattern": "^T[0-9]{4}(\.[0-9]{3})?$",
            "description": "MITRE ATT&CK technique ID"
        },
        "artefacts": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Observable artifacts to detect"
        },
        "behaviours": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Behavioral patterns to detect"
        },
        "rationale": {
            "type": "string",
            "description": "Why this detection matters"
        },
        "source_refs": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Citations to technique IDs or line numbers"
        },
        "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1,
            "description": "Confidence level (0.0-1.0)"
        },
        "source": {
            "type": "string",
            "maxLength": 120,
            "description": "One-line citation with core evidence"
        },
        "evidence": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Direct quotes from report"
        },
        "evaluation": {
            "type": "object",
            "properties": {
                "quality_score": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100
                },
                "criteria": {
                    "type": "object",
                    "properties": {
                        "has_technique_id": {"type": "boolean"},
                        "has_artefacts": {"type": "boolean"},
                        "has_evidence": {"type": "boolean"},
                        "realistic_confidence": {"type": "boolean"}
                    }
                }
            }
        }
    },
    "required": ["id", "name", "technique_id", "rationale", "confidence", "source"]
}


# Schema for attack flow
ATTACK_FLOW_SCHEMA = {
    "type": "object",
    "properties": {
        "flow": {
            "type": "object",
            "properties": {
                "label": {"type": "string", "const": "AttackFlow"},
                "pk": {"type": "string"},
                "properties": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "description": {"type": "string"}
                    }
                }
            }
        },
        "steps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "order": {
                        "type": "integer",
                        "minimum": 1
                    },
                    "entity": {
                        "type": "object",
                        "properties": {
                            "label": {
                                "type": "string",
                                "enum": ["Technique", "Tool", "Malware", "Infrastructure"]
                            },
                            "pk": {"type": "string"}
                        }
                    },
                    "description": {
                        "type": "string",
                        "maxLength": 120
                    },
                    "reason": {
                        "type": "string",
                        "maxLength": 60
                    }
                },
                "required": ["order", "entity", "description", "reason"]
            }
        },
        "notes": {
            "type": "string",
            "description": "Overall reasoning and confidence"
        }
    },
    "required": ["flow", "steps"]
}