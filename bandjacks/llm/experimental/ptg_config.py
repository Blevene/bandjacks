"""Configuration flags for PTG building - Epic 4 T27."""

import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
import json


@dataclass
class PTGBuildConfig:
    """Configuration for PTG model building behavior."""
    
    # Feature flags
    enable_judge: bool = field(
        default_factory=lambda: os.getenv("PTG_ENABLE_JUDGE", "true").lower() == "true"
    )
    enable_triage: bool = field(
        default_factory=lambda: os.getenv("PTG_ENABLE_TRIAGE", "true").lower() == "true"
    )
    enable_evidence_retrieval: bool = field(
        default_factory=lambda: os.getenv("PTG_ENABLE_EVIDENCE", "true").lower() == "true"
    )
    enable_cache: bool = field(
        default_factory=lambda: os.getenv("PTG_ENABLE_CACHE", "true").lower() == "true"
    )
    enable_async_processing: bool = field(
        default_factory=lambda: os.getenv("PTG_ENABLE_ASYNC", "false").lower() == "true"
    )
    
    # Judge configuration
    judge_model: str = field(
        default_factory=lambda: os.getenv("PTG_JUDGE_MODEL", "gpt-4o-mini")
    )
    judge_batch_size: int = field(
        default_factory=lambda: int(os.getenv("PTG_JUDGE_BATCH_SIZE", "10"))
    )
    judge_confidence_threshold: float = field(
        default_factory=lambda: float(os.getenv("PTG_JUDGE_CONFIDENCE_THRESHOLD", "0.7"))
    )
    
    # Triage configuration
    triage_ambiguity_threshold: float = field(
        default_factory=lambda: float(os.getenv("PTG_TRIAGE_AMBIGUITY", "0.7"))
    )
    triage_min_count: int = field(
        default_factory=lambda: int(os.getenv("PTG_TRIAGE_MIN_COUNT", "2"))
    )
    triage_max_pairs: int = field(
        default_factory=lambda: int(os.getenv("PTG_TRIAGE_MAX_PAIRS", "100"))
    )
    
    # Evidence retrieval
    evidence_top_k: int = field(
        default_factory=lambda: int(os.getenv("PTG_EVIDENCE_TOP_K", "5"))
    )
    evidence_min_score: float = field(
        default_factory=lambda: float(os.getenv("PTG_EVIDENCE_MIN_SCORE", "0.5"))
    )
    
    # PTG parameters
    alpha_statistical: float = field(
        default_factory=lambda: float(os.getenv("PTG_ALPHA", "0.6"))
    )
    beta_judge: float = field(
        default_factory=lambda: float(os.getenv("PTG_BETA", "0.3"))
    )
    gamma_structure: float = field(
        default_factory=lambda: float(os.getenv("PTG_GAMMA", "0.1"))
    )
    delta_temporal: float = field(
        default_factory=lambda: float(os.getenv("PTG_DELTA", "0.0"))
    )
    epsilon_confidence: float = field(
        default_factory=lambda: float(os.getenv("PTG_EPSILON", "0.0"))
    )
    
    # Processing limits
    max_nodes: int = field(
        default_factory=lambda: int(os.getenv("PTG_MAX_NODES", "500"))
    )
    max_edges: int = field(
        default_factory=lambda: int(os.getenv("PTG_MAX_EDGES", "2000"))
    )
    edge_probability_threshold: float = field(
        default_factory=lambda: float(os.getenv("PTG_EDGE_THRESHOLD", "0.1"))
    )
    
    # Budget controls
    max_judge_cost_usd: float = field(
        default_factory=lambda: float(os.getenv("PTG_MAX_JUDGE_COST", "5.0"))
    )
    max_build_time_seconds: int = field(
        default_factory=lambda: int(os.getenv("PTG_MAX_BUILD_TIME", "300"))
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary for serialization."""
        return {
            "enable_judge": self.enable_judge,
            "enable_triage": self.enable_triage,
            "enable_evidence_retrieval": self.enable_evidence_retrieval,
            "enable_cache": self.enable_cache,
            "enable_async_processing": self.enable_async_processing,
            "judge_model": self.judge_model,
            "judge_batch_size": self.judge_batch_size,
            "judge_confidence_threshold": self.judge_confidence_threshold,
            "triage_ambiguity_threshold": self.triage_ambiguity_threshold,
            "triage_min_count": self.triage_min_count,
            "triage_max_pairs": self.triage_max_pairs,
            "evidence_top_k": self.evidence_top_k,
            "evidence_min_score": self.evidence_min_score,
            "alpha_statistical": self.alpha_statistical,
            "beta_judge": self.beta_judge,
            "gamma_structure": self.gamma_structure,
            "delta_temporal": self.delta_temporal,
            "epsilon_confidence": self.epsilon_confidence,
            "max_nodes": self.max_nodes,
            "max_edges": self.max_edges,
            "edge_probability_threshold": self.edge_probability_threshold,
            "max_judge_cost_usd": self.max_judge_cost_usd,
            "max_build_time_seconds": self.max_build_time_seconds
        }
    
    def validate(self) -> bool:
        """Validate configuration constraints."""
        # Check feature weights sum to 1.0
        weight_sum = (
            self.alpha_statistical + 
            self.beta_judge + 
            self.gamma_structure + 
            self.delta_temporal + 
            self.epsilon_confidence
        )
        
        if abs(weight_sum - 1.0) > 0.01:
            raise ValueError(f"Feature weights must sum to 1.0, got {weight_sum}")
        
        # Check thresholds are in valid ranges
        if not 0 <= self.judge_confidence_threshold <= 1:
            raise ValueError(f"Judge confidence threshold must be in [0, 1]")
        
        if not 0 <= self.triage_ambiguity_threshold <= 1:
            raise ValueError(f"Triage ambiguity threshold must be in [0, 1]")
        
        if not 0 <= self.edge_probability_threshold <= 1:
            raise ValueError(f"Edge probability threshold must be in [0, 1]")
        
        # Check positive values
        if self.judge_batch_size <= 0:
            raise ValueError("Judge batch size must be positive")
        
        if self.max_nodes <= 0 or self.max_edges <= 0:
            raise ValueError("Max nodes and edges must be positive")
        
        return True
    
    @classmethod
    def from_env(cls) -> "PTGBuildConfig":
        """Create config from environment variables."""
        config = cls()
        try:
            config.validate()
        except ValueError as e:
            # Log warning and use defaults if validation fails
            import logging
            logging.warning(f"PTG config validation failed, using defaults: {e}")
            config = cls()
        return config
    
    @classmethod
    def from_json(cls, json_str: str) -> "PTGBuildConfig":
        """Create config from JSON string."""
        data = json.loads(json_str)
        return cls(**data)


# Global config instance
_ptg_config: Optional[PTGBuildConfig] = None


def get_ptg_config() -> PTGBuildConfig:
    """Get or create global PTG configuration."""
    global _ptg_config
    if _ptg_config is None:
        _ptg_config = PTGBuildConfig.from_env()
    return _ptg_config


def set_ptg_config(config: PTGBuildConfig) -> None:
    """Set global PTG configuration."""
    global _ptg_config
    config.validate()
    _ptg_config = config


def reset_ptg_config() -> None:
    """Reset PTG configuration to defaults from environment."""
    global _ptg_config
    _ptg_config = PTGBuildConfig.from_env()