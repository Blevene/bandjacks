"""Defense API metrics collection for monitoring and observability."""

import time
from typing import Dict, Any, Optional, Callable
from functools import wraps
import logging
from threading import Lock

logger = logging.getLogger(__name__)


class DefenseMetrics:
    """Singleton metrics collector for defense endpoints."""
    
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        # Counters
        self.overlay_calls_total = 0
        self.mincut_calls_total = 0
        self.defenses_returned_total = 0
        self.techniques_processed_total = 0
        
        # Aggregates for averages
        self.counters_per_step_sum = 0
        self.overlay_calls_with_steps = 0
        self.mincut_coverage_sum = 0
        self.mincut_recommendation_sum = 0
        
        # Latency tracking
        self.overlay_latencies = []
        self.mincut_latencies = []
        
        # Error counters
        self.overlay_errors = 0
        self.mincut_errors = 0
        
        self._initialized = True
    
    def record_overlay_call(
        self,
        flow_id: str,
        total_actions: int,
        defended_actions: int,
        defense_count: int,
        latency_ms: float,
        error: Optional[str] = None
    ):
        """Record metrics for a defense overlay API call."""
        self.overlay_calls_total += 1
        
        if error:
            self.overlay_errors += 1
            logger.warning(f"Overlay call failed for flow {flow_id}: {error}")
        else:
            self.defenses_returned_total += defense_count
            self.techniques_processed_total += total_actions
            
            if total_actions > 0:
                avg_counters = defense_count / total_actions
                self.counters_per_step_sum += avg_counters
                self.overlay_calls_with_steps += 1
            
            self.overlay_latencies.append(latency_ms)
            
            # Keep only last 1000 latencies to prevent memory growth
            if len(self.overlay_latencies) > 1000:
                self.overlay_latencies = self.overlay_latencies[-1000:]
    
    def record_mincut_call(
        self,
        flow_id: str,
        total_techniques: int,
        covered_techniques: int,
        recommendation_count: int,
        latency_ms: float,
        error: Optional[str] = None
    ):
        """Record metrics for a mincut API call."""
        self.mincut_calls_total += 1
        
        if error:
            self.mincut_errors += 1
            logger.warning(f"Mincut call failed for flow {flow_id}: {error}")
        else:
            # Calculate coverage delta (improvement)
            if total_techniques > 0:
                coverage_pct = (covered_techniques / total_techniques) * 100
                self.mincut_coverage_sum += coverage_pct
            
            self.mincut_recommendation_sum += recommendation_count
            self.mincut_latencies.append(latency_ms)
            
            # Keep only last 1000 latencies
            if len(self.mincut_latencies) > 1000:
                self.mincut_latencies = self.mincut_latencies[-1000:]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics snapshot."""
        metrics = {
            # Counters
            "overlay_calls_total": self.overlay_calls_total,
            "mincut_calls_total": self.mincut_calls_total,
            "defenses_returned_total": self.defenses_returned_total,
            "techniques_processed_total": self.techniques_processed_total,
            
            # Averages
            "avg_counters_per_step": (
                self.counters_per_step_sum / self.overlay_calls_with_steps
                if self.overlay_calls_with_steps > 0 else 0
            ),
            "mincut_coverage_delta": (
                self.mincut_coverage_sum / self.mincut_calls_total
                if self.mincut_calls_total > 0 else 0
            ),
            "mincut_recommendation_size": (
                self.mincut_recommendation_sum / self.mincut_calls_total
                if self.mincut_calls_total > 0 else 0
            ),
            
            # Latencies
            "overlay_latency_p50": self._percentile(self.overlay_latencies, 50),
            "overlay_latency_p95": self._percentile(self.overlay_latencies, 95),
            "overlay_latency_p99": self._percentile(self.overlay_latencies, 99),
            "mincut_latency_p50": self._percentile(self.mincut_latencies, 50),
            "mincut_latency_p95": self._percentile(self.mincut_latencies, 95),
            "mincut_latency_p99": self._percentile(self.mincut_latencies, 99),
            
            # Error rates
            "overlay_error_rate": (
                self.overlay_errors / self.overlay_calls_total
                if self.overlay_calls_total > 0 else 0
            ),
            "mincut_error_rate": (
                self.mincut_errors / self.mincut_calls_total
                if self.mincut_calls_total > 0 else 0
            ),
        }
        
        return metrics
    
    def _percentile(self, values: list, percentile: float) -> float:
        """Calculate percentile from list of values."""
        if not values:
            return 0.0
        
        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile / 100)
        
        if index >= len(sorted_values):
            return sorted_values[-1]
        
        return sorted_values[index]
    
    def reset(self):
        """Reset all metrics to zero."""
        self.__init__()
        self._initialized = True


# Global metrics instance
metrics = DefenseMetrics()


def track_overlay_metrics(func: Callable) -> Callable:
    """
    Decorator to track defense overlay endpoint metrics.
    
    Usage:
        @track_overlay_metrics
        async def get_defense_overlay(flow_id: str):
            ...
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        error = None
        result = None
        
        try:
            result = await func(*args, **kwargs)
            return result
        except Exception as e:
            error = str(e)
            raise
        finally:
            latency_ms = (time.time() - start_time) * 1000
            
            # Extract metrics from result if available
            if result and hasattr(result, '__dict__'):
                flow_id = getattr(result, 'flow_id', 'unknown')
                total_actions = getattr(result, 'total_actions', 0)
                defended_actions = getattr(result, 'defended_actions', 0)
                
                # Count total defenses
                defense_count = 0
                if hasattr(result, 'defenses_by_action'):
                    for action in result.defenses_by_action:
                        defense_count += action.get('defense_count', 0)
                
                metrics.record_overlay_call(
                    flow_id=flow_id,
                    total_actions=total_actions,
                    defended_actions=defended_actions,
                    defense_count=defense_count,
                    latency_ms=latency_ms,
                    error=error
                )
            else:
                # Minimal metrics if result not available
                metrics.record_overlay_call(
                    flow_id='unknown',
                    total_actions=0,
                    defended_actions=0,
                    defense_count=0,
                    latency_ms=latency_ms,
                    error=error or "No result"
                )
    
    return wrapper


def track_mincut_metrics(func: Callable) -> Callable:
    """
    Decorator to track mincut endpoint metrics.
    
    Usage:
        @track_mincut_metrics
        async def compute_minimal_defense(request):
            ...
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        error = None
        result = None
        
        try:
            result = await func(*args, **kwargs)
            return result
        except Exception as e:
            error = str(e)
            raise
        finally:
            latency_ms = (time.time() - start_time) * 1000
            
            # Extract metrics from result
            if result and hasattr(result, '__dict__'):
                flow_id = getattr(result, 'flow_id', 'unknown')
                total_techniques = getattr(result, 'total_attack_techniques', 0)
                covered_techniques = getattr(result, 'covered_techniques', 0)
                recommendations = getattr(result, 'recommendations', [])
                
                metrics.record_mincut_call(
                    flow_id=flow_id,
                    total_techniques=total_techniques,
                    covered_techniques=covered_techniques,
                    recommendation_count=len(recommendations),
                    latency_ms=latency_ms,
                    error=error
                )
            else:
                # Minimal metrics if result not available
                metrics.record_mincut_call(
                    flow_id='unknown',
                    total_techniques=0,
                    covered_techniques=0,
                    recommendation_count=0,
                    latency_ms=latency_ms,
                    error=error or "No result"
                )
    
    return wrapper


def get_defense_metrics() -> Dict[str, Any]:
    """Get current defense metrics snapshot."""
    return metrics.get_metrics()


def reset_defense_metrics():
    """Reset all defense metrics."""
    metrics.reset()