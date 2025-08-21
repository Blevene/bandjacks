from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import time
import uuid


@dataclass
class LlmCallStat:
    model: str
    ms: int
    tokens_in: int
    tokens_out: int
    tool_calls: int


@dataclass
class SpanState:
    state: str  # queued|retrieved|discovered|mapped|verified|consolidated
    cands: int = 0
    llm_calls: int = 0
    last_error: Optional[str] = None


@dataclass
class ExtractionTracker:
    run_id: str = field(default_factory=lambda: f"ex-{uuid.uuid4()}")
    started_at: float = field(default_factory=time.time)
    stage: str = "init"
    spans_total: int = 0
    spans_processed: int = 0
    counters: Dict[str, int] = field(default_factory=lambda: {
        "llm_calls": 0,
        "candidates": 0,
        "verified_claims": 0,
        "techniques": 0,
        "spans_found": 0,
    })
    cost_usd: float = 0.0
    llm_stats: List[LlmCallStat] = field(default_factory=list)
    span_states: Dict[int, SpanState] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)

    def log(self, level: str, msg: str, **kw) -> None:
        self.events.append({"ts": time.time(), "level": level, "msg": msg, **kw})

    def set_stage(self, name: str) -> None:
        self.stage = name
        self.log("info", f"stage:{name}")

    def set_spans_total(self, n: int) -> None:
        self.spans_total = n
        self.counters["spans_found"] = n

    def update_span(self, idx: int, state: str, **kw) -> None:
        st = self.span_states.get(idx, SpanState(state="queued"))
        st.state = state
        for k, v in kw.items():
            setattr(st, k, v)
        self.span_states[idx] = st

    def add_llm_call(self, model: str, ms: int, tokens_in: int, tokens_out: int, tool_calls: int, cost_usd: float) -> None:
        self.counters["llm_calls"] += 1
        self.cost_usd += cost_usd
        self.llm_stats.append(LlmCallStat(model, ms, tokens_in, tokens_out, tool_calls))

    def percent(self) -> int:
        if self.spans_total <= 0:
            return 0
        base = int((self.spans_processed / max(1, self.spans_total)) * 100)
        stage_adj = {
            "SpanFinder": 5,
            "Retriever": 20,
            "Discovery": 35,
            "Mapper": 60,
            "Verifier": 75,
            "Consolidator": 90,
            "Assembler": 100,
        }
        return min(100, max(base, stage_adj.get(self.stage, base)))

    def snapshot(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "stage": self.stage,
            "percent": self.percent(),
            "spans_total": self.spans_total,
            "spans_processed": self.spans_processed,
            "counters": self.counters,
            "cost_usd": round(self.cost_usd, 4),
            "dur_sec": int(time.time() - self.started_at),
            "events_tail": self.events[-25:],
        }


