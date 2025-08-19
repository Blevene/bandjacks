"""Async extraction run management: start, status, result."""

import asyncio
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from bandjacks.llm.agentic_v2 import run_agentic_v2
from bandjacks.llm.tracker import ExtractionTracker


router = APIRouter(prefix="/extract/runs", tags=["extract_runs"])


RUNS: Dict[str, Dict[str, Any]] = {}


class StartRunRequest(BaseModel):
    method: str = Field("agentic_v2", description="Extraction method")
    content: str = Field(..., description="Report text")
    title: Optional[str] = Field(None)
    source_type: Optional[str] = Field("report")
    config: Optional[Dict[str, Any]] = Field(default_factory=dict)


class StartRunResponse(BaseModel):
    run_id: str
    accepted: bool = True


@router.post("", response_model=StartRunResponse)
async def start_run(req: StartRunRequest) -> StartRunResponse:
    if req.method != "agentic_v2":
        raise HTTPException(status_code=400, detail="Only agentic_v2 is supported for runs")

    tracker = ExtractionTracker()
    run_id = tracker.run_id
    RUNS[run_id] = {"tracker": tracker, "task": None, "result": None}

    async def _worker():
        try:
            cfg = req.config or {}
            # ensure title flows to assembler
            cfg.setdefault("title", req.title)
            result = run_agentic_v2(req.content, cfg, tracker=tracker)
            RUNS[run_id]["result"] = result
        except Exception as e:
            tracker.log("error", "run_failed", error=str(e))
            RUNS[run_id]["result"] = {"error": str(e), "metrics": tracker.snapshot()}

    # Run in background
    RUNS[run_id]["task"] = asyncio.create_task(_worker())
    return StartRunResponse(run_id=run_id)


@router.get("/{run_id}/status")
async def get_status(run_id: str) -> Dict[str, Any]:
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    tracker: ExtractionTracker = run["tracker"]
    snap = tracker.snapshot()
    # add state info
    task = run.get("task")
    snap["state"] = (
        "finished" if task and task.done() else "running"
    )
    return snap


@router.get("/{run_id}/result")
async def get_result(run_id: str) -> Dict[str, Any]:
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    task = run.get("task")
    if task and not task.done():
        raise HTTPException(status_code=202, detail="run in progress")
    result = run.get("result")
    if result is None:
        raise HTTPException(status_code=500, detail="run finished without result")
    return result


