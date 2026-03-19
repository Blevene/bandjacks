"""LLM cost statistics endpoint."""

from fastapi import APIRouter
from bandjacks.llm.token_utils import get_budget_tracker

router = APIRouter(tags=["costs"])


@router.get("/costs/stats")
def get_cost_stats():
    """Return current LLM cost statistics.

    Returns daily aggregate of token usage, costs, and per-model breakdowns.
    """
    tracker = get_budget_tracker()
    daily_stats = tracker.get_usage_stats()

    return {"daily": daily_stats}
