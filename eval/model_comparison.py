#!/usr/bin/env python3
"""Compare local vs cloud LLM performance on the extraction pipeline.

Runs the same reports through two model configurations and produces a
side-by-side comparison of extraction quality, latency, cost, and
JSON compliance.

Usage:
    # Compare local Gemma 4 against cloud Gemini 3 Flash:
    python -m eval.model_comparison

    # Run only specific reports:
    python -m eval.model_comparison --reports apt29

    # Use a different local model:
    python -m eval.model_comparison --local-model "nvidia-nemotron-3-nano-30b-a3b-mlx"

    # Override cloud model:
    python -m eval.model_comparison --cloud-model "gemini/gemini-2.5-flash"
"""

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from bandjacks.llm.client import LLMClient
from bandjacks.llm.extraction_pipeline import ExtractionPipeline

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Ground-truth technique IDs extracted from the sample reports
# ---------------------------------------------------------------------------
GROUND_TRUTH: Dict[str, Set[str]] = {
    # Lazarus markdown report — technique IDs are explicitly listed
    "lazarus": {
        "T1566.001", "T1078", "T1059.001", "T1059.003", "T1053.005",
        "T1547.001", "T1543.003", "T1546.003", "T1055", "T1027", "T1070",
        "T1003", "T1558.003", "T1003.001", "T1056.001", "T1021.001",
        "T1021.002", "T1047", "T1114", "T1005", "T1071.001", "T1102.001",
        "T1041", "T1567.002", "T1486",
    },
    # APT29 plaintext report — techniques implied by descriptions
    "apt29": {
        "T1566.001",  # Spearphishing Attachment
        "T1203",      # Exploitation for Client Execution
        "T1059.001",  # PowerShell
        "T1547.001",  # Registry Run Keys
        "T1053.005",  # Scheduled Task
        "T1082",      # System Information Discovery
        "T1016",      # System Network Configuration Discovery
        "T1018",      # Remote System Discovery
        "T1087",      # Account Discovery
        "T1003",      # OS Credential Dumping
        "T1003.001",  # LSASS Memory
        "T1550.002",  # Pass the Hash
        "T1558.003",  # Kerberoasting
        "T1021.001",  # Remote Desktop Protocol
        "T1047",      # WMI
        "T1021.006",  # Windows Remote Management
        "T1071.001",  # Web Protocols
        "T1090.004",  # Domain Fronting
        "T1102",      # Web Service
        "T1560.001",  # Archive via Utility (7-zip)
        "T1567.002",  # Exfiltration to Cloud Storage
        "T1070.001",  # Clear Windows Event Logs
        "T1070.006",  # Timestomp
        "T1574.002",  # DLL Side-Loading
        "T1001.002",  # Steganography
        "T1036",      # Masquerading
    },
}


@dataclass
class ModelRunResult:
    """Captures everything from a single pipeline run."""
    model_label: str
    model_id: str
    report_name: str
    techniques: Dict[str, Any] = field(default_factory=dict)
    entities: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    flow_steps: int = 0
    flow_data: Dict[str, Any] = field(default_factory=dict)
    json_errors: int = 0
    total_llm_calls: int = 0
    total_tokens_in: int = 0
    total_tokens_out: int = 0
    cost_usd: float = 0.0
    duration_sec: float = 0.0
    error: Optional[str] = None


@dataclass
class ComparisonResult:
    """Side-by-side comparison of two model runs on the same report."""
    report_name: str
    ground_truth_ids: Set[str]
    cloud: ModelRunResult
    local: ModelRunResult

    # Computed metrics (populated by compute())
    cloud_recall: float = 0.0
    local_recall: float = 0.0
    cloud_precision: float = 0.0
    local_precision: float = 0.0
    cloud_f1: float = 0.0
    local_f1: float = 0.0
    overlap_ids: Set[str] = field(default_factory=set)
    cloud_only_ids: Set[str] = field(default_factory=set)
    local_only_ids: Set[str] = field(default_factory=set)

    def compute(self) -> "ComparisonResult":
        cloud_ids = set(self.cloud.techniques.keys())
        local_ids = set(self.local.techniques.keys())
        gt = self.ground_truth_ids

        self.overlap_ids = cloud_ids & local_ids
        self.cloud_only_ids = cloud_ids - local_ids
        self.local_only_ids = local_ids - cloud_ids

        # Recall: how many ground-truth techniques did the model find?
        if gt:
            self.cloud_recall = len(cloud_ids & gt) / len(gt)
            self.local_recall = len(local_ids & gt) / len(gt)
        # Precision: how many extracted techniques are in ground truth?
        if cloud_ids:
            self.cloud_precision = len(cloud_ids & gt) / len(cloud_ids) if gt else 0
        if local_ids:
            self.local_precision = len(local_ids & gt) / len(local_ids) if gt else 0
        # F1
        if self.cloud_precision + self.cloud_recall > 0:
            self.cloud_f1 = 2 * self.cloud_precision * self.cloud_recall / (self.cloud_precision + self.cloud_recall)
        if self.local_precision + self.local_recall > 0:
            self.local_f1 = 2 * self.local_precision * self.local_recall / (self.local_precision + self.local_recall)

        return self


# ---------------------------------------------------------------------------
# Pipeline runner — patches the LLM client to use a specific model
# ---------------------------------------------------------------------------

def _run_pipeline(
    report_text: str,
    report_name: str,
    model_label: str,
    model_id: str,
    api_base: Optional[str] = None,
    api_key: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
) -> ModelRunResult:
    """Run the extraction pipeline with a specific model configuration."""

    result = ModelRunResult(
        model_label=model_label,
        model_id=model_id,
        report_name=report_name,
    )

    # Monkey-patch a fresh LLMClient for this run
    import bandjacks.llm.client as client_mod
    from bandjacks.llm.cache import get_cache
    original_client = client_mod._global_client

    try:
        # Clear the LLM response cache so the second model doesn't hit
        # cached responses from the first model's run.
        cache = get_cache()
        with cache.lock:
            cache.cache.clear()
        logger.info(f"[{model_label}] Cleared LLM response cache")

        patched = LLMClient.__new__(LLMClient)
        # Copy all attributes from a default-constructed client
        base = LLMClient()
        patched.__dict__.update(base.__dict__)

        # Override model routing
        patched.model = model_id
        patched.api_key_for_completion = api_key or base.api_key_for_completion
        if api_base:
            patched.local_api_base = api_base
            # Local models need longer timeout (reasoning models are slow)
            # and higher max_tokens (reasoning tokens eat into the budget)
            patched.timeout = 600  # 10 minutes
            patched.max_tokens = 16000  # reasoning overhead ~75%
        else:
            patched.local_api_base = ""
        # Disable fallbacks so we measure this model only
        patched.fallback_models = []

        client_mod._global_client = patched

        pipeline = ExtractionPipeline()
        run_config = config or {}
        # Disable caching so both models get fresh calls
        run_config["disable_llm_cache"] = True

        logger.info(f"[{model_label}] Starting extraction on '{report_name}' with model={model_id}")
        t0 = time.time()
        output = pipeline.extract_and_build_flow(report_text, config=run_config)
        result.duration_sec = time.time() - t0

        result.techniques = output.get("techniques", {})
        result.entities = output.get("entities", {})
        result.metrics = output.get("metrics", {})
        # Flow data — normalized flows use "steps" (renamed from "actions")
        flows = output.get("flows", [])
        if flows:
            flow = flows[0]
            steps = flow.get("steps", flow.get("actions", []))
            result.flow_steps = len(steps)
            result.flow_data = flow
        else:
            fallback_flow = output.get("flow", {})
            steps = fallback_flow.get("steps", fallback_flow.get("actions", []))
            result.flow_steps = len(steps)
            result.flow_data = fallback_flow
        result.total_llm_calls = result.metrics.get("llm_calls", 0)
        result.total_tokens_in = result.metrics.get("tokens_in", 0)
        result.total_tokens_out = result.metrics.get("tokens_out", 0)
        result.cost_usd = result.metrics.get("cost_usd", 0.0)

        logger.info(
            f"[{model_label}] Done: {len(result.techniques)} techniques, "
            f"{result.duration_sec:.1f}s, ${result.cost_usd:.4f}"
        )

    except Exception as e:
        result.error = str(e)
        logger.error(f"[{model_label}] Pipeline failed: {e}", exc_info=True)
    finally:
        # Restore original client
        client_mod._global_client = original_client

    return result


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def _fmt_pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def _print_comparison(comp: ComparisonResult) -> None:
    """Print a formatted comparison table."""
    c, l = comp.cloud, comp.local
    print(f"\n{'=' * 80}")
    print(f"  REPORT: {comp.report_name}")
    print(f"  Ground truth: {len(comp.ground_truth_ids)} techniques")
    print(f"{'=' * 80}")

    header = f"{'Metric':<35} {'Cloud (' + c.model_id[:20] + ')':<25} {'Local (' + l.model_id[:20] + ')':<25}"
    print(f"\n{header}")
    print("-" * 85)

    rows = [
        ("Techniques extracted", str(len(c.techniques)), str(len(l.techniques))),
        ("Recall (vs ground truth)", _fmt_pct(comp.cloud_recall), _fmt_pct(comp.local_recall)),
        ("Precision (vs ground truth)", _fmt_pct(comp.cloud_precision), _fmt_pct(comp.local_precision)),
        ("F1 Score", _fmt_pct(comp.cloud_f1), _fmt_pct(comp.local_f1)),
        ("", "", ""),
        ("Duration (sec)", f"{c.duration_sec:.1f}s", f"{l.duration_sec:.1f}s"),
        ("LLM calls", str(c.total_llm_calls), str(l.total_llm_calls)),
        ("Tokens in", f"{c.total_tokens_in:,}", f"{l.total_tokens_in:,}"),
        ("Tokens out", f"{c.total_tokens_out:,}", f"{l.total_tokens_out:,}"),
        ("Cost (USD)", f"${c.cost_usd:.4f}", f"${l.cost_usd:.4f}"),
        ("", "", ""),
        ("Flow steps", str(c.flow_steps), str(l.flow_steps)),
        ("Entities extracted", str(len(c.entities.get("entities", []))), str(len(l.entities.get("entities", [])))),
    ]

    if c.error:
        rows.append(("Cloud ERROR", c.error[:40], ""))
    if l.error:
        rows.append(("Local ERROR", "", l.error[:40]))

    for label, cv, lv in rows:
        print(f"  {label:<33} {cv:<25} {lv:<25}")

    # Technique overlap analysis
    print(f"\n  --- Technique Overlap ---")
    print(f"  Both models found:  {len(comp.overlap_ids)}")
    print(f"  Cloud only:         {len(comp.cloud_only_ids)}  {sorted(comp.cloud_only_ids)}")
    print(f"  Local only:         {len(comp.local_only_ids)}  {sorted(comp.local_only_ids)}")

    # Ground truth hits/misses
    cloud_ids = set(c.techniques.keys())
    local_ids = set(l.techniques.keys())
    gt = comp.ground_truth_ids
    if gt:
        cloud_hits = sorted(cloud_ids & gt)
        local_hits = sorted(local_ids & gt)
        missed_both = sorted(gt - cloud_ids - local_ids)
        print(f"\n  --- Ground Truth Coverage ---")
        print(f"  Cloud hit:   {len(cloud_hits)}/{len(gt)}  {cloud_hits}")
        print(f"  Local hit:   {len(local_hits)}/{len(gt)}  {local_hits}")
        if missed_both:
            print(f"  Missed both: {len(missed_both)}  {missed_both}")

    # Confidence distribution
    if c.techniques or l.techniques:
        print(f"\n  --- Confidence Distribution ---")
        for label, techs in [("Cloud", c.techniques), ("Local", l.techniques)]:
            if techs:
                confs = [t.get("confidence", 0) for t in techs.values() if isinstance(t, dict)]
                if confs:
                    avg = sum(confs) / len(confs)
                    lo, hi = min(confs), max(confs)
                    print(f"  {label}: avg={avg:.0f}  min={lo}  max={hi}")

    # Attack flow comparison
    if c.flow_data or l.flow_data:
        print(f"\n  --- Attack Flow Comparison ---")
        for label, run in [("Cloud", c), ("Local", l)]:
            flow = run.flow_data
            if not flow:
                print(f"  {label}: No flow generated")
                continue
            actions = flow.get("steps", flow.get("actions", []))
            edges = flow.get("edges", [])
            stats = flow.get("stats", {})
            tiers = stats.get("tier_distribution", {})

            # Tactic coverage in flow
            tactics_in_flow = []
            for a in actions:
                t = a.get("tactic")
                if t and (not tactics_in_flow or tactics_in_flow[-1] != t):
                    tactics_in_flow.append(t)

            print(f"  {label}: {len(actions)} steps, {len(edges)} edges "
                  f"(high={tiers.get('high', 0)}, med={tiers.get('medium', 0)}, low={tiers.get('low', 0)})")
            print(f"    Kill chain: {' → '.join(tactics_in_flow)}")
            # Show first/last 3 steps
            if len(actions) <= 8:
                for i, a in enumerate(actions):
                    print(f"    [{i}] {a.get('name', '?')} ({a.get('external_id', '?')}) [{a.get('tactic', '?')}]")
            else:
                for i, a in enumerate(actions[:3]):
                    print(f"    [{i}] {a.get('name', '?')} ({a.get('external_id', '?')}) [{a.get('tactic', '?')}]")
                print(f"    ... ({len(actions) - 6} more steps) ...")
                for a in actions[-3:]:
                    idx = actions.index(a)
                    print(f"    [{idx}] {a.get('name', '?')} ({a.get('external_id', '?')}) [{a.get('tactic', '?')}]")


def _save_results(comparisons: List[ComparisonResult], output_dir: Path) -> Path:
    """Save detailed results to JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = output_dir / f"model_comparison_{ts}.json"

    data = {
        "timestamp": ts,
        "comparisons": [],
    }

    for comp in comparisons:
        entry = {
            "report": comp.report_name,
            "ground_truth_count": len(comp.ground_truth_ids),
            "cloud": {
                "model": comp.cloud.model_id,
                "techniques_count": len(comp.cloud.techniques),
                "recall": round(comp.cloud_recall, 4),
                "precision": round(comp.cloud_precision, 4),
                "f1": round(comp.cloud_f1, 4),
                "duration_sec": round(comp.cloud.duration_sec, 1),
                "llm_calls": comp.cloud.total_llm_calls,
                "tokens_in": comp.cloud.total_tokens_in,
                "tokens_out": comp.cloud.total_tokens_out,
                "cost_usd": round(comp.cloud.cost_usd, 6),
                "techniques": {k: _serialize_technique(v) for k, v in comp.cloud.techniques.items()},
                "flow": _serialize_flow(comp.cloud.flow_data),
                "error": comp.cloud.error,
            },
            "local": {
                "model": comp.local.model_id,
                "techniques_count": len(comp.local.techniques),
                "recall": round(comp.local_recall, 4),
                "precision": round(comp.local_precision, 4),
                "f1": round(comp.local_f1, 4),
                "duration_sec": round(comp.local.duration_sec, 1),
                "llm_calls": comp.local.total_llm_calls,
                "tokens_in": comp.local.total_tokens_in,
                "tokens_out": comp.local.total_tokens_out,
                "cost_usd": round(comp.local.cost_usd, 6),
                "techniques": {k: _serialize_technique(v) for k, v in comp.local.techniques.items()},
                "flow": _serialize_flow(comp.local.flow_data),
                "error": comp.local.error,
            },
            "overlap": sorted(comp.overlap_ids),
            "cloud_only": sorted(comp.cloud_only_ids),
            "local_only": sorted(comp.local_only_ids),
        }
        data["comparisons"].append(entry)

    with open(out_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    return out_path


def _serialize_technique(t: Any) -> Any:
    if isinstance(t, dict):
        return {k: v for k, v in t.items() if k != "embedding"}
    return str(t)


def _serialize_flow(flow: Dict[str, Any]) -> Dict[str, Any]:
    """Serialize flow for JSON output, keeping steps and stats."""
    if not flow:
        return {}
    # Normalized flows use "steps" (renamed from "actions" in the pipeline)
    steps = flow.get("steps", flow.get("actions", []))
    return {
        "flow_type": flow.get("flow_type", "unknown"),
        "steps_count": len(steps),
        "stats": flow.get("stats", {}),
        "steps": [
            {
                "order": a.get("order", i),
                "external_id": a.get("external_id", a.get("attack_pattern_ref", "").replace("attack-pattern--", "")),
                "name": a.get("name", ""),
                "tactic": a.get("tactic", ""),
                "confidence": a.get("confidence", 0),
            }
            for i, a in enumerate(steps)
        ],
    }


# ---------------------------------------------------------------------------
# Sample report loaders
# ---------------------------------------------------------------------------

SAMPLES_DIR = PROJECT_ROOT / "samples" / "reports"

def _load_reports(filter_names: Optional[List[str]] = None) -> List[Tuple[str, str]]:
    """Return (name, text) pairs for sample reports."""
    reports = []

    # Plaintext APT29
    apt29_path = SAMPLES_DIR / "plaintext_threat_report.txt"
    if apt29_path.exists():
        reports.append(("apt29", apt29_path.read_text()))

    # Markdown Lazarus
    lazarus_path = SAMPLES_DIR / "markdown_threat_report.md"
    if lazarus_path.exists():
        reports.append(("lazarus", lazarus_path.read_text()))

    if filter_names:
        reports = [(n, t) for n, t in reports if n in filter_names]

    return reports


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Compare local vs cloud LLM extraction quality")
    parser.add_argument("--reports", nargs="*", default=None,
                        help="Report names to test (apt29, lazarus). Default: all")
    parser.add_argument("--local-base", default="http://192.168.1.210:1234/v1",
                        help="Local LLM API base URL")
    parser.add_argument("--local-model", default="google/gemma-4-26b-a4b",
                        help="Local model ID as reported by the server")
    parser.add_argument("--local-key", default="no-key",
                        help="API key for local server")
    parser.add_argument("--cloud-model", default=None,
                        help="Cloud model override (default: use env config)")
    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "eval" / "results"),
                        help="Directory for JSON results")
    parser.add_argument("--cloud-only", action="store_true",
                        help="Only run cloud model (for baseline)")
    parser.add_argument("--local-only", action="store_true",
                        help="Only run local model")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quiet noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("litellm").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    reports = _load_reports(args.reports)
    if not reports:
        print("No reports found. Check samples/reports/ directory.")
        return 1

    # Load the technique cache — required for revoked filtering and semantic dedup
    from bandjacks.services.technique_cache import technique_cache
    neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_pass = os.getenv("NEO4J_PASSWORD", "bandjacks-dev")
    try:
        count = technique_cache.load_from_neo4j(neo4j_uri, neo4j_user, neo4j_pass)
        print(f"  Loaded {count} techniques into cache")
    except Exception as e:
        print(f"  WARNING: Failed to load technique cache: {e}")

    # Resolve cloud model from environment if not overridden
    cloud_model = args.cloud_model
    if not cloud_model:
        ref_client = LLMClient()
        cloud_model = ref_client.model
    cloud_api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("OPENAI_API_KEY") or None

    local_model_litellm = f"openai/{args.local_model}"

    # Preflight: verify local model is reachable and responds
    if not args.cloud_only:
        print(f"\n  Preflight: testing local model at {args.local_base}...")
        try:
            import httpx
            resp = httpx.post(
                f"{args.local_base}/chat/completions",
                json={
                    "model": args.local_model,
                    "messages": [{"role": "user", "content": "Say OK"}],
                    "max_tokens": 5,
                },
                headers={"Authorization": f"Bearer {args.local_key}"},
                timeout=30,
            )
            resp.raise_for_status()
            body = resp.json()
            preflight_content = body["choices"][0]["message"]["content"]
            print(f"  Preflight OK: model responded with: {preflight_content!r}")
        except Exception as e:
            print(f"  ERROR: Local model preflight failed: {e}")
            print(f"  Check that LM Studio is serving at {args.local_base}")
            return 1

    print(f"\n{'#' * 80}")
    print(f"  MODEL COMPARISON — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"  Cloud:  {cloud_model}")
    print(f"  Local:  {local_model_litellm} @ {args.local_base}")
    print(f"  Reports: {[n for n, _ in reports]}")
    print(f"{'#' * 80}")

    comparisons: List[ComparisonResult] = []

    for report_name, report_text in reports:
        gt = GROUND_TRUTH.get(report_name, set())
        print(f"\n>>> Processing: {report_name} ({len(report_text)} chars, {len(gt)} ground-truth techniques)")

        cloud_result = ModelRunResult(model_label="cloud", model_id=cloud_model, report_name=report_name)
        local_result = ModelRunResult(model_label="local", model_id=local_model_litellm, report_name=report_name)

        if not args.local_only:
            print(f"\n  [Cloud] Running {cloud_model}...")
            cloud_result = _run_pipeline(
                report_text=report_text,
                report_name=report_name,
                model_label="cloud",
                model_id=cloud_model,
                api_key=cloud_api_key,
                config={"relevance_threshold": 0.20},
            )

        if not args.cloud_only:
            print(f"\n  [Local] Running {local_model_litellm}...")
            local_result = _run_pipeline(
                report_text=report_text,
                report_name=report_name,
                model_label="local",
                model_id=local_model_litellm,
                api_base=args.local_base,
                api_key=args.local_key,
                config={"relevance_threshold": 0.10},
            )

        comp = ComparisonResult(
            report_name=report_name,
            ground_truth_ids=gt,
            cloud=cloud_result,
            local=local_result,
        ).compute()
        comparisons.append(comp)
        _print_comparison(comp)

    # Summary across all reports
    if len(comparisons) > 1:
        print(f"\n{'=' * 80}")
        print(f"  AGGREGATE SUMMARY")
        print(f"{'=' * 80}")
        for label, accessor in [("Cloud", "cloud"), ("Local", "local")]:
            total_techs = sum(len(getattr(c, accessor).techniques) for c in comparisons)
            total_time = sum(getattr(c, accessor).duration_sec for c in comparisons)
            total_cost = sum(getattr(c, accessor).cost_usd for c in comparisons)
            avg_recall = sum(getattr(c, f"{accessor}_recall") for c in comparisons) / len(comparisons)
            avg_f1 = sum(getattr(c, f"{accessor}_f1") for c in comparisons) / len(comparisons)
            print(f"  {label:6s}: {total_techs} techniques, recall={_fmt_pct(avg_recall)}, "
                  f"F1={_fmt_pct(avg_f1)}, time={total_time:.1f}s, cost=${total_cost:.4f}")

    # Save results
    out_path = _save_results(comparisons, Path(args.output_dir))
    print(f"\nResults saved to: {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
