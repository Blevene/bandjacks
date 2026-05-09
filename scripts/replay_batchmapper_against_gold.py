#!/usr/bin/env python3
"""Replay BatchMapperAgent diagnostic captures and report patch impact.

Two modes:

1. **Revoked-emission count (default)** — pure measurement, no gold needed.
   Reads `captured_calls.jsonl`, counts how many (span_id, tid) pairs
   the cloud emitted are revoked/deprecated according to a supplied
   revoked-TID list. This reproduces the diagnostic's headline number
   (162 revoked emissions across 195 BatchMapperAgent calls).

2. **F1 vs gold (--gold-md mode)** — parses the human-graded `.md`
   sibling files in
   `/Users/blove/Documents/Code/gemma_4_tid/__archive/data/bandjacks_diagnostic/labeling/`
   to extract `[y]` / `[n]` markings, then computes precision/recall/F1
   for the captured cloud predictions. Pass --strip-revoked to simulate
   the patch effect (cloud_raw 0.613 → cloud_clean 0.627 in the
   diagnostic's source_comparison.json).

Usage:
  uv run python scripts/replay_batchmapper_against_gold.py \\
      --captured /Users/.../captured_calls.jsonl \\
      --revoked  /Users/.../revoked_tids.json \\
      [--gold-md /Users/.../auto_v3_spans_labeled.md] \\
      [--strip-revoked] \\
      --out      data/replay_metrics.json

The --revoked file is a JSON array of strings, e.g. `["T1128", "T1024", ...]`.
Generate it from a running bandjacks via:
    from bandjacks.services.technique_cache import technique_cache
    json.dump(sorted(technique_cache.revoked_ids()), open("revoked_tids.json","w"))
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
GOLD_LINE = re.compile(r"^- \[(?P<grade>[yn?])\] `(?P<tid>T\d{4}(?:\.\d{3})?)`")
SPAN_HEADER = re.compile(r"^## Span \d+ — call_ordinal=(?P<co>\d+), span_id=(?P<sid>\d+)")
ADDITIONAL = re.compile(r"^\*\*Additional correct TIDs:\*\* (?P<rest>.+)$")


def load_jsonl(path: Path):
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def _strip_fences(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    return s


def extract_predicted_pairs(captured_rows):
    """Yield (call_ordinal, span_id, tid) tuples from captured BatchMapper responses."""
    for row in captured_rows:
        if row.get("call_type") != "BatchMapperAgent":
            continue
        ordinal = row.get("call_ordinal")
        try:
            content = row["response_body"]["choices"][0]["message"]["content"]
            parsed = json.loads(_strip_fences(content))
        except (KeyError, IndexError, TypeError, json.JSONDecodeError):
            continue
        for item in parsed.get("techniques", []):
            yield ordinal, item.get("span"), item.get("tid")


def parse_gold_md(path: Path):
    """Yield (call_ordinal, span_id, tid) for every TID graded `[y]` or
    listed under 'Additional correct TIDs' in the .md."""
    cur_co = None
    cur_sid = None
    for raw in path.read_text().splitlines():
        m = SPAN_HEADER.match(raw)
        if m:
            cur_co = int(m.group("co"))
            cur_sid = int(m.group("sid"))
            continue
        m = GOLD_LINE.match(raw)
        if m and m.group("grade") == "y" and cur_co is not None and cur_sid is not None:
            yield cur_co, cur_sid, m.group("tid")
            continue
        m = ADDITIONAL.match(raw)
        if m and cur_co is not None and cur_sid is not None:
            for tid in TID_RE.findall(m.group("rest")):
                yield cur_co, cur_sid, tid


def score(pred_pairs, gold_pairs):
    p, g = set(pred_pairs), set(gold_pairs)
    tp = len(p & g)
    fp = len(p - g)
    fn = len(g - p)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--captured", required=True, type=Path,
                    help="Path to captured_calls.jsonl from the diagnostic")
    ap.add_argument("--revoked", required=True, type=Path,
                    help="JSON file containing array of revoked TID strings")
    ap.add_argument("--gold-md", type=Path, nargs="*", default=None,
                    help="Optional path(s) to labeled .md file(s). If supplied, "
                         "computes precision/recall/F1 against [y] gradings. "
                         "Pass multiple to combine gold sets (e.g., auto_v2 + auto_v3). "
                         "Predictions are filtered to spans covered by the gold to "
                         "avoid penalizing the model for spans outside the labeled set.")
    ap.add_argument("--strip-revoked", action="store_true",
                    help="Simulate post-patch behavior by dropping revoked "
                         "TIDs from predictions before scoring/counting.")
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    revoked_set = set(json.loads(args.revoked.read_text()))

    pred = list(extract_predicted_pairs(load_jsonl(args.captured)))
    pred_total = len(pred)
    pred_revoked = [(co, sid, tid) for co, sid, tid in pred if tid in revoked_set]

    if args.strip_revoked:
        pred_for_scoring = [t for t in pred if t[2] not in revoked_set]
    else:
        pred_for_scoring = pred

    out = {
        "captured_jsonl": str(args.captured),
        "revoked_tids_supplied": len(revoked_set),
        "predictions_total": pred_total,
        "predictions_revoked": len(pred_revoked),
        "predictions_after_strip": len(pred_for_scoring),
        "strip_revoked": args.strip_revoked,
        "top_revoked_emitted": _top_n(pred_revoked, key=lambda t: t[2], n=10),
    }

    if args.gold_md:
        gold = []
        for md in args.gold_md:
            gold.extend(parse_gold_md(md))
        # Filter predictions to spans the gold actually covers — otherwise
        # predictions for unlabeled spans inflate FP.
        gold_spans = {(co, sid) for co, sid, _ in gold}
        pred_in_gold_scope = [
            (co, sid, tid) for co, sid, tid in pred_for_scoring
            if (co, sid) in gold_spans
        ]
        out["gold_md"] = [str(p) for p in args.gold_md]
        out["gold_pairs"] = len(gold)
        out["gold_spans_covered"] = len(gold_spans)
        out["predictions_in_gold_scope"] = len(pred_in_gold_scope)
        out["scores"] = score(pred_in_gold_scope, gold)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


def _top_n(items, *, key, n):
    from collections import Counter
    c = Counter(key(item) for item in items)
    return c.most_common(n)


if __name__ == "__main__":
    main()
