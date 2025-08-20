# Extraction Runs API Endpoints

The extraction runs endpoints start asynchronous extractions, expose live status, and return results when complete.

## POST /extract/runs

Start an async extraction run using the agentic v2 pipeline.

### Request

```http
POST /v1/extract/runs
Content-Type: application/json
```

```json
{
  "method": "agentic_v2",
  "content": "Report text or document content",
  "title": "Optional report title",
  "config": {
    "top_k": 5,
    "disable_discovery": true,
    "min_quotes": 2
  }
}
```

### Response

```json
{
  "run_id": "ex-27798222-d2ad-41a8-b879-666a6fcf33c6",
  "accepted": true
}
```

Notes:
- Provide plain text in `content`. For PDFs, extract text client-side before calling this endpoint.

## GET /extract/runs/{run_id}/status

Check the status and progress of a run.

### Request

```http
GET /v1/extract/runs/{run_id}/status
```

### Response

```json
{
  "run_id": "ex-27798222-d2ad-41a8-b879-666a6fcf33c6",
  "state": "running",
  "stage": "Mapper",
  "percent": 65,
  "spans_total": 38,
  "spans_processed": 22,
  "counters": {
    "llm_calls": 0,
    "candidates": 0,
    "verified_claims": 15,
    "techniques": 12,
    "spans_found": 38
  },
  "cost_usd": 0.0,
  "dur_sec": 486
}
```

## GET /extract/runs/{run_id}/result

Return the final extraction result with STIX bundle and metrics.

### Request

```http
GET /v1/extract/runs/{run_id}/result
```

### Response

```json
{
  "techniques": {
    "T1566.001": {
      "name": "Phishing: Spearphishing Attachment",
      "confidence": 95,
      "evidence": ["The attackers sent spearphishing emails..."],
      "line_refs": [15, 16],
      "tactic": "initial-access",
      "claim_count": 2
    }
  },
  "bundle": { "type": "bundle", "id": "bundle--...", "objects": [] },
  "flow": {},
  "metrics": {
    "run_id": "ex-27798222-d2ad-41a8-b879-666a6fcf33c6",
    "stage": "Completed",
    "percent": 100,
    "dur_sec": 512,
    "spans_total": 38,
    "spans_processed": 38
  }
}
```


