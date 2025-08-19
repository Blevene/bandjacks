from pathlib import Path
from bandjacks.loaders.parse_text import extract_text
import requests, json

pdf = Path("/Volumes/tank/bandjacks/samples/reports/TheWizards APT group uses SLAAC spoofing to perform adversary-in-the-middle attacks.pdf")
uri = pdf.as_uri()  # e.g., file:///Volumes/tank/bandjacks/samples/reports/...

txt = extract_text(source_type="pdf", content_url=uri)["text"]
payload = {
  "method": "agentic_v2",
  "content": txt,
  "title": "SLAAC AITM",
  "config": { "top_k": 5, "disable_discovery": False, "max_discovery_per_span": 1, "min_quotes": 2 }
}
print(requests.post("http://localhost:8000/v1/extract/runs", json=payload).json())