import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bandjacks.loaders.parse_text import extract_text
import requests, json

pdf_path = Path("/Volumes/tank/bandjacks/samples/reports/TheWizards APT group uses SLAAC spoofing to perform adversary-in-the-middle attacks.pdf")

# Read the PDF file directly
with open(pdf_path, 'rb') as f:
    pdf_content = f.read()

# Extract text from PDF bytes
txt = extract_text(source_type="pdf", inline_text=pdf_content)["text"]
payload = {
  "method": "agentic_v2",
  "content": txt,
  "title": "SLAAC AITM",
  "config": { "top_k": 5, "disable_discovery": False, "max_discovery_per_span": 1, "min_quotes": 2 }
}
print(requests.post("http://localhost:8000/v1/extract/runs", json=payload).json())