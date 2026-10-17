import re
import sys
from pathlib import Path

import yaml

RULES = {
    "docs/detections": ["title", "mitre", "data_source", "severity", "owner", "status"],
    "docs/sops": ["title", "owner", "last_reviewed"],
}
SEVERITIES = {"low", "medium", "high", "critical"}
STATUSES = {"draft", "testing", "production", "deprecated"}
MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")

errors = []

for folder, required in RULES.items():
    for path in sorted(Path(folder).glob("*.md")):
        if path.name == "index.md":
            continue
        text = path.read_text(encoding="utf-8")
        match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        if not match:
            errors.append(f"{path}: missing front matter block")
            continue
        try:
            meta = yaml.safe_load(match.group(1)) or {}
        except yaml.YAMLError as exc:
            errors.append(f"{path}: invalid YAML ({exc})")
            continue
        for key in required:
            if not meta.get(key):
                errors.append(f"{path}: missing '{key}'")
        if "severity" in required and meta.get("severity") and str(meta["severity"]).lower() not in SEVERITIES:
            errors.append(f"{path}: severity must be one of {sorted(SEVERITIES)}")
        if "status" in required and meta.get("status") and str(meta["status"]).lower() not in STATUSES:
            errors.append(f"{path}: status must be one of {sorted(STATUSES)}")
        if "mitre" in required and meta.get("mitre") and not MITRE.match(str(meta["mitre"])):
            errors.append(f"{path}: mitre '{meta['mitre']}' is not like T1110 or T1110.001")

if errors:
    print("Front matter check failed:")
    for e in errors:
        print(" -", e)
    sys.exit(1)

print("Front matter check passed")
