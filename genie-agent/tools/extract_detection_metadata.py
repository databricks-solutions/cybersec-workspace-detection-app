"""Extract detection metadata from the base/ notebooks into one JSON catalog.

The Genie Agent surface is GENERATED from the existing detections rather than
hand-maintained beside them. Every notebook in ``base/detections/`` already
carries a structured ``dscc`` YAML block (name, objective, MITRE taxonomy,
severity, fidelity, false_positives, required columns) -- that block is the
single source of truth, so the agent's instructions, its function COMMENTs and
its detection catalog view all derive from it.

Why generated and not written by hand: a hand-kept copy of 34 detections'
metadata drifts the first time someone edits a notebook's severity or adds a
MITRE tag. Re-running this script is the whole update path.

    python genie-agent/tools/extract_detection_metadata.py \
        --repo-root . --out genie-agent/agent/detection_catalog.json

Stdlib + PyYAML only (PyYAML ships in Databricks Runtime).

NOT a transpiler. This extracts METADATA, not query logic. The PySpark bodies
are ported to SQL by hand under ``genie-agent/functions/`` because the
translation needs judgement per detection -- see genie-agent/docs/PORTING.md.
This script's job is to tell you what must be ported and to keep every
descriptive field in sync once it is.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML required: pip install pyyaml")

#: The notebooks embed their YAML inside a ``%md`` cell, so every line carries a
#: ``# MAGIC `` prefix. Captured non-greedily between the fenced markers.
_YAML_BLOCK = re.compile(r"# MAGIC ```yaml\n(.*?)# MAGIC ```", re.S)

#: ``@detect``-decorated entry point. The function name is the detection's
#: callable identity and becomes the generated SQL function's name.
_DETECT_FN = re.compile(r"@detect\([^)]*\)\s*\ndef\s+(\w+)\s*\(", re.S)

#: Tables the detection reads. Drives the "which system tables must the customer
#: grant SELECT on" section of the install docs -- getting that list wrong is a
#: silent permission failure at query time, not a deploy error.
_SPARK_TABLE = re.compile(r'spark\.table\(\s*["\']([^"\']+)["\']\s*\)')


def _strip_magic(block: str) -> str:
    """Remove the ``# MAGIC`` notebook prefix from each line of *block*.

    Handles both ``# MAGIC content`` and a bare ``# MAGIC`` (blank line inside
    the block); replacing only the first occurrence per line keeps any literal
    ``# MAGIC`` appearing later in a description intact.
    """
    out: List[str] = []
    for line in block.split("\n"):
        if line.startswith("# MAGIC "):
            out.append(line[len("# MAGIC ") :])
        elif line.startswith("# MAGIC"):
            out.append(line[len("# MAGIC") :])
        else:
            out.append(line)
    return "\n".join(out)


def _clean_prose(text: Optional[str]) -> str:
    """Collapse a notebook YAML prose field into one clean line.

    These fields are folded YAML scalars written inside a ``%md`` cell, so they
    arrive with hard line breaks and -- in a few notebooks -- a stray literal
    ``# MAGIC`` that the authoring template left behind. Both would end up
    inside a generated SQL ``COMMENT``, which is exactly the text Genie reads to
    choose a function, so it is worth normalising here.
    """
    if not text:
        return ""
    t = text.replace("# MAGIC", " ")
    return re.sub(r"\s+", " ", t).strip()


def _parse_notebook(path: Path, repo_root: Path) -> Optional[Dict[str, Any]]:
    """Parse one detection notebook into a catalog record, or ``None``.

    Returns ``None`` (with a warning) rather than raising: one malformed
    notebook should not abort extraction of the other 33. The caller counts
    skips and exits non-zero, so a regression still fails CI.
    """
    text = path.read_text(encoding="utf-8")

    block = _YAML_BLOCK.search(text)
    if not block:
        print(f"  WARN no yaml block: {path.name}", file=sys.stderr)
        return None

    try:
        doc = yaml.safe_load(_strip_magic(block.group(1)))
    except yaml.YAMLError as exc:
        print(f"  WARN yaml parse failed: {path.name}: {exc}", file=sys.stderr)
        return None

    dscc = (doc or {}).get("dscc") or {}
    det = dscc.get("detection") or {}
    if not det.get("name"):
        print(f"  WARN no detection.name: {path.name}", file=sys.stderr)
        return None

    fn_match = _DETECT_FN.search(text)
    tables = sorted(set(_SPARK_TABLE.findall(text)))

    # Notebooks live in base/detections/<category>/<file>.py
    category = path.parent.name

    return {
        "name": det["name"],
        "function_name": fn_match.group(1) if fn_match else path.stem,
        "sql_function_name": f"detect_{fn_match.group(1) if fn_match else path.stem}",
        "source_notebook": str(path.relative_to(repo_root)),
        "category": category,
        "description": _clean_prose(det.get("description")),
        "objective": _clean_prose(det.get("objective")),
        "severity": det.get("severity", "unknown"),
        "fidelity": det.get("fidelity", "unknown"),
        "taxonomy": det.get("taxonomy") or [],
        "false_positives": _clean_prose(det.get("false_positives")),
        "source_tables": tables,
        "uuid": dscc.get("uuid", ""),
        "author": dscc.get("author", ""),
    }


def extract(repo_root: Path) -> Dict[str, Any]:
    """Build the full catalog from every notebook under ``base/detections``."""
    det_dir = repo_root / "base" / "detections"
    if not det_dir.is_dir():
        sys.exit(f"not a detection repo: {det_dir} missing")

    records: List[Dict[str, Any]] = []
    skipped = 0
    for path in sorted(det_dir.rglob("*.py")):
        rec = _parse_notebook(path, repo_root)
        if rec is None:
            skipped += 1
        else:
            records.append(rec)

    records.sort(key=lambda r: (r["category"], r["name"]))

    by_cat: Dict[str, int] = {}
    by_sev: Dict[str, int] = {}
    tables: set[str] = set()
    for r in records:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        tables.update(r["source_tables"])

    return {
        "detections": records,
        "summary": {
            "total": len(records),
            "skipped": skipped,
            "by_category": dict(sorted(by_cat.items())),
            "by_severity": dict(sorted(by_sev.items())),
            "source_tables": sorted(tables),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo-root", default=".", type=Path)
    ap.add_argument("--out", type=Path, help="write JSON here (default: stdout)")
    args = ap.parse_args()

    catalog = extract(args.repo_root.resolve())
    payload = json.dumps(catalog, indent=2) + "\n"

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
        s = catalog["summary"]
        print(f"wrote {args.out}")
        print(f"  detections : {s['total']} (skipped {s['skipped']})")
        print(f"  categories : {s['by_category']}")
        print(f"  severity   : {s['by_severity']}")
        print(f"  tables     : {s['source_tables']}")
    else:
        sys.stdout.write(payload)

    # A skipped notebook means the agent surface silently under-covers the
    # detection set -- fail so CI catches it.
    return 1 if catalog["summary"]["skipped"] else 0


if __name__ == "__main__":
    sys.exit(main())
