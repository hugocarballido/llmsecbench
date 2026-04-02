#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_labels.py
---------------
Merge human labels from a CSV file into a results JSONL.

The CSV must have at minimum an 'id' column and a 'human_class' column
(values: A / B / C / D / E). An optional 'human_rationale' column is also
supported.

Example:
  python tools/merge_labels.py \
    --results outputs/run_001/results.jsonl \
    --labels  data/labeling.csv \
    --out     golden/golden_labeled.jsonl
"""

import argparse
import csv
import json
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Merge human labels CSV into results JSONL.")
    ap.add_argument("--results", required=True, help="Input results JSONL (from runner)")
    ap.add_argument("--labels",  required=True, help="Input CSV with human labels")
    ap.add_argument("--out",     required=True, help="Output merged JSONL path")
    args = ap.parse_args()

    results_path = Path(args.results)
    labels_path  = Path(args.labels)
    out_path     = Path(args.out)

    # Load labels from CSV
    labels: dict = {}
    with labels_path.open("r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            _id = row.get("id", "").strip()
            if not _id:
                continue
            hc = row.get("human_class", "").strip().upper()
            labels[_id] = {
                "human_class": hc,
                "human_compromised": (hc == "D") if hc in {"A", "B", "C", "D"} else None,
                "human_rationale": row.get("human_rationale", "").strip(),
            }

    # Merge into results
    out_path.parent.mkdir(parents=True, exist_ok=True)
    merged = 0
    missing = 0

    with results_path.open("r", encoding="utf-8") as f_in, \
         out_path.open("w", encoding="utf-8") as f_out:
        for line in f_in:
            item = json.loads(line)
            ann = labels.get(item.get("id", ""))
            if ann:
                item.update(ann)
                merged += 1
            else:
                item.setdefault("human_class", "")
                item.setdefault("human_compromised", None)
                item.setdefault("human_rationale", "")
                missing += 1
            f_out.write(json.dumps(item, ensure_ascii=False) + "\n")

    print(f"OK → {out_path}  (merged={merged}, no_label={missing})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
