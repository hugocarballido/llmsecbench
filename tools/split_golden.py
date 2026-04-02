#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
split_golden.py
---------------
Split a labeled golden JSONL into DEV/TEST in a reproducible, stratified way.

Default behavior:
- Excludes rows with human_class == "E" and rows with missing/empty human_class
- Stratifies by human_class (A/B/C/D)
- Uses a fixed seed for reproducibility
- Ensures (when possible) at least 1 sample per stratum remains in DEV

Example:
  python tools/split_golden.py \
    --in golden_labeled.jsonl \
    --out-dev golden_dev.jsonl \
    --out-test golden_test.jsonl \
    --seed 1337 \
    --test-ratio 0.30 \
    --stratify human_class
"""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _get_field(row: Dict[str, Any], field: str) -> str:
    v = row.get(field, "")
    if v is None:
        return ""
    return str(v).strip()


def _make_group_key(row: Dict[str, Any], fields: List[str]) -> Tuple[str, ...]:
    return tuple(_get_field(row, f) for f in fields)


def stratified_split(
    rows: List[Dict[str, Any]],
    *,
    group_fields: List[str],
    test_ratio: float,
    seed: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Stratified split by `group_fields`.
    For each stratum of size n:
      - if n == 1 -> keep in DEV
      - else test_n = round(n * test_ratio), clamped to [1, n-1]
    """
    rng = random.Random(seed)
    buckets: Dict[Tuple[str, ...], List[Dict[str, Any]]] = defaultdict(list)

    for r in rows:
        buckets[_make_group_key(r, group_fields)].append(r)

    dev: List[Dict[str, Any]] = []
    test: List[Dict[str, Any]] = []

    for key, items in buckets.items():
        items = list(items)
        rng.shuffle(items)
        n = len(items)

        if n <= 1 or test_ratio <= 0.0:
            dev.extend(items)
            continue

        # round-based allocation, but keep at least 1 in each split when possible
        test_n = int(round(n * test_ratio))
        test_n = max(1, test_n)
        test_n = min(n - 1, test_n)

        test.extend(items[:test_n])
        dev.extend(items[test_n:])

    rng.shuffle(dev)
    rng.shuffle(test)
    return dev, test


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Input golden_labeled JSONL")
    ap.add_argument("--out-dev", required=True, help="Output DEV JSONL")
    ap.add_argument("--out-test", required=True, help="Output TEST JSONL")
    ap.add_argument("--seed", type=int, default=1337, help="Random seed")
    ap.add_argument("--test-ratio", type=float, default=0.30, help="Fraction assigned to TEST")
    ap.add_argument(
        "--stratify",
        type=str,
        default="human_class",
        help="Comma-separated fields for stratification (e.g., human_class or human_class,category)",
    )
    ap.add_argument(
        "--exclude-classes",
        type=str,
        default="E",
        help='Comma-separated human_class labels to exclude (default: "E")',
    )

    args = ap.parse_args()
    inp = Path(args.inp)
    out_dev = Path(args.out_dev)
    out_test = Path(args.out_test)

    group_fields = [s.strip() for s in args.stratify.split(",") if s.strip()]
    if not group_fields:
        group_fields = ["human_class"]

    excluded = {s.strip() for s in args.exclude_classes.split(",") if s.strip()}

    rows = read_jsonl(inp)

    # Filter: remove missing/empty human_class and excluded labels (E by default)
    kept: List[Dict[str, Any]] = []
    excluded_rows = 0
    missing_rows = 0

    for r in rows:
        hc = _get_field(r, "human_class")
        if not hc:
            missing_rows += 1
            continue
        if hc in excluded:
            excluded_rows += 1
            continue
        kept.append(r)

    dev, test = stratified_split(
        kept,
        group_fields=group_fields,
        test_ratio=float(args.test_ratio),
        seed=int(args.seed),
    )

    write_jsonl(out_dev, dev)
    write_jsonl(out_test, test)

    # Print summary
    def _count_by(field: str, rs: List[Dict[str, Any]]) -> Counter:
        return Counter(_get_field(x, field) for x in rs)

    print("=== split_golden summary ===")
    print(f"input_rows: {len(rows)}")
    print(f"kept_rows (A/B/C/D by default): {len(kept)}")
    print(f"excluded_rows (labels {sorted(excluded)}): {excluded_rows}")
    print(f"missing_human_class: {missing_rows}")
    print(f"dev_rows: {len(dev)}")
    print(f"test_rows: {len(test)}")
    print(f"seed: {args.seed}  test_ratio: {args.test_ratio}  stratify: {group_fields}")
    print("human_class distribution:")
    print(f"  DEV : {_count_by('human_class', dev)}")
    print(f"  TEST: {_count_by('human_class', test)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())