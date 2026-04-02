import json
from pathlib import Path
from llmsecbench.eval.scorers import score_conversation

def read_jsonl(p: Path):
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)

def write_jsonl(p: Path, rows):
    with p.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def rescore_results(input_results: Path, output_results: Path):
    out = []
    for r in read_jsonl(input_results):
        r["score"] = score_conversation(
            r.get("expected_policy", ""),
            r.get("assistant_outputs", []),
            attack_family=r.get("attack_family"),
        )
        out.append(r)
    write_jsonl(output_results, out)

def eval_binary_D_vs_not(results_path: Path, golden_labeled_path: Path):
    # index results by id
    res = {r["id"]: r for r in read_jsonl(results_path)}
    tp=fp=tn=fn=0
    excluded_E=excluded_missing=0

    for g in read_jsonl(golden_labeled_path):
        h = (g.get("human_class") or "").strip()
        if not h:
            excluded_missing += 1
            continue
        if h == "E":
            excluded_E += 1
            continue

        y = (h == "D")
        s = res[g["id"]]["score"]
        yhat = bool(s.get("summary", {}).get("compromised_any", False))

        if y and yhat: tp += 1
        elif (not y) and yhat: fp += 1
        elif (not y) and (not yhat): tn += 1
        else: fn += 1

    prec = tp/(tp+fp) if (tp+fp) else 0.0
    rec  = tp/(tp+fn) if (tp+fn) else 0.0
    f1   = (2*prec*rec/(prec+rec)) if (prec+rec) else 0.0
    acc  = (tp+tn)/(tp+tn+fp+fn)

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": prec, "recall": rec, "f1": f1, "accuracy": acc,
        "excluded_E": excluded_E, "excluded_missing": excluded_missing
    }

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Input results JSONL (outputs congelados)")
    ap.add_argument("--out", dest="out", required=True, help="Output rescored JSONL")
    ap.add_argument("--golden", dest="golden", default=None, help="Optional golden labeled JSONL for eval")
    args = ap.parse_args()

    inp = Path(args.inp)
    out = Path(args.out)
    rescore_results(inp, out)

    if args.golden:
        gold = Path(args.golden)
        print(eval_binary_D_vs_not(out, gold))
    else:
        print({"status": "rescored", "in": str(inp), "out": str(out)})