from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from dotenv import load_dotenv

from .runner import RunConfig, make_golden_set, run_benchmark
from .utils.io import write_json
from .utils.report import summarize_results
from .models.openai_api import OpenAIClient
from .models.ollama_local import OllamaClient


def _make_client(model: str):
    if model.startswith("ollama:"):
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        return OllamaClient(model=model.replace("ollama:", "", 1), host=host)
    return OpenAIClient(model=model)


# ── subcommand: run ──────────────────────────────────────────────────────────

def cmd_run(args):
    load_dotenv()
    client = _make_client(args.model)
    cfg = RunConfig(
        model=args.model,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        limit=args.limit,
        anti_contracts=False,
    )
    summary = run_benchmark(args.dataset, client, cfg, output_path=args.out)
    write_json(args.out.replace(".jsonl", ".summary.json"), summary)

    report_path = args.out.replace(".jsonl", ".report.json")
    summarize_results(args.out, out_json=report_path)

    print(f"Done. Wrote {args.out}")
    print(f"Wrote {report_path}")


def add_run_parser(sub):
    p = sub.add_parser("run", help="Run the benchmark against a dataset.")
    p.add_argument("--dataset",     required=True,  help="Path to dataset JSONL")
    p.add_argument("--model",       required=True,  help="Model name (e.g. gpt-4.1-mini or ollama:llama3)")
    p.add_argument("--out",         default="results.jsonl", help="Output JSONL path")
    p.add_argument("--max-tokens",  type=int,   default=256,  dest="max_tokens",  help="Max completion tokens")
    p.add_argument("--temperature", type=float, default=0.0,                      help="Sampling temperature")
    p.add_argument("--limit",       type=int,   default=None,                     help="Limit number of tests")
    p.set_defaults(func=cmd_run)


# ── subcommand: make-golden ──────────────────────────────────────────────────

def cmd_make_golden(args):
    load_dotenv()
    client = _make_client(args.model)
    cfg = RunConfig(
        model=args.model,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        anti_contracts=False,
    )
    summary = make_golden_set(
        args.dataset, client, cfg,
        out_path=args.out,
        sample_size=args.sample_size,
        seed=args.seed,
    )
    write_json(args.out.replace(".jsonl", ".summary.json"), summary)
    print(f"Done. Wrote {args.out}")
    print("(label human_class=A/B/C/D/E and human_compromised before split_golden)")


def add_make_golden_parser(sub):
    p = sub.add_parser("make-golden", help="Generate a golden set for human labeling.")
    p.add_argument("--dataset",     required=True,  help="Path to dataset JSONL")
    p.add_argument("--model",       required=True,  help="Reference model (e.g. gpt-4.1-mini)")
    p.add_argument("--out",         default="golden_set.jsonl", help="Output JSONL path")
    p.add_argument("--sample-size", type=int,   default=100,  dest="sample_size", help="Number of samples")
    p.add_argument("--seed",        type=int,   default=1337,                     help="Random seed")
    p.add_argument("--max-tokens",  type=int,   default=256,  dest="max_tokens",  help="Max completion tokens")
    p.add_argument("--temperature", type=float, default=0.0,                      help="Sampling temperature")
    p.set_defaults(func=cmd_make_golden)


# ── subcommand: report ───────────────────────────────────────────────────────

def cmd_report(args):
    rep = summarize_results(args.results, out_json=args.out, golden_path=args.golden)
    print(f"Wrote {args.out} (n={rep.get('n')})")


def add_report_parser(sub):
    p = sub.add_parser("report", help="Generate an aggregated report from results.")
    p.add_argument("--results", required=True, help="Path to results JSONL")
    p.add_argument("--out",     default="report.json", help="Output report JSON path")
    p.add_argument("--golden",  default=None, help="Optional golden JSONL (to diff by id)")
    p.set_defaults(func=cmd_report)

# ── subcommand: rescore ──────────────────────────────────────────────────────

def cmd_rescore(args):
    from pathlib import Path
    from tools.rescore_jsonl import rescore_results, eval_binary_D_vs_not

    inp = Path(args.inp)
    out = Path(args.out)
    rescore_results(inp, out)
    print(f"Done. Rescored {inp} → {out}")

    if args.golden:
        gold = Path(args.golden)
        metrics = eval_binary_D_vs_not(out, gold)
        print(metrics)


def add_rescore_parser(sub):
    p = sub.add_parser("rescore", help="Rescore existing results JSONL without re-running inference.")
    p.add_argument("--in",     dest="inp",    required=True, help="Input results JSONL")
    p.add_argument("--out",    dest="out",    required=True, help="Output rescored JSONL")
    p.add_argument("--golden", dest="golden", default=None,  help="Optional golden labeled JSONL for eval metrics")
    p.set_defaults(func=cmd_rescore)


# ── subcommand: report-pdf ───────────────────────────────────────────────────

def cmd_report_pdf(args):
    from pathlib import Path
    from tools.report_pdf import build_report

    build_report(
        Path(args.inp), Path(args.out),
        dataset_name=args.dataset,
        show_compromised_excerpts=args.show_compromised_excerpts,
    )
    print(f"Done. Report written → {args.out}")


def add_report_pdf_parser(sub):
    p = sub.add_parser("report-pdf", help="Generate a PDF report from scored results JSONL.")
    p.add_argument("--in",      dest="inp",     required=True,  help="Input scored JSONL")
    p.add_argument("--out",     dest="out",     required=True,  help="Output PDF path")
    p.add_argument("--dataset", dest="dataset", default="(unspecified)", help="Dataset name shown in the report")
    p.add_argument("--show-compromised-excerpts", action="store_true",
                   help="Include raw compromised output excerpts in the report (disabled by default)")
    p.set_defaults(func=cmd_report_pdf)


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="llmsecbench",
        description="Unified security benchmark for LLMs.",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    add_run_parser(sub)
    add_make_golden_parser(sub)
    add_report_parser(sub)
    add_rescore_parser(sub)  
    add_report_pdf_parser(sub)  

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()