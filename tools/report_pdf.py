#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
report_pdf_pro.py
-----------------
Professional PDF report generator for LLMSecBench scored JSONL results.

Usage:
  python report_pdf_pro.py --in results_scored.jsonl --out report.pdf --dataset eval_mix_v2

Dependencies:
  pip install reportlab matplotlib numpy
"""

from __future__ import annotations

import argparse
import json
import io
from pathlib import Path
from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import numpy as np

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ──────────────────────────────────────────────
# Design tokens
# ──────────────────────────────────────────────
P = {
    # Brand
    "ink":       "#0D0D0D",
    "purple":    "#5B2D8E",
    "purple_lt": "#7B4DB5",
    "purple_bg": "#F3EEF9",
    "purple_mid":"#D0B8EE",
    # Status
    "red":       "#D63031",
    "red_lt":    "#FDECEA",
    "amber":     "#E17055",
    "amber_lt":  "#FFF3EE",
    "green":     "#00B894",
    "green_lt":  "#E6FAF6",
    "blue":      "#0984E3",
    "blue_lt":   "#E8F4FD",
    # Neutrals
    "grey_1":    "#F8F8F8",
    "grey_2":    "#EEEEEE",
    "grey_3":    "#BBBBBB",
    "grey_4":    "#888888",
    "grey_5":    "#444444",
    "white":     "#FFFFFF",
}

W, H = A4  # 595.27 x 841.89 pt
MARGIN_H = 2.0 * cm
MARGIN_V = 1.8 * cm
CONTENT_W = W - 2 * MARGIN_H

def hx(h: str) -> colors.HexColor:
    return colors.HexColor(h)

def esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

# ──────────────────────────────────────────────
# Data helpers
# ──────────────────────────────────────────────
def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

def _score(r):  return r.get("score") or {}
def _summary(r): return (_score(r).get("summary") or {})
def _bool(x):   return bool(x) if x is not None else False

def agg_group(items: List[Dict[str, Any]]) -> Dict[str, int]:
    total = len(items)
    compromised = sum(1 for x in items if _bool(_summary(x).get("compromised_any")))
    success = sum(1 for x in items if _bool(_score(x).get("success")))
    unexpected_refusal = sum(
        1 for x in items
        if (str(x.get("expected_policy", "")).strip().lower() == "answer"
            and _bool(_summary(x).get("refusal_any"))
            and not _bool(_summary(x).get("compromised_any")))
    )
    return {"total": total, "compromised": compromised,
            "success": success, "unexpected_refusal": unexpected_refusal}

# ──────────────────────────────────────────────
# Chart factory — returns PNG bytes via BytesIO
# ──────────────────────────────────────────────
def _fig_to_bytes(fig) -> bytes:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=220, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return buf.read()

def _apply_spine_style(ax, show_grid=True, grid_axis="y"):
    ax.set_facecolor(P["grey_1"])
    for sp in ["top", "right"]:
        ax.spines[sp].set_visible(False)
    ax.spines["left"].set_color(P["grey_3"])
    ax.spines["bottom"].set_color(P["grey_3"])
    ax.tick_params(colors=P["grey_5"], labelsize=8)
    ax.xaxis.label.set_color(P["grey_5"])
    ax.yaxis.label.set_color(P["grey_5"])
    if show_grid:
        ax.grid(axis=grid_axis, color=P["grey_2"], linewidth=0.8, zorder=0)


def chart_summary_scorecard(comp_rate, succ_rate, unexp_count, n_total) -> bytes:
    """Horizontal KPI bar — three metrics side by side."""
    fig, axes = plt.subplots(1, 3, figsize=(11, 2.2), facecolor=P["white"])
    fig.subplots_adjust(wspace=0.05)

    specs = [
        ("Compromise rate",  f"{comp_rate:.2f}%",
         P["red"] if comp_rate > 5 else P["green"], P["red_lt"] if comp_rate > 5 else P["green_lt"]),
        ("Policy success",   f"{succ_rate:.1f}%",
         P["green"] if succ_rate >= 95 else P["amber"], P["green_lt"] if succ_rate >= 95 else P["amber_lt"]),
        ("Unexpected refusals", str(int(unexp_count)),
         P["amber"] if unexp_count > 0 else P["green"], P["amber_lt"] if unexp_count > 0 else P["green_lt"]),
    ]
    for ax, (label, val, fg, bg) in zip(axes, specs):
        ax.set_facecolor(bg)
        ax.set_xlim(0, 1); ax.set_ylim(0, 1)
        for sp in ax.spines.values():
            sp.set_edgecolor(fg); sp.set_linewidth(1.5)
        ax.set_xticks([]); ax.set_yticks([])
        ax.text(0.5, 0.62, val, ha="center", va="center",
                fontsize=26, fontweight="bold", color=fg, transform=ax.transAxes)
        ax.text(0.5, 0.22, label, ha="center", va="center",
                fontsize=9, color=P["grey_5"], transform=ax.transAxes)
    return _fig_to_bytes(fig)


def chart_response_donut(resp_types: Counter) -> bytes:
    order  = ["refusal", "educational", "deflection", "actionable", "other"]
    clrmap = {
        "refusal":     P["green"],
        "educational": P["blue"],
        "deflection":  P["purple_lt"],
        "actionable":  P["red"],
        "other":       P["grey_3"],
    }
    labels = [k for k in order if k in resp_types] + [k for k in resp_types if k not in order]
    values = [resp_types[k] for k in labels]
    clrs   = [clrmap.get(k, P["grey_3"]) for k in labels]

    fig, ax = plt.subplots(figsize=(5.5, 3.8), facecolor=P["white"])
    wedges, texts, autotexts = ax.pie(
        values, labels=None, colors=clrs,
        autopct=lambda p: f"{p:.1f}%" if p > 3 else "",
        pctdistance=0.78,
        startangle=90,
        wedgeprops=dict(width=0.52, edgecolor=P["white"], linewidth=2),
    )
    for at in autotexts:
        at.set_fontsize(7.5); at.set_color(P["white"]); at.set_fontweight("bold")

    total = sum(values)
    ax.text(0, 0, str(total), ha="center", va="center",
            fontsize=20, fontweight="bold", color=P["ink"])
    ax.text(0, -0.18, "responses", ha="center", va="center",
            fontsize=8, color=P["grey_4"])

    handles = [mpatches.Patch(color=clrmap.get(l, P["grey_3"]), label=f"{l}  ({resp_types.get(l,0)})")
               for l in labels]
    ax.legend(handles=handles, loc="center left", bbox_to_anchor=(0.95, 0.5),
              frameon=False, fontsize=8.5, labelcolor=P["grey_5"])
    ax.set_title("Response type distribution", fontsize=10, fontweight="bold",
                 color=P["ink"], pad=10)
    return _fig_to_bytes(fig)


def chart_compromise_by_category(cat_stats: Dict[str, Dict]) -> bytes:
    cats  = sorted(cat_stats.keys())
    rates = [(cat_stats[c]["compromised"] / cat_stats[c]["total"] * 100
              if cat_stats[c]["total"] else 0.0) for c in cats]
    cnts  = [cat_stats[c]["compromised"] for c in cats]

    fig, ax = plt.subplots(figsize=(8, 3.2), facecolor=P["white"])
    _apply_spine_style(ax)
    bar_colors = [P["red"] if r > 0 else P["grey_3"] for r in rates]
    bars = ax.bar(cats, rates, color=bar_colors, width=0.55,
                  edgecolor=P["white"], linewidth=1.2, zorder=3)

    for bar, cnt, rate in zip(bars, cnts, rates):
        if cnt > 0:
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.4,
                    f"{cnt}", ha="center", va="bottom",
                    fontsize=8, fontweight="bold", color=P["red"])

    ax.set_ylabel("Compromise rate (%)", fontsize=8.5)
    ax.set_ylim(0, max(1, max(rates) * 1.35) if rates else 5)
    ax.set_xticks(range(len(cats)))
    ax.set_xticklabels([c.replace("_", "\n") for c in cats], fontsize=8)
    ax.set_title("Compromise rate by category", fontsize=10, fontweight="bold",
                 color=P["ink"], pad=8)
    fig.tight_layout()
    return _fig_to_bytes(fig)


def chart_unexpected_refusal_by_category(cat_stats: Dict[str, Dict]) -> bytes:
    cats  = sorted(cat_stats.keys())
    rates = [(cat_stats[c]["unexpected_refusal"] / cat_stats[c]["total"] * 100
              if cat_stats[c]["total"] else 0.0) for c in cats]
    cnts  = [cat_stats[c]["unexpected_refusal"] for c in cats]

    fig, ax = plt.subplots(figsize=(8, 3.2), facecolor=P["white"])
    _apply_spine_style(ax)
    bar_colors = [P["amber"] if r > 0 else P["grey_3"] for r in rates]
    bars = ax.bar(cats, rates, color=bar_colors, width=0.55,
                  edgecolor=P["white"], linewidth=1.2, zorder=3)

    for bar, cnt in zip(bars, cnts):
        if cnt > 0:
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.4,
                    f"{cnt}", ha="center", va="bottom",
                    fontsize=8, fontweight="bold", color=P["amber"])

    ax.set_ylabel("Unexpected refusal rate (%)", fontsize=8.5)
    ax.set_ylim(0, max(1, max(rates) * 1.35) if rates else 5)
    ax.set_xticks(range(len(cats)))
    ax.set_xticklabels([c.replace("_", "\n") for c in cats], fontsize=8)
    ax.set_title("Unexpected refusal rate by category  (expected_policy = answer)",
                 fontsize=10, fontweight="bold", color=P["ink"], pad=8)
    fig.tight_layout()
    return _fig_to_bytes(fig)


def chart_attack_family_heatmap(fam_stats: Dict[str, Dict]) -> bytes:
    """Sorted horizontal bar — top 12 attack families by volume."""
    fam_sorted = sorted(fam_stats.items(), key=lambda kv: kv[1]["total"], reverse=True)[:12]
    names  = [f[0] or "(none)" for f in fam_sorted]
    totals = [f[1]["total"]      for f in fam_sorted]
    comps  = [f[1]["compromised"] for f in fam_sorted]
    succs  = [f[1]["success"]    for f in fam_sorted]

    y = np.arange(len(names))
    fig, ax = plt.subplots(figsize=(8, max(3, len(names) * 0.45 + 0.8)), facecolor=P["white"])
    _apply_spine_style(ax, grid_axis="x")

    ax.barh(y, totals, height=0.55, color=P["purple_mid"], zorder=3, label="Total")
    ax.barh(y, succs,  height=0.55, color=P["green"],      zorder=4, label="Policy success")
    ax.barh(y, comps,  height=0.55, color=P["red"],        zorder=5, label="Compromised")

    for i, (t, s, c) in enumerate(zip(totals, succs, comps)):
        ax.text(t + 0.1, i, str(t), va="center", fontsize=7.5, color=P["grey_5"])

    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("Count", fontsize=8.5)
    ax.set_title("Attack family breakdown (top 12 by volume)",
                 fontsize=10, fontweight="bold", color=P["ink"], pad=8)
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    fig.tight_layout()
    return _fig_to_bytes(fig)


# ──────────────────────────────────────────────
# Styles
# ──────────────────────────────────────────────
def make_styles():
    base = getSampleStyleSheet()
    add  = {}

    def s(name, parent="Normal", **kw):
        add[name] = ParagraphStyle(name=name, parent=base[parent], **kw)

    s("ReportTitle",
      fontSize=26, leading=32, spaceAfter=4, spaceBefore=0,
      textColor=hx(P["white"]), fontName="Helvetica-Bold", alignment=TA_LEFT)

    s("ReportSubtitle",
      fontSize=11, leading=15, spaceAfter=2,
      textColor=hx(P["purple_mid"]), fontName="Helvetica", alignment=TA_LEFT)

    s("H1",
      fontSize=13, leading=17, spaceBefore=14, spaceAfter=4,
      textColor=hx(P["purple"]), fontName="Helvetica-Bold")

    s("H2",
      fontSize=10.5, leading=14, spaceBefore=10, spaceAfter=3,
      textColor=hx(P["purple"]), fontName="Helvetica-Bold")

    s("Body",
      fontSize=9, leading=13, spaceAfter=4,
      textColor=hx(P["grey_5"]), fontName="Helvetica")

    s("BodySmall",
      fontSize=8, leading=11, spaceAfter=3,
      textColor=hx(P["grey_4"]), fontName="Helvetica")

    s("Meta",
      fontSize=8.5, leading=11, spaceAfter=2,
      textColor=hx(P["grey_4"]), fontName="Helvetica")

    s("Badge",
      fontSize=8, leading=10,
      textColor=hx(P["white"]), fontName="Helvetica-Bold", alignment=TA_CENTER)

    s("FlagID",
      fontSize=9.5, leading=12, spaceBefore=8, spaceAfter=2,
      textColor=hx(P["ink"]), fontName="Helvetica-Bold")

    for name, st in add.items():
        base.add(st)
    return base


# ──────────────────────────────────────────────
# Page template callbacks
# ──────────────────────────────────────────────
def _make_header_footer(model: str, dataset: str, scorer: str):
    def draw(canv: canvas.Canvas, doc):
        canv.saveState()
        # Header bar
        canv.setFillColor(hx(P["purple"]))
        canv.rect(0, H - 0.9 * cm, W, 0.9 * cm, fill=1, stroke=0)
        # Thin accent stripe
        canv.setFillColor(hx(P["purple_lt"]))
        canv.rect(0, H - 0.9 * cm, 0.4 * cm, 0.9 * cm, fill=1, stroke=0)

        canv.setFillColor(hx(P["white"]))
        canv.setFont("Helvetica-Bold", 9)
        canv.drawString(MARGIN_H, H - 0.6 * cm, "LLMSecBench — Evaluation Report")
        canv.setFont("Helvetica", 8.5)
        canv.drawRightString(W - MARGIN_H, H - 0.6 * cm,
                             f"{dataset}  ·  {model}")

        # Footer line
        canv.setStrokeColor(hx(P["grey_2"]))
        canv.setLineWidth(0.5)
        canv.line(MARGIN_H, 1.3 * cm, W - MARGIN_H, 1.3 * cm)

        canv.setFillColor(hx(P["grey_4"]))
        canv.setFont("Helvetica", 7.5)
        canv.drawString(MARGIN_H, 0.7 * cm, f"Scorer: {scorer}")
        canv.drawRightString(W - MARGIN_H, 0.7 * cm,
                             f"Page {canv.getPageNumber()}")
        canv.restoreState()
    return draw


def _cover_page(canv: canvas.Canvas, doc):
    canv.saveState()
    # Deep purple banner
    canv.setFillColor(hx(P["purple"]))
    canv.rect(0, H * 0.60, W, H * 0.40, fill=1, stroke=0)
    # Decorative stripe
    canv.setFillColor(hx(P["purple_lt"]))
    canv.rect(0, H * 0.60 - 0.35 * cm, W, 0.35 * cm, fill=1, stroke=0)
    # Title
    canv.setFont("Helvetica-Bold", 28)
    canv.setFillColor(hx(P["white"]))
    canv.drawString(MARGIN_H, H * 0.82, "LLMSecBench")
    canv.setFont("Helvetica", 18)
    canv.setFillColor(hx(P["purple_mid"]))
    canv.drawString(MARGIN_H, H * 0.76, "Security Evaluation Report")
    canv.restoreState()


# ──────────────────────────────────────────────
# Table style helpers
# ──────────────────────────────────────────────
def _header_table_style(col_count):
    return TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  hx(P["purple"])),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  hx(P["white"])),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0),  8),
        ("BOTTOMPADDING",(0, 0), (-1, 0),  6),
        ("TOPPADDING",   (0, 0), (-1, 0),  6),
        # Body
        ("FONTSIZE",     (0, 1), (-1, -1), 8.5),
        ("FONTNAME",     (0, 1), (-1, -1), "Helvetica"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [hx(P["grey_1"]), hx(P["white"])]),
        ("TEXTCOLOR",    (0, 1), (-1, -1), hx(P["grey_5"])),
        ("ALIGN",        (1, 1), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 1), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 1), (-1, -1), 5),
        ("LINEBELOW",    (0, 0), (-1, 0),  1.2, hx(P["purple_lt"])),
        ("LINEBELOW",    (0, 1), (-1, -2), 0.4, hx(P["grey_2"])),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("BOX",          (0, 0), (-1, -1), 0.5, hx(P["grey_2"])),
    ])


def _kv_table_style():
    return TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), hx(P["purple_bg"])),
        ("TEXTCOLOR",    (0, 0), (0, -1), hx(P["purple"])),
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",     (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",     (0, 0), (-1, -1),8.5),
        ("TEXTCOLOR",    (1, 0), (1, -1), hx(P["grey_5"])),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW",    (0, 0), (-1, -2), 0.4, hx(P["grey_2"])),
        ("BOX",          (0, 0), (-1, -1), 0.5, hx(P["grey_2"])),
    ])


# ──────────────────────────────────────────────
# Report builder
# ──────────────────────────────────────────────
def build_report(
    in_path: Path, out_path: Path,
    *,
    show_compromised_excerpts: bool = False,
    dataset_name: str = "(unspecified)",
) -> None:
    rows = read_jsonl(in_path)
    if not rows:
        raise SystemExit("No rows in input JSONL")

    N      = len(rows)
    model  = rows[0].get("model", "(unknown)")
    scorer = (_summary(rows[0]).get("scorer_version") or "(unknown)")

    resp_types:  Counter                         = Counter()
    by_category: Dict[str, List[Dict]]           = defaultdict(list)
    by_family:   Dict[str, List[Dict]]           = defaultdict(list)
    compromised_ids: List[str]                   = []
    unexpected_refusal_ids: List[str]            = []
    success_true = 0

    for r in rows:
        by_category[r.get("category", "")].append(r)
        by_family[r.get("attack_family", "")].append(r)
        s = _summary(r)
        if _bool(s.get("compromised_any")):
            compromised_ids.append(str(r.get("id")))
        resp_types[(s.get("response_type") or "other")] += 1
        if _bool(_score(r).get("success")):
            success_true += 1
        expected = (str(r.get("expected_policy", "")) or "").strip().lower()
        if (expected == "answer"
                and _bool(s.get("refusal_any"))
                and not _bool(s.get("compromised_any"))):
            unexpected_refusal_ids.append(str(r.get("id")))

    cat_stats = {k: agg_group(v) for k, v in by_category.items()}
    fam_stats = {k: agg_group(v) for k, v in by_family.items()}

    comp_count = len(compromised_ids)
    comp_rate  = comp_count / N * 100.0 if N else 0.0
    succ_rate  = success_true / N * 100.0 if N else 0.0
    unexp_count= len(unexpected_refusal_ids)

    # ── build flagged list ──────────────────────
    flagged: List[Dict] = []
    for r in rows:
        rid  = str(r.get("id"))
        s    = _summary(r)
        comp = _bool(s.get("compromised_any"))
        unexp= rid in unexpected_refusal_ids
        if not (comp or unexp):
            continue
        per_turn = (_score(r).get("per_turn") or [{}])
        ev  = (per_turn[0].get("evidence", []) if per_turn else [])[:6]
        ao  = r.get("assistant_outputs") or []
        if isinstance(ao, str): ao = [ao]
        excerpt = " ".join((ao[0] or "").replace("\r", " ").splitlines()).strip()
        if len(excerpt) > 350: excerpt = excerpt[:350] + "…"
        if comp and not show_compromised_excerpts:
            excerpt = "[REDACTED — compromised output omitted for safety]"
        flagged.append({
            "id": rid, "category": str(r.get("category", "")),
            "attack_family": str(r.get("attack_family", "")),
            "expected_policy": str(r.get("expected_policy", "")),
            "compromised": comp, "success": _bool(_score(r).get("success")),
            "reason": str(_score(r).get("reason", "")),
            "response_type": str(s.get("response_type", "")),
            "max_actionability": s.get("max_actionability", {}),
            "evidence": ev, "excerpt": excerpt,
        })

    # ── render charts to bytes ──────────────────
    kpi_bytes  = chart_summary_scorecard(comp_rate, succ_rate, unexp_count, N)
    don_bytes  = chart_response_donut(resp_types)
    comp_bytes = chart_compromise_by_category(cat_stats)
    unex_bytes = chart_unexpected_refusal_by_category(cat_stats)
    fam_bytes  = chart_attack_family_heatmap(fam_stats)

    def img(data: bytes, w_cm: float, h_cm: float) -> Image:
        return Image(io.BytesIO(data), width=w_cm * cm, height=h_cm * cm)

    # ── styles ──────────────────────────────────
    ST = make_styles()

    # ── doc setup ───────────────────────────────
    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        rightMargin=MARGIN_H, leftMargin=MARGIN_H,
        topMargin=1.4 * cm, bottomMargin=1.6 * cm,
        title="LLMSecBench Report",
    )

    hf = _make_header_footer(model, dataset_name, scorer)

    # ── story ────────────────────────────────────
    story: List[Any] = []

    # ── COVER ────────────────────────────────────
    # We draw the cover purely via the onFirstPage callback
    # and skip the header/footer on that page.
    # Instead we inject a spacer that pushes content below the banner.
    story.append(Spacer(1, H * 0.42))   # below purple banner

    meta_data = [
        ["Dataset",        esc(dataset_name)],
        ["Model",          esc(model)],
        ["Input file",     esc(in_path.name)],
        ["Scorer version", esc(scorer)],
        ["Total prompts",  str(N)],
    ]
    meta_tbl = Table(meta_data, colWidths=[3.5 * cm, CONTENT_W - 3.5 * cm])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",    (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9.5),
        ("TEXTCOLOR",   (0, 0), (0, -1), hx(P["purple"])),
        ("TEXTCOLOR",   (1, 0), (1, -1), hx(P["grey_5"])),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0,0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("LINEBELOW",   (0, 0), (-1, -2), 0.4, hx(P["grey_2"])),
    ]))
    story.append(meta_tbl)
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ───────────────────────
    story.append(Paragraph("Executive Summary", ST["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=hx(P["purple_mid"]),
                            spaceAfter=8))
    story.append(img(kpi_bytes, 17.0, 2.5))
    story.append(Spacer(1, 10))

    intro = (
        f"This report presents the LLMSecBench evaluation results for model "
        f"<b>{esc(model)}</b> on dataset <b>{esc(dataset_name)}</b> "
        f"({N} prompts across {len(cat_stats)} categories). "
        f"The primary security signal is <b>compromised_any</b>, which measures whether "
        f"the model produced actionable harmful output. "
        f"<b>Policy success</b> tracks compliance with the expected response policy "
        f"(answer or refuse). "
        f"<b>Unexpected refusals</b> count benign prompts that were incorrectly refused."
    )
    story.append(Paragraph(intro, ST["Body"]))
    story.append(Spacer(1, 6))

    # Metric interpretation table
    interp = [
        ["Metric", "Definition", "Value"],
        ["compromised_any",   "Model produced an actionable harmful response",
         f"{comp_count} / {N}  ({comp_rate:.2f}%)"],
        ["Policy success",    "Response complied with expected_policy (answer or refuse)",
         f"{success_true} / {N}  ({succ_rate:.1f}%)"],
        ["Unexpected refusal","expected_policy=answer, refusal detected, not compromised",
         str(int(unexp_count))],
    ]
    it = Table(interp, colWidths=[3.8 * cm, 8.5 * cm, 4.1 * cm])
    it.setStyle(_header_table_style(3))
    # Colour-code the value column
    value_col = 2
    if comp_rate > 5:
        it.setStyle(TableStyle([("TEXTCOLOR", (value_col, 1), (value_col, 1), hx(P["red"])),
                                ("FONTNAME",  (value_col, 1), (value_col, 1), "Helvetica-Bold")]))
    if succ_rate >= 95:
        it.setStyle(TableStyle([("TEXTCOLOR", (value_col, 2), (value_col, 2), hx(P["green"])),
                                ("FONTNAME",  (value_col, 2), (value_col, 2), "Helvetica-Bold")]))
    if unexp_count > 0:
        it.setStyle(TableStyle([("TEXTCOLOR", (value_col, 3), (value_col, 3), hx(P["amber"])),
                                ("FONTNAME",  (value_col, 3), (value_col, 3), "Helvetica-Bold")]))
    story.append(it)
    story.append(PageBreak())

    # ── RESPONSE TYPE OVERVIEW ───────────────────
    story.append(Paragraph("Response Type Overview", ST["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=hx(P["purple_mid"]),
                            spaceAfter=10))

    story.append(Paragraph(
        "The donut chart below shows the distribution of response types across all evaluated prompts. "
        "<b>Refusal</b> and <b>deflection</b> are the desired outcomes for attack prompts, "
        "while <b>actionable</b> responses indicate a potential compromise.",
        ST["Body"]
    ))
    story.append(Spacer(1, 6))
    story.append(img(don_bytes, 13.0, 8.5))
    story.append(PageBreak())

    # ── COMPROMISE & REFUSAL CHARTS ──────────────
    story.append(Paragraph("Compromise & Utility Analysis", ST["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=hx(P["purple_mid"]),
                            spaceAfter=8))

    story.append(Paragraph(
        "The bar charts below show compromise rate and unexpected refusal rate broken down by "
        "test category. A <b style='color:#D63031'>red bar</b> indicates at least one "
        "compromised case; <b style='color:#E17055'>amber bars</b> highlight categories "
        "with utility regressions (unexpected refusals).",
        ST["Body"]
    ))
    story.append(Spacer(1, 6))
    story.append(img(comp_bytes, 17.0, 6.8))
    story.append(Spacer(1, 10))
    story.append(img(unex_bytes, 17.0, 6.8))
    story.append(PageBreak())

    # ── ATTACK FAMILY BREAKDOWN ───────────────────
    story.append(Paragraph("Attack Family Breakdown", ST["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=hx(P["purple_mid"]),
                            spaceAfter=8))
    story.append(Paragraph(
        "The horizontal chart below ranks attack families by volume and overlays "
        "policy-success and compromise counts.",
        ST["Body"]
    ))
    story.append(Spacer(1, 6))
    story.append(img(fam_bytes, 17.0, max(5.0, len(fam_stats) * 0.52 + 1.2)))
    story.append(PageBreak())

    # ── TABLES ───────────────────────────────────
    story.append(Paragraph("Detailed Breakdown by Category", ST["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=hx(P["purple_mid"]),
                            spaceAfter=8))

    cat_rows = [["Category", "Total", "Compromised", "Comp %",
                 "Policy success", "Unexp. refusals"]]
    for c in sorted(cat_stats.keys()):
        st = cat_stats[c]
        t  = st["total"]
        cp = st["compromised"]
        cat_rows.append([
            c or "(none)", t, cp,
            f"{cp/t*100:.1f}%" if t else "—",
            st["success"], st["unexpected_refusal"],
        ])

    ct = Table(cat_rows, hAlign="LEFT",
               colWidths=[5.0*cm, 1.8*cm, 2.2*cm, 1.8*cm, 2.6*cm, 2.8*cm])
    ct.setStyle(_header_table_style(6))
    # Highlight non-zero compromise
    for i, row in enumerate(cat_rows[1:], start=1):
        if row[2] and int(row[2]) > 0:
            ct.setStyle(TableStyle([
                ("TEXTCOLOR", (2, i), (3, i), hx(P["red"])),
                ("FONTNAME",  (2, i), (3, i), "Helvetica-Bold"),
            ]))
    story.append(ct)

    story.append(Spacer(1, 16))
    story.append(Paragraph("Detailed Breakdown by Attack Family (top 12)", ST["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=hx(P["purple_mid"]),
                            spaceAfter=8))

    fam_sorted = sorted(fam_stats.items(), key=lambda kv: kv[1]["total"], reverse=True)
    fam_rows = [["Attack family", "Total", "Compromised", "Comp %",
                 "Policy success", "Unexp. refusals"]]
    for fam, st in fam_sorted[:12]:
        t  = st["total"]
        cp = st["compromised"]
        fam_rows.append([
            fam or "(none)", t, cp,
            f"{cp/t*100:.1f}%" if t else "—",
            st["success"], st["unexpected_refusal"],
        ])

    ft = Table(fam_rows, hAlign="LEFT",
               colWidths=[5.5*cm, 1.8*cm, 2.2*cm, 1.8*cm, 2.6*cm, 2.3*cm])
    ft.setStyle(_header_table_style(6))
    story.append(ft)
    story.append(PageBreak())

    # ── FLAGGED CASES ─────────────────────────────
    story.append(Paragraph("Appendix — Flagged Cases", ST["H1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=hx(P["purple_mid"]),
                            spaceAfter=4))
    story.append(Paragraph(
        "Only <b>compromised</b> cases and <b>unexpected refusals</b> are listed. "
        "Excerpts of compromised outputs are redacted by default.",
        ST["Body"]
    ))
    story.append(Spacer(1, 8))

    for c in flagged:
        badge_text = "● COMPROMISED" if c["compromised"] else "● UNEXPECTED REFUSAL"
        badge_fg   = P["red"]        if c["compromised"] else P["amber"]
        badge_bg   = P["red_lt"]     if c["compromised"] else P["amber_lt"]

        # ID + category row
        id_para = Paragraph(
            f"<b>{esc(c['id'])}</b>"
            f"  <font color='{P['grey_4']}'>|</font>  "
            f"{esc(c['category'])}  ·  {esc(c['attack_family'])}",
            ST["FlagID"]
        )

        badge_tbl = Table([[Paragraph(badge_text, ST["Badge"])]],
                          colWidths=[5.2 * cm])
        badge_tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), hx(badge_bg)),
            ("TEXTCOLOR",    (0, 0), (-1, -1), hx(badge_fg)),
            ("BOX",          (0, 0), (-1, -1), 1, hx(badge_fg)),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))

        kv = [
            ["Expected policy", esc(c["expected_policy"])],
            ["Success",         "✓ yes" if c["success"] else "✗ no"],
            ["Reason",          esc(c["reason"])],
            ["Response type",   esc(c["response_type"])],
            ["Max actionability", esc(str(c["max_actionability"]))],
            ["Evidence",        esc(", ".join(c["evidence"]))],
        ]
        kv_tbl = Table(kv, colWidths=[3.2 * cm, CONTENT_W - 3.2 * cm])
        kv_tbl.setStyle(_kv_table_style())
        # Green / red for success
        kv_tbl.setStyle(TableStyle([
            ("TEXTCOLOR", (1, 1), (1, 1),
             hx(P["green"]) if c["success"] else hx(P["red"])),
            ("FONTNAME",  (1, 1), (1, 1), "Helvetica-Bold"),
        ]))

        excerpt_tbl = Table(
            [[Paragraph(esc(c["excerpt"]), ST["BodySmall"])]],
            colWidths=[CONTENT_W],
        )
        excerpt_tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), hx(P["grey_1"])),
            ("BOX",          (0, 0), (-1, -1), 0.5, hx(P["grey_3"])),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING",   (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ]))

        block = KeepTogether([
            id_para, badge_tbl,
            Spacer(1, 4),
            kv_tbl,
            Spacer(1, 4),
            Paragraph("<b>Response excerpt:</b>", ST["BodySmall"]),
            Spacer(1, 2),
            excerpt_tbl,
            Spacer(1, 14),
            HRFlowable(width="100%", thickness=0.4, color=hx(P["grey_2"]),
                       spaceAfter=4),
        ])
        story.append(block)

    # ── BUILD ────────────────────────────────────
    doc.build(story,
              onFirstPage=_cover_page,
              onLaterPages=hf)


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in",  dest="inp",     required=True)
    ap.add_argument("--out", dest="out",     required=True)
    ap.add_argument("--dataset", dest="dataset", default="(unspecified)")
    ap.add_argument("--show-compromised-excerpts", action="store_true")
    args = ap.parse_args()

    build_report(
        Path(args.inp), Path(args.out),
        show_compromised_excerpts=bool(args.show_compromised_excerpts),
        dataset_name=args.dataset,
    )
    print(f"✓  Report written → {args.out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())