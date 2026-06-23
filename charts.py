"""
charts.py — Matplotlib/Seaborn visualizations for the Admin Dashboard.
All charts are rendered into tkinter-compatible FigureCanvasTkAgg widgets.
"""

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import pandas as pd
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from database import get_vote_counts, get_vote_timeline, get_anomaly_logs, get_audit_logs

# ── Palette ───────────────────────────────────────────────────────────────────
PALETTE = ["#00A896", "#1A2744", "#F5A623", "#D0021B", "#7C3AED", "#059669"]
NAVY    = "#1A2744"
TEAL    = "#00A896"
AMBER   = "#F5A623"
RED     = "#D0021B"

plt.rcParams.update({
    "figure.facecolor": "#F4F6FA",
    "axes.facecolor":   "#FFFFFF",
    "axes.edgecolor":   "#D1D5DB",
    "axes.spines.top":  False,
    "axes.spines.right": False,
    "font.family": "DejaVu Sans",
    "axes.titleweight": "bold",
    "axes.titlesize": 11,
    "axes.labelsize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
})


def embed_figure(fig, parent_frame):
    """Embed a matplotlib figure into a Tkinter frame."""
    canvas = FigureCanvasTkAgg(fig, master=parent_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)
    return canvas


# ── 1. Vote Distribution Bar Chart ────────────────────────────────────────────

def vote_distribution_chart(parent_frame):
    vote_counts = get_vote_counts()
    if not vote_counts:
        return None

    fig, ax = plt.subplots(figsize=(6, 3.5))
    candidates = list(vote_counts.keys())
    counts = list(vote_counts.values())
    bars = ax.barh(candidates, counts, color=PALETTE[:len(candidates)], edgecolor="white", height=0.6)

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
                str(count), va="center", fontsize=9, fontweight="bold", color=NAVY)

    ax.set_xlabel("Votes", color=NAVY)
    ax.set_title("Candidate Vote Distribution", color=NAVY, pad=10)
    ax.set_xlim(0, max(counts) * 1.2 + 1)
    fig.tight_layout()
    return embed_figure(fig, parent_frame)


# ── 2. Votes Over Time Line Chart ─────────────────────────────────────────────

def votes_over_time_chart(parent_frame):
    timeline = get_vote_timeline()
    if not timeline:
        return None

    df = pd.DataFrame(timeline)
    df["voted_at"] = pd.to_datetime(df["voted_at"])
    df = df.sort_values("voted_at")
    df["cumulative"] = range(1, len(df) + 1)

    fig, ax = plt.subplots(figsize=(6, 3))
    ax.plot(df["voted_at"], df["cumulative"], color=TEAL, linewidth=2, marker="o", markersize=4)
    ax.fill_between(df["voted_at"], df["cumulative"], alpha=0.15, color=TEAL)
    ax.set_xlabel("Time")
    ax.set_ylabel("Cumulative Votes")
    ax.set_title("Voting Activity Over Time", color=NAVY, pad=10)
    fig.autofmt_xdate(rotation=30)
    fig.tight_layout()
    return embed_figure(fig, parent_frame)


# ── 3. Anomaly Score Distribution ────────────────────────────────────────────

def anomaly_score_chart(parent_frame):
    anomalies = get_anomaly_logs(limit=100)
    if not anomalies:
        return None

    scores = [a["anomaly_score"] for a in anomalies if a["anomaly_score"] is not None]
    if not scores:
        return None

    fig, ax = plt.subplots(figsize=(6, 3))
    ax.hist(scores, bins=15, color=AMBER, edgecolor="white", alpha=0.85)
    ax.axvline(0.7, color=RED, linestyle="--", linewidth=1.5, label="Risk Threshold (0.7)")
    ax.set_xlabel("Anomaly Score")
    ax.set_ylabel("Frequency")
    ax.set_title("Anomaly Score Distribution", color=NAVY, pad=10)
    ax.legend(fontsize=8)
    fig.tight_layout()
    return embed_figure(fig, parent_frame)


# ── 4. Vote Share Donut Chart ─────────────────────────────────────────────────

def vote_share_donut(parent_frame):
    vote_counts = get_vote_counts()
    if not vote_counts:
        return None

    fig, ax = plt.subplots(figsize=(4.5, 3.5))
    labels = list(vote_counts.keys())
    sizes  = list(vote_counts.values())
    wedge_props = {"width": 0.55, "edgecolor": "white", "linewidth": 2}
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, autopct="%1.0f%%",
        colors=PALETTE[:len(labels)], wedgeprops=wedge_props,
        startangle=90, pctdistance=0.75
    )
    for t in autotexts:
        t.set_fontsize(8)
        t.set_fontweight("bold")
    ax.set_title("Vote Share", color=NAVY, pad=10)
    fig.tight_layout()
    return embed_figure(fig, parent_frame)


# ── 5. Security Events Severity Chart ────────────────────────────────────────

def security_events_chart(parent_frame):
    logs = get_audit_logs(limit=200)
    if not logs:
        return None

    df = pd.DataFrame(logs)
    severity_counts = df["severity"].value_counts()
    sev_colors = {"CRITICAL": RED, "WARNING": AMBER, "INFO": TEAL}
    colors_list = [sev_colors.get(s, "#6B7280") for s in severity_counts.index]

    fig, ax = plt.subplots(figsize=(5, 3))
    bars = ax.bar(severity_counts.index, severity_counts.values,
                  color=colors_list, edgecolor="white", width=0.5)
    for bar, val in zip(bars, severity_counts.values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
                str(val), ha="center", fontsize=9, fontweight="bold", color=NAVY)
    ax.set_title("Security Events by Severity", color=NAVY, pad=10)
    ax.set_ylabel("Count")
    fig.tight_layout()
    return embed_figure(fig, parent_frame)
