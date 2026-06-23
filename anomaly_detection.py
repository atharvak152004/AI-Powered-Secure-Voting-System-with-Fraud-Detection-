"""
anomaly_detection.py — AI-based fraud detection for the voting system.

Techniques used:
  • Isolation Forest  — detects outlier voting sessions by behavioural features
  • Local Outlier Factor — identifies unusual vote-timing bursts
  • Rule-based heuristics — catches deterministic fraud patterns

Each detected anomaly is written to the anomaly_logs table and displayed
in the Admin Dashboard.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from database import get_vote_timeline, get_audit_logs, log_anomaly, get_anomaly_count, get_total_votes


# ── Feature Engineering ───────────────────────────────────────────────────────

def build_vote_features(timeline: list[dict]) -> pd.DataFrame:
    """
    Convert raw vote records into a feature matrix.

    Features per vote:
        hour_of_day        — voting hour (0-23)
        seconds_since_last — inter-arrival time in seconds
        votes_last_5min    — rolling vote count in a 5-minute window
        candidate_entropy  — running entropy of vote distribution so far
    """
    if not timeline:
        return pd.DataFrame()

    df = pd.DataFrame(timeline)
    df["voted_at"] = pd.to_datetime(df["voted_at"])
    df = df.sort_values("voted_at").reset_index(drop=True)

    df["hour_of_day"] = df["voted_at"].dt.hour
    df["seconds_since_last"] = df["voted_at"].diff().dt.total_seconds().fillna(0)

    # Rolling vote count (last 5 min)
    df.set_index("voted_at", inplace=True)
    df["votes_last_5min"] = df["candidate"].rolling("5min").count().values
    df.reset_index(inplace=True)

    # Running candidate entropy
    counts = {}
    entropies = []
    for candidate in df["candidate"]:
        counts[candidate] = counts.get(candidate, 0) + 1
        total = sum(counts.values())
        probs = np.array(list(counts.values())) / total
        entropy = -np.sum(probs * np.log2(probs + 1e-9))
        entropies.append(entropy)
    df["candidate_entropy"] = entropies

    return df[["hour_of_day", "seconds_since_last", "votes_last_5min", "candidate_entropy"]]


# ── Isolation Forest Detector ─────────────────────────────────────────────────

def run_isolation_forest(features: pd.DataFrame) -> np.ndarray:
    """
    Returns anomaly scores for each vote event.
    Score < 0  → outlier (suspicious)
    Score > 0  → inlier  (normal)
    """
    if len(features) < 5:
        return np.zeros(len(features))

    clf = IsolationForest(
        n_estimators=200,
        contamination=0.05,   # assume ~5% fraud rate
        random_state=42,
        n_jobs=-1
    )
    scaler = StandardScaler()
    X = scaler.fit_transform(features)
    clf.fit(X)
    return clf.decision_function(X)   # continuous score


# ── Local Outlier Factor Detector ─────────────────────────────────────────────

def run_lof(features: pd.DataFrame) -> np.ndarray:
    if len(features) < 5:
        return np.zeros(len(features))

    n_neighbors = min(20, len(features) - 1)
    lof = LocalOutlierFactor(n_neighbors=n_neighbors, contamination=0.05)
    scaler = StandardScaler()
    X = scaler.fit_transform(features)
    lof.fit_predict(X)
    return -lof.negative_outlier_factor_   # higher = more anomalous


# ── Rule-Based Heuristics ─────────────────────────────────────────────────────

def rule_based_checks(timeline: list[dict]) -> list[dict]:
    """
    Deterministic fraud checks that don't rely on ML models.
    Returns a list of alert dicts.
    """
    alerts = []
    if not timeline:
        return alerts

    df = pd.DataFrame(timeline)
    df["voted_at"] = pd.to_datetime(df["voted_at"])

    # 1. Rapid successive votes (< 5 seconds apart)
    df_sorted = df.sort_values("voted_at")
    diffs = df_sorted["voted_at"].diff().dt.total_seconds()
    rapid = diffs[diffs < 5].index.tolist()
    for idx in rapid:
        row = df_sorted.iloc[idx]
        alerts.append({
            "type": "RAPID_VOTING",
            "username": row.get("username", "unknown"),
            "score": 0.95,
            "details": f"Vote cast within 5 seconds of previous vote at {row['voted_at']}"
        })

    # 2. Unusual vote spike (> 50% of votes for one candidate in last 10 votes)
    if len(df) >= 10:
        last10 = df.tail(10)
        for cand, grp in last10.groupby("candidate"):
            if len(grp) >= 7:
                alerts.append({
                    "type": "VOTE_SPIKE",
                    "username": "multiple",
                    "score": 0.80,
                    "details": f"Candidate '{cand}' received {len(grp)}/10 recent votes — possible coordinated voting"
                })

    # 3. Abnormal voting hour (outside 8AM–8PM)
    after_hours = df[~df["voted_at"].dt.hour.between(8, 20)]
    for _, row in after_hours.iterrows():
        alerts.append({
            "type": "OFF_HOURS_VOTE",
            "username": row.get("username", "unknown"),
            "score": 0.60,
            "details": f"Vote cast at {row['voted_at'].strftime('%H:%M')} — outside expected hours"
        })

    return alerts


# ── Failed Login Analysis ─────────────────────────────────────────────────────

def analyze_login_failures() -> list[dict]:
    """Checks audit log for brute-force patterns."""
    alerts = []
    logs = get_audit_logs(limit=500)
    failures: dict[str, list] = {}

    for entry in logs:
        if entry["event_type"] == "LOGIN_FAILED" and entry["username"]:
            failures.setdefault(entry["username"], []).append(entry["timestamp"])

    for user, timestamps in failures.items():
        if len(timestamps) >= 3:
            alerts.append({
                "type": "BRUTE_FORCE",
                "username": user,
                "score": min(0.5 + len(timestamps) * 0.1, 0.99),
                "details": f"{len(timestamps)} consecutive failed login attempts for user '{user}'"
            })

    return alerts


# ── Election Integrity Score ──────────────────────────────────────────────────

def compute_integrity_score() -> tuple[float, str]:
    """
    Returns (score_percentage, status_label)
    100% = perfectly normal; lower = more suspicious
    """
    total = get_total_votes()
    anomaly_count = get_anomaly_count()

    if total == 0:
        return 100.0, "No Votes Yet"

    anomaly_rate = anomaly_count / max(total, 1)

    # Base score starts at 100, penalise by anomaly rate
    score = max(0.0, 100.0 - anomaly_rate * 200)

    if score >= 90:
        status = "✅ Normal"
    elif score >= 70:
        status = "⚠️ Mild Concerns"
    elif score >= 50:
        status = "🔶 Suspicious Activity Detected"
    else:
        status = "🚨 HIGH RISK — Possible Fraud"

    return round(score, 1), status


# ── Master Analysis Runner ────────────────────────────────────────────────────

def run_full_analysis() -> dict:
    """
    Runs all detectors and writes new findings to anomaly_logs.
    Returns a summary dict for the dashboard.
    """
    timeline = get_vote_timeline()
    features = build_vote_features(timeline)

    new_flags = 0

    if not features.empty:
        if_scores = run_isolation_forest(features)
        lof_scores = run_lof(features)

        for i, (if_score, lof_score) in enumerate(zip(if_scores, lof_scores)):
            # Normalise IF score to 0-1 (more negative = more suspicious)
            normalized_if = max(0.0, min(1.0, 0.5 - if_score))
            combined = (normalized_if + min(lof_score / 3.0, 1.0)) / 2.0

            if combined > 0.6:  # threshold for flagging
                vote = timeline[i]
                log_anomaly(
                    anomaly_type="ML_ANOMALY",
                    username=vote.get("username"),
                    score=round(combined, 3),
                    details=f"IF score={if_score:.3f}, LOF score={lof_score:.3f} for vote at {vote.get('voted_at')}"
                )
                new_flags += 1

    # Rule-based checks
    rule_alerts = rule_based_checks(timeline)
    for alert in rule_alerts:
        log_anomaly(
            anomaly_type=alert["type"],
            username=alert["username"],
            score=alert["score"],
            details=alert["details"]
        )
        new_flags += 1

    # Login failure analysis
    brute_alerts = analyze_login_failures()
    for alert in brute_alerts:
        log_anomaly(
            anomaly_type=alert["type"],
            username=alert["username"],
            score=alert["score"],
            details=alert["details"]
        )
        new_flags += 1

    score, status = compute_integrity_score()

    return {
        "new_flags": new_flags,
        "integrity_score": score,
        "integrity_status": status,
        "total_anomalies": get_anomaly_count(),
        "total_votes": get_total_votes()
    }
