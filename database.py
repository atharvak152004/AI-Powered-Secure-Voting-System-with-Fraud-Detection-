"""
database.py — SQLite database layer for AI-Powered Secure Voting System
Replaces legacy text-file storage with structured relational database.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "voting_system.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def initialize_database():
    """Create all tables if they don't exist."""
    conn = get_connection()
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    NOT NULL UNIQUE,
            password_hash   TEXT    NOT NULL,
            roll_number     TEXT    UNIQUE,
            failed_attempts INTEGER DEFAULT 0,
            locked_until    TEXT    DEFAULT NULL,
            created_at      TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS admins (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    NOT NULL UNIQUE,
            password_hash   TEXT    NOT NULL,
            created_at      TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS votes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    NOT NULL,
            roll_number     TEXT    NOT NULL UNIQUE,
            candidate       TEXT    NOT NULL,
            voted_at        TEXT    DEFAULT (datetime('now')),
            ip_hash         TEXT    DEFAULT 'N/A',
            session_token   TEXT,
            FOREIGN KEY (username) REFERENCES users(username)
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type  TEXT    NOT NULL,
            username    TEXT,
            details     TEXT,
            severity    TEXT    DEFAULT 'INFO',
            timestamp   TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS anomaly_logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            anomaly_type    TEXT    NOT NULL,
            username        TEXT,
            anomaly_score   REAL,
            details         TEXT,
            flagged         INTEGER DEFAULT 1,
            detected_at     TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS election_config (
            key     TEXT PRIMARY KEY,
            value   TEXT
        );

        INSERT OR IGNORE INTO election_config VALUES ('status', 'ongoing');
        INSERT OR IGNORE INTO election_config VALUES ('started_at', datetime('now'));
    """)
    conn.commit()
    conn.close()


# ── User CRUD ────────────────────────────────────────────────────────────────

def add_user(username: str, password_hash: str, roll_number: str = None):
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, roll_number) VALUES (?, ?, ?)",
            (username, password_hash, roll_number)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user(username: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_failed_attempts(username: str, attempts: int, locked_until: str = None):
    conn = get_connection()
    conn.execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
        (attempts, locked_until, username)
    )
    conn.commit()
    conn.close()


def reset_failed_attempts(username: str):
    conn = get_connection()
    conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
        (username,)
    )
    conn.commit()
    conn.close()


# ── Admin CRUD ────────────────────────────────────────────────────────────────

def add_admin(username: str, password_hash: str):
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_admin(username: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ── Vote CRUD ────────────────────────────────────────────────────────────────

def cast_vote(username: str, roll_number: str, candidate: str, session_token: str = None):
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO votes (username, roll_number, candidate, session_token) VALUES (?, ?, ?, ?)",
            (username, roll_number, candidate, session_token)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def has_voted(roll_number: str) -> bool:
    conn = get_connection()
    row = conn.execute("SELECT id FROM votes WHERE roll_number = ?", (roll_number,)).fetchone()
    conn.close()
    return row is not None


def get_vote_counts() -> dict:
    conn = get_connection()
    rows = conn.execute(
        "SELECT candidate, COUNT(*) as cnt FROM votes GROUP BY candidate"
    ).fetchall()
    conn.close()
    return {r["candidate"]: r["cnt"] for r in rows}


def get_all_votes():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM votes ORDER BY voted_at").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_vote_timeline():
    """Returns list of (timestamp, candidate) for anomaly detection."""
    conn = get_connection()
    rows = conn.execute("SELECT voted_at, candidate, username FROM votes ORDER BY voted_at").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Audit Logs ───────────────────────────────────────────────────────────────

def log_event(event_type: str, username: str = None, details: str = None, severity: str = "INFO"):
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_logs (event_type, username, details, severity) VALUES (?, ?, ?, ?)",
        (event_type, username, details, severity)
    )
    conn.commit()
    conn.close()


def get_audit_logs(limit: int = 100):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Anomaly Logs ─────────────────────────────────────────────────────────────

def log_anomaly(anomaly_type: str, username: str = None, score: float = None, details: str = None):
    conn = get_connection()
    conn.execute(
        "INSERT INTO anomaly_logs (anomaly_type, username, anomaly_score, details) VALUES (?, ?, ?, ?)",
        (anomaly_type, username, score, details)
    )
    conn.commit()
    conn.close()


def get_anomaly_logs(limit: int = 50):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM anomaly_logs ORDER BY detected_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_anomaly_count() -> int:
    conn = get_connection()
    row = conn.execute("SELECT COUNT(*) as cnt FROM anomaly_logs WHERE flagged = 1").fetchone()
    conn.close()
    return row["cnt"]


# ── Election Config ──────────────────────────────────────────────────────────

def get_election_status() -> str:
    conn = get_connection()
    row = conn.execute("SELECT value FROM election_config WHERE key = 'status'").fetchone()
    conn.close()
    return row["value"] if row else "ongoing"


def set_election_status(status: str):
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO election_config (key, value) VALUES ('status', ?)", (status,)
    )
    conn.commit()
    conn.close()


def get_total_votes() -> int:
    conn = get_connection()
    row = conn.execute("SELECT COUNT(*) as cnt FROM votes").fetchone()
    conn.close()
    return row["cnt"]
