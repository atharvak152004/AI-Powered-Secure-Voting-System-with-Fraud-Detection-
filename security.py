"""
security.py — Authentication, hashing, lockout, session management
Implements bcrypt password hashing, account lockout policy, role-based
access control, and cryptographic session tokens.
"""

import bcrypt
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from database import (
    get_user, get_admin, update_failed_attempts,
    reset_failed_attempts, log_event, add_user, add_admin
)

# ── Policy Constants ─────────────────────────────────────────────────────────
MAX_ATTEMPTS = 5          # lockout after N consecutive failures
LOCKOUT_MINUTES = 15      # duration of lockout


# ── Password Hashing ─────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


# ── Session Tokens ───────────────────────────────────────────────────────────

def generate_session_token() -> str:
    return secrets.token_hex(32)


# ── User Authentication ──────────────────────────────────────────────────────

class AuthResult:
    def __init__(self, success: bool, message: str, session_token: str = None):
        self.success = success
        self.message = message
        self.session_token = session_token


def authenticate_user(username: str, password: str) -> AuthResult:
    user = get_user(username)

    if not user:
        log_event("LOGIN_FAILED", username, "User not found", "WARNING")
        return AuthResult(False, "Invalid username or password.")

    # Check lockout
    if user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if datetime.now() < locked_until:
            remaining = int((locked_until - datetime.now()).total_seconds() // 60)
            log_event("LOGIN_BLOCKED", username, f"Account locked for {remaining} more minutes", "WARNING")
            return AuthResult(False, f"Account locked. Try again in {remaining} minute(s).")
        else:
            reset_failed_attempts(username)
            user = get_user(username)  # refresh

    if not verify_password(password, user["password_hash"]):
        attempts = user["failed_attempts"] + 1
        locked_until = None
        if attempts >= MAX_ATTEMPTS:
            locked_until = (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            log_event("ACCOUNT_LOCKED", username, f"Locked after {attempts} failed attempts", "CRITICAL")
        else:
            log_event("LOGIN_FAILED", username, f"Wrong password (attempt {attempts})", "WARNING")
        update_failed_attempts(username, attempts, locked_until)
        remaining = MAX_ATTEMPTS - attempts
        if remaining <= 0:
            return AuthResult(False, f"Account locked for {LOCKOUT_MINUTES} minutes.")
        return AuthResult(False, f"Invalid password. {remaining} attempt(s) remaining.")

    # Success
    reset_failed_attempts(username)
    token = generate_session_token()
    log_event("LOGIN_SUCCESS", username, "User authenticated successfully", "INFO")
    return AuthResult(True, "Login successful!", token)


def authenticate_admin(username: str, password: str) -> AuthResult:
    admin = get_admin(username)
    if not admin:
        log_event("ADMIN_LOGIN_FAILED", username, "Admin not found", "WARNING")
        return AuthResult(False, "Invalid admin credentials.")

    if not verify_password(password, admin["password_hash"]):
        log_event("ADMIN_LOGIN_FAILED", username, "Wrong admin password", "WARNING")
        return AuthResult(False, "Invalid admin credentials.")

    token = generate_session_token()
    log_event("ADMIN_LOGIN_SUCCESS", username, "Admin authenticated", "INFO")
    return AuthResult(True, "Admin login successful!", token)


# ── Bootstrap Default Users ──────────────────────────────────────────────────

def bootstrap_default_accounts():
    """
    Seeds initial admin and sample user if database is empty.
    In production these would be set via a secure setup wizard.
    """
    # Default admin
    existing = get_admin("admin")
    if not existing:
        add_admin("admin", hash_password("Admin@2024!"))
        log_event("BOOTSTRAP", "system", "Default admin account created", "INFO")

    # Sample voter for demo
    existing_user = get_user("voter1")
    if not existing_user:
        add_user("voter1", hash_password("Voter@123"), roll_number="2024001")
        log_event("BOOTSTRAP", "system", "Sample voter1 created", "INFO")

    existing_user2 = get_user("voter2")
    if not existing_user2:
        add_user("voter2", hash_password("Voter@456"), roll_number="2024002")
        log_event("BOOTSTRAP", "system", "Sample voter2 created", "INFO")


# ── Vote Integrity ────────────────────────────────────────────────────────────

def compute_vote_hash(username: str, roll_number: str, candidate: str, timestamp: str) -> str:
    """Creates a SHA-256 fingerprint of a vote record for integrity checks."""
    payload = f"{username}:{roll_number}:{candidate}:{timestamp}"
    return hashlib.sha256(payload.encode()).hexdigest()
