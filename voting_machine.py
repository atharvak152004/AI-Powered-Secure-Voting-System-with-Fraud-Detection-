"""
voting_machine.py — AI-Powered Secure Voting System with Anomaly Detection
==========================================================================
Extended from the original Tkinter voting system.

New capabilities:
  • SQLite database (replaces text files)
  • bcrypt password hashing  
  • Account lockout after 5 failed attempts
  • Role-based access control (voter / admin)
  • AI anomaly detection (Isolation Forest + LOF)
  • Real-time integrity score in Admin Dashboard
  • Audit trail for every action
  • Matplotlib charts inside the dashboard
  • Export full election report to PDF
"""

import os
import sys
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import threading
import time

# ── Bootstrap project modules ─────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

import database as db
from security import authenticate_user, authenticate_admin, bootstrap_default_accounts, hash_password
from anomaly_detection import run_full_analysis, compute_integrity_score
from database import (
    cast_vote, has_voted, get_vote_counts, get_audit_logs,
    get_anomaly_logs, get_total_votes, get_election_status,
    set_election_status, log_event, add_user
)

# ── Initialise database & seed accounts ──────────────────────────────────────
db.initialize_database()
bootstrap_default_accounts()

# ── Application constants ─────────────────────────────────────────────────────
MAX_CANDIDATES = 5
CANDIDATES = ["Atharva", "Yash", "Om", "Raj", "NONE OF THESE"]
CANDIDATE_BIO = {
    "Atharva":        "Academic topper. Promises better study resources.",
    "Yash":         "Sports captain. Advocates improved facilities.",
    "Om":      "Tech enthusiast. Wants a student coding lab.",
    "Raj":         "Cultural head. Pushes for more events & welfare.",
    "NONE OF THESE": "Register dissatisfaction with current nominees.",
}

# ── Colour theme ──────────────────────────────────────────────────────────────
BG       = "#F4F6FA"
NAVY     = "#1A2744"
TEAL     = "#00A896"
AMBER    = "#F5A623"
RED      = "#D0021B"
WHITE    = "#FFFFFF"
CARD_BG  = "#FFFFFF"
BTN_FG   = WHITE
BTN_FONT = ("Helvetica", 10, "bold")

# Tkinter palette helpers
def tk_style_button(btn, color=TEAL, fg=WHITE):
    btn.configure(bg=color, fg=fg, activebackground=color,
                  font=BTN_FONT, relief="flat", bd=0,
                  padx=12, pady=6, cursor="hand2")

# ── Active session store (in-memory) ─────────────────────────────────────────
active_sessions: dict[str, str] = {}   # username → session_token


# ─────────────────────────────────────────────────────────────────────────────
# ROOT WINDOW
# ─────────────────────────────────────────────────────────────────────────────
root = tk.Tk()
root.title("AI-Powered Secure Voting System")
root.configure(bg=BG)
root.geometry("900x680")
root.resizable(True, True)


def build_header(parent):
    hdr = tk.Frame(parent, bg=NAVY, pady=10)
    hdr.pack(fill="x")
    tk.Label(hdr, text="🗳  AI-POWERED SECURE VOTING SYSTEM",
             bg=NAVY, fg=WHITE, font=("Helvetica", 16, "bold")).pack()
    tk.Label(hdr, text="Second Year · F Division · Class Representative Election",
             bg=NAVY, fg="#94A3B8", font=("Helvetica", 9)).pack()


def build_footer(parent):
    ftr = tk.Frame(parent, bg=NAVY, pady=5)
    ftr.pack(fill="x", side="bottom")
    election_status = get_election_status()
    color = TEAL if election_status == "ongoing" else AMBER
    tk.Label(ftr, text=f"Election Status: {election_status.upper()}",
             bg=NAVY, fg=color, font=("Helvetica", 8, "bold")).pack(side="left", padx=12)

    score, status = compute_integrity_score()
    score_color = TEAL if score >= 90 else AMBER if score >= 70 else RED
    tk.Label(ftr, text=f"Integrity Score: {score}%  {status}",
             bg=NAVY, fg=score_color, font=("Helvetica", 8, "bold")).pack(side="right", padx=12)


# ── Home screen ───────────────────────────────────────────────────────────────

def build_home():
    for w in root.winfo_children():
        w.destroy()

    build_header(root)

    body = tk.Frame(root, bg=BG)
    body.pack(fill="both", expand=True, padx=40, pady=30)

    # Decorative banner
    banner = tk.Frame(body, bg=TEAL, pady=14)
    banner.pack(fill="x", pady=(0, 24))
    tk.Label(banner, text="✦  CAST YOUR VOTE TODAY  ✦",
             bg=TEAL, fg=WHITE, font=("Helvetica", 13, "bold")).pack()
    tk.Label(banner, text='"Your vote is your voice. Make it count."',
             bg=TEAL, fg="#D1FAF6", font=("Helvetica", 9, "italic")).pack()

    # Cards row
    cards_frame = tk.Frame(body, bg=BG)
    cards_frame.pack(expand=True)

    def make_card(parent, title, desc, icon, command, btn_color=TEAL):
        card = tk.Frame(parent, bg=CARD_BG, bd=1, relief="solid",
                        padx=24, pady=20)
        card.pack(side="left", padx=16, pady=8, fill="y")
        tk.Label(card, text=icon, bg=CARD_BG, font=("Helvetica", 30)).pack()
        tk.Label(card, text=title, bg=CARD_BG, fg=NAVY,
                 font=("Helvetica", 12, "bold")).pack(pady=(4, 2))
        tk.Label(card, text=desc, bg=CARD_BG, fg="#6B7280",
                 font=("Helvetica", 8), wraplength=180, justify="center").pack(pady=(0, 12))
        btn = tk.Button(card, text=f"  {title}  ", command=command)
        tk_style_button(btn, btn_color)
        btn.pack(fill="x")

    make_card(cards_frame, "Voter Login", "Authenticate and cast\nyour secure vote.",
              "🧑‍🎓", show_user_login, TEAL)
    make_card(cards_frame, "Admin Login", "Access election dashboard\nand AI analytics.",
              "🛡️", show_admin_login, NAVY)
    make_card(cards_frame, "Register Voter", "Create a new voter\naccount.",
              "📋", show_register, "#7C3AED")

    # Stats strip
    stats = tk.Frame(body, bg=WHITE, pady=12)
    stats.pack(fill="x", pady=(20, 0))
    total = get_total_votes()
    anomalies = db.get_anomaly_count()
    score, _ = compute_integrity_score()

    for label, val, color in [
        ("Total Votes Cast", str(total), TEAL),
        ("Active Anomaly Alerts", str(anomalies), RED if anomalies > 0 else "#6B7280"),
        ("Integrity Score", f"{score}%", TEAL if score >= 90 else AMBER),
    ]:
        col = tk.Frame(stats, bg=WHITE)
        col.pack(side="left", expand=True)
        tk.Label(col, text=val, bg=WHITE, fg=color,
                 font=("Helvetica", 22, "bold")).pack()
        tk.Label(col, text=label, bg=WHITE, fg="#6B7280",
                 font=("Helvetica", 8)).pack()

    build_footer(root)


# ── Registration ──────────────────────────────────────────────────────────────

def show_register():
    win = tk.Toplevel(root)
    win.title("Register New Voter")
    win.configure(bg=BG)
    win.geometry("400x360")

    tk.Label(win, text="📋  Voter Registration", bg=BG, fg=NAVY,
             font=("Helvetica", 14, "bold")).pack(pady=(20, 4))
    tk.Label(win, text="Create your voter account", bg=BG, fg="#6B7280",
             font=("Helvetica", 9)).pack(pady=(0, 16))

    frame = tk.Frame(win, bg=BG)
    frame.pack(padx=40)

    def field(label):
        tk.Label(frame, text=label, bg=BG, fg=NAVY,
                 font=("Helvetica", 9, "bold"), anchor="w").pack(fill="x")
        e = tk.Entry(frame, font=("Helvetica", 10), relief="solid", bd=1)
        e.pack(fill="x", pady=(2, 10))
        return e

    uname_e  = field("Username")
    roll_e   = field("Roll Number")
    pass_e   = field("Password")
    pass_e.configure(show="*")
    conf_e   = field("Confirm Password")
    conf_e.configure(show="*")

    def do_register():
        u, r, p, c = uname_e.get().strip(), roll_e.get().strip(), pass_e.get(), conf_e.get()
        if not all([u, r, p, c]):
            messagebox.showerror("Error", "All fields are required.", parent=win)
            return
        if p != c:
            messagebox.showerror("Error", "Passwords do not match.", parent=win)
            return
        if len(p) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters.", parent=win)
            return
        hashed = hash_password(p)
        if add_user(u, hashed, roll_number=r):
            log_event("USER_REGISTERED", u, f"Roll: {r}", "INFO")
            messagebox.showinfo("Success", f"Voter '{u}' registered successfully!", parent=win)
            win.destroy()
        else:
            messagebox.showerror("Error", "Username or Roll Number already exists.", parent=win)

    btn = tk.Button(frame, text="Register", command=do_register)
    tk_style_button(btn)
    btn.pack(fill="x", pady=(4, 0))


# ── User Login ────────────────────────────────────────────────────────────────

def show_user_login():
    win = tk.Toplevel(root)
    win.title("Voter Login")
    win.configure(bg=BG)
    win.geometry("380x300")

    tk.Label(win, text="🧑‍🎓  Voter Login", bg=BG, fg=NAVY,
             font=("Helvetica", 14, "bold")).pack(pady=(20, 4))
    tk.Label(win, text="Enter your credentials to cast your vote", bg=BG, fg="#6B7280",
             font=("Helvetica", 9)).pack(pady=(0, 16))

    frame = tk.Frame(win, bg=BG)
    frame.pack(padx=40)

    tk.Label(frame, text="Username", bg=BG, fg=NAVY,
             font=("Helvetica", 9, "bold"), anchor="w").pack(fill="x")
    uname_e = tk.Entry(frame, font=("Helvetica", 10), relief="solid", bd=1)
    uname_e.pack(fill="x", pady=(2, 10))

    tk.Label(frame, text="Password", bg=BG, fg=NAVY,
             font=("Helvetica", 9, "bold"), anchor="w").pack(fill="x")
    pass_e = tk.Entry(frame, show="*", font=("Helvetica", 10), relief="solid", bd=1)
    pass_e.pack(fill="x", pady=(2, 14))

    def do_login():
        u, p = uname_e.get().strip(), pass_e.get()
        result = authenticate_user(u, p)
        if result.success:
            active_sessions[u] = result.session_token
            win.destroy()
            show_vote_screen(u, result.session_token)
        else:
            messagebox.showerror("Login Failed", result.message, parent=win)

    btn = tk.Button(frame, text="Login & Vote", command=do_login)
    tk_style_button(btn)
    btn.pack(fill="x")

    win.bind("<Return>", lambda e: do_login())


# ── Voting Screen ─────────────────────────────────────────────────────────────

def show_vote_screen(username: str, session_token: str):
    if get_election_status() != "ongoing":
        messagebox.showerror("Closed", "The election has ended. Voting is closed.")
        return

    win = tk.Toplevel(root)
    win.title("Cast Your Vote")
    win.configure(bg=BG)
    win.geometry("560x600")

    hdr = tk.Frame(win, bg=NAVY, pady=10)
    hdr.pack(fill="x")
    tk.Label(hdr, text=f"Welcome, {username.upper()} 🗳️",
             bg=NAVY, fg=WHITE, font=("Helvetica", 13, "bold")).pack()

    # Roll number gate
    roll = simpledialog.askstring("Verify Identity",
                                  "Enter your Roll Number to proceed:",
                                  parent=win)
    if not roll:
        win.destroy()
        return

    if has_voted(roll):
        log_event("DOUBLE_VOTE_ATTEMPT", username, f"Roll {roll} tried to vote again", "WARNING")
        messagebox.showerror("Already Voted",
                             "This roll number has already cast a vote.", parent=win)
        win.destroy()
        return

    body = tk.Frame(win, bg=BG, padx=24, pady=16)
    body.pack(fill="both", expand=True)

    tk.Label(body, text="Select your candidate", bg=BG, fg=NAVY,
             font=("Helvetica", 12, "bold")).pack(anchor="w", pady=(0, 12))

    voted = tk.BooleanVar(value=False)

    def do_vote(candidate):
        if voted.get():
            return
        confirm = messagebox.askyesno("Confirm Vote",
                                      f"You are voting for:\n\n  {candidate}\n\nThis action cannot be undone.",
                                      parent=win)
        if not confirm:
            return
        success = cast_vote(username, roll, candidate, session_token)
        if success:
            voted.set(True)
            log_event("VOTE_CAST", username, f"Roll {roll} voted for {candidate}", "INFO")
            # Trigger async anomaly check
            threading.Thread(target=run_full_analysis, daemon=True).start()
            messagebox.showinfo("✅ Vote Recorded",
                                f"Your vote for '{candidate}' has been securely recorded.\nThank you!",
                                parent=win)
            win.destroy()
            build_home()   # refresh stats
        else:
            messagebox.showerror("Error", "Failed to record vote. Please try again.", parent=win)

    for candidate in CANDIDATES:
        card = tk.Frame(body, bg=WHITE, bd=1, relief="solid", padx=16, pady=10)
        card.pack(fill="x", pady=5)
        left = tk.Frame(card, bg=WHITE)
        left.pack(side="left", fill="both", expand=True)
        tk.Label(left, text=candidate, bg=WHITE, fg=NAVY,
                 font=("Helvetica", 11, "bold")).pack(anchor="w")
        tk.Label(left, text=CANDIDATE_BIO.get(candidate, ""),
                 bg=WHITE, fg="#6B7280", font=("Helvetica", 8),
                 wraplength=380, justify="left").pack(anchor="w")
        btn = tk.Button(card, text="Vote ▶", command=lambda c=candidate: do_vote(c))
        tk_style_button(btn)
        btn.pack(side="right")


# ── Admin Login ───────────────────────────────────────────────────────────────

def show_admin_login():
    win = tk.Toplevel(root)
    win.title("Admin Login")
    win.configure(bg=BG)
    win.geometry("380x280")

    tk.Label(win, text="🛡️  Admin Login", bg=BG, fg=NAVY,
             font=("Helvetica", 14, "bold")).pack(pady=(20, 4))
    tk.Label(win, text="Authorised personnel only", bg=BG, fg="#6B7280",
             font=("Helvetica", 9)).pack(pady=(0, 16))

    frame = tk.Frame(win, bg=BG)
    frame.pack(padx=40)

    tk.Label(frame, text="Admin Username", bg=BG, fg=NAVY,
             font=("Helvetica", 9, "bold"), anchor="w").pack(fill="x")
    uname_e = tk.Entry(frame, font=("Helvetica", 10), relief="solid", bd=1)
    uname_e.pack(fill="x", pady=(2, 10))

    tk.Label(frame, text="Password", bg=BG, fg=NAVY,
             font=("Helvetica", 9, "bold"), anchor="w").pack(fill="x")
    pass_e = tk.Entry(frame, show="*", font=("Helvetica", 10), relief="solid", bd=1)
    pass_e.pack(fill="x", pady=(2, 14))

    def do_admin_login():
        u, p = uname_e.get().strip(), pass_e.get()
        result = authenticate_admin(u, p)
        if result.success:
            win.destroy()
            show_admin_dashboard(u)
        else:
            messagebox.showerror("Access Denied", result.message, parent=win)

    btn = tk.Button(frame, text="Access Dashboard", command=do_admin_login)
    tk_style_button(btn, NAVY)
    btn.pack(fill="x")
    win.bind("<Return>", lambda e: do_admin_login())


# ── Admin Dashboard ───────────────────────────────────────────────────────────

def show_admin_dashboard(admin_username: str):
    win = tk.Toplevel(root)
    win.title("Admin Dashboard — Election Control")
    win.configure(bg=BG)
    win.geometry("1080x740")

    # Header
    hdr = tk.Frame(win, bg=NAVY, pady=10)
    hdr.pack(fill="x")
    tk.Label(hdr, text="🛡️  Election Admin Dashboard",
             bg=NAVY, fg=WHITE, font=("Helvetica", 14, "bold")).pack(side="left", padx=16)
    tk.Label(hdr, text=f"Logged in as: {admin_username}",
             bg=NAVY, fg="#94A3B8", font=("Helvetica", 9)).pack(side="right", padx=16)

    # Notebook (tabs)
    nb = ttk.Notebook(win)
    nb.pack(fill="both", expand=True, padx=12, pady=12)

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TNotebook.Tab", font=("Helvetica", 10, "bold"),
                    padding=[12, 6], background="#D1D5DB", foreground=NAVY)
    style.map("TNotebook.Tab", background=[("selected", NAVY)],
              foreground=[("selected", WHITE)])

    # ── Tab 1: Overview ────────────────────────────────────────────────────────
    tab_overview = tk.Frame(nb, bg=BG)
    nb.add(tab_overview, text="📊 Overview")

    def build_overview():
        for w in tab_overview.winfo_children():
            w.destroy()

        # Run AI analysis in background
        analysis = run_full_analysis()

        # KPI strip
        kpi_frame = tk.Frame(tab_overview, bg=WHITE, pady=14)
        kpi_frame.pack(fill="x", padx=12, pady=(12, 8))

        vote_counts = get_vote_counts()
        winner = max(vote_counts, key=vote_counts.get) if vote_counts else "—"
        total = get_total_votes()
        score = analysis["integrity_score"]
        n_anomalies = analysis["total_anomalies"]

        for label, val, color in [
            ("Total Votes", str(total), TEAL),
            ("Leading Candidate", winner, NAVY),
            ("Integrity Score", f"{score}%", TEAL if score >= 90 else AMBER if score >= 70 else RED),
            ("Anomaly Alerts", str(n_anomalies), RED if n_anomalies > 0 else "#6B7280"),
        ]:
            col = tk.Frame(kpi_frame, bg=WHITE)
            col.pack(side="left", expand=True)
            tk.Label(col, text=val, bg=WHITE, fg=color,
                     font=("Helvetica", 20, "bold")).pack()
            tk.Label(col, text=label, bg=WHITE, fg="#6B7280",
                     font=("Helvetica", 8)).pack()

        # Integrity status banner
        status_color = TEAL if score >= 90 else AMBER if score >= 70 else RED
        banner = tk.Frame(tab_overview, bg=status_color, pady=6)
        banner.pack(fill="x", padx=12)
        tk.Label(banner,
                 text=f"Election Integrity Score: {score}%   |   {analysis['integrity_status']}",
                 bg=status_color, fg=WHITE, font=("Helvetica", 10, "bold")).pack()

        # Charts row
        charts_row = tk.Frame(tab_overview, bg=BG)
        charts_row.pack(fill="both", expand=True, padx=12, pady=8)

        left_chart = tk.Frame(charts_row, bg=WHITE, bd=1, relief="solid")
        left_chart.pack(side="left", fill="both", expand=True, padx=(0, 6))
        right_chart = tk.Frame(charts_row, bg=WHITE, bd=1, relief="solid")
        right_chart.pack(side="left", fill="both", expand=True, padx=(6, 0))

        try:
            from charts import vote_distribution_chart, vote_share_donut
            vote_distribution_chart(left_chart)
            vote_share_donut(right_chart)
        except Exception as e:
            tk.Label(left_chart, text=f"Chart error: {e}", bg=WHITE).pack(expand=True)

    build_overview()

    # ── Tab 2: Candidate Results ───────────────────────────────────────────────
    tab_results = tk.Frame(nb, bg=BG)
    nb.add(tab_results, text="🏆 Results")

    vote_counts = get_vote_counts()
    total = get_total_votes()

    res_frame = tk.Frame(tab_results, bg=BG)
    res_frame.pack(fill="both", expand=True, padx=24, pady=16)
    tk.Label(res_frame, text="Live Election Results", bg=BG, fg=NAVY,
             font=("Helvetica", 13, "bold")).pack(anchor="w", pady=(0, 12))

    cols = ("Candidate", "Votes", "Percentage", "Status")
    tree = ttk.Treeview(res_frame, columns=cols, show="headings", height=6)
    for col in cols:
        tree.heading(col, text=col)
        tree.column(col, anchor="center", width=180)

    max_v = max(vote_counts.values()) if vote_counts else 0
    for cand in CANDIDATES:
        cnt = vote_counts.get(cand, 0)
        pct = f"{cnt/total*100:.1f}%" if total > 0 else "0%"
        status = "🏆 LEADING" if cnt == max_v and max_v > 0 else ""
        tree.insert("", "end", values=(cand, cnt, pct, status))
    tree.pack(fill="both", expand=True)

    # Activity chart
    try:
        from charts import votes_over_time_chart
        chart_frame = tk.Frame(tab_results, bg=WHITE, bd=1, relief="solid")
        chart_frame.pack(fill="both", expand=True, padx=24, pady=8)
        votes_over_time_chart(chart_frame)
    except Exception:
        pass

    # ── Tab 3: AI Anomaly Detection ───────────────────────────────────────────
    tab_ai = tk.Frame(nb, bg=BG)
    nb.add(tab_ai, text="🤖 AI Anomaly Detection")

    ai_frame = tk.Frame(tab_ai, bg=BG)
    ai_frame.pack(fill="both", expand=True, padx=24, pady=12)

    tk.Label(ai_frame, text="AI Fraud Detection Log", bg=BG, fg=NAVY,
             font=("Helvetica", 12, "bold")).pack(anchor="w")
    tk.Label(ai_frame,
             text="Powered by Isolation Forest + Local Outlier Factor (scikit-learn)",
             bg=BG, fg="#6B7280", font=("Helvetica", 8)).pack(anchor="w", pady=(0, 8))

    a_cols = ("Timestamp", "Type", "User", "Risk Score", "Details")
    a_tree = ttk.Treeview(ai_frame, columns=a_cols, show="headings", height=10)
    a_tree.heading("Timestamp",  text="Detected At")
    a_tree.heading("Type",       text="Anomaly Type")
    a_tree.heading("User",       text="User")
    a_tree.heading("Risk Score", text="Risk Score")
    a_tree.heading("Details",    text="Details")
    a_tree.column("Timestamp",  width=140)
    a_tree.column("Type",       width=160)
    a_tree.column("User",       width=100)
    a_tree.column("Risk Score", width=90, anchor="center")
    a_tree.column("Details",    width=400)

    anomalies = get_anomaly_logs(limit=50)
    for a in anomalies:
        score_str = f"{a['anomaly_score']:.2f}" if a["anomaly_score"] else "—"
        tag = "high" if (a["anomaly_score"] or 0) >= 0.7 else "low"
        a_tree.insert("", "end", values=(
            a["detected_at"][:16], a["anomaly_type"],
            a["username"] or "—", score_str, a["details"] or ""
        ), tags=(tag,))

    a_tree.tag_configure("high", foreground=RED)
    a_tree.tag_configure("low",  foreground=AMBER)

    sb = ttk.Scrollbar(ai_frame, orient="vertical", command=a_tree.yview)
    a_tree.configure(yscrollcommand=sb.set)
    a_tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="left", fill="y")

    # Score chart
    try:
        from charts import anomaly_score_chart
        chart_f = tk.Frame(tab_ai, bg=WHITE, bd=1, relief="solid")
        chart_f.pack(fill="both", expand=True, padx=24, pady=(8, 12))
        anomaly_score_chart(chart_f)
    except Exception:
        pass

    def refresh_analysis():
        run_full_analysis()
        messagebox.showinfo("AI Analysis", "Anomaly detection complete. Reload dashboard to see updates.")

    btn_run = tk.Button(tab_ai, text="⚙  Run AI Analysis Now", command=refresh_analysis)
    tk_style_button(btn_run, NAVY)
    btn_run.pack(pady=8)

    # ── Tab 4: Audit Trail ────────────────────────────────────────────────────
    tab_audit = tk.Frame(nb, bg=BG)
    nb.add(tab_audit, text="📋 Audit Trail")

    aud_frame = tk.Frame(tab_audit, bg=BG)
    aud_frame.pack(fill="both", expand=True, padx=24, pady=12)
    tk.Label(aud_frame, text="Full Audit Trail", bg=BG, fg=NAVY,
             font=("Helvetica", 12, "bold")).pack(anchor="w", pady=(0, 8))

    l_cols = ("Timestamp", "Event", "User", "Severity", "Details")
    l_tree = ttk.Treeview(aud_frame, columns=l_cols, show="headings", height=20)
    for col, w in zip(l_cols, [140, 180, 100, 90, 400]):
        l_tree.heading(col, text=col)
        l_tree.column(col, width=w)

    logs = get_audit_logs(limit=200)
    for entry in logs:
        sev = entry["severity"]
        tag = "crit" if sev == "CRITICAL" else "warn" if sev == "WARNING" else "info"
        l_tree.insert("", "end", values=(
            entry["timestamp"][:16], entry["event_type"],
            entry["username"] or "—", sev, entry["details"] or ""
        ), tags=(tag,))

    l_tree.tag_configure("crit", foreground=RED)
    l_tree.tag_configure("warn", foreground=AMBER)
    l_tree.tag_configure("info", foreground="#059669")

    lsb = ttk.Scrollbar(aud_frame, orient="vertical", command=l_tree.yview)
    l_tree.configure(yscrollcommand=lsb.set)
    l_tree.pack(side="left", fill="both", expand=True)
    lsb.pack(side="left", fill="y")

    # ── Tab 5: Security & Charts ──────────────────────────────────────────────
    tab_sec = tk.Frame(nb, bg=BG)
    nb.add(tab_sec, text="🔐 Security Analytics")

    try:
        from charts import security_events_chart
        sec_chart_f = tk.Frame(tab_sec, bg=WHITE, bd=1, relief="solid")
        sec_chart_f.pack(fill="both", expand=True, padx=24, pady=12)
        security_events_chart(sec_chart_f)
    except Exception as e:
        tk.Label(tab_sec, text=f"Chart error: {e}", bg=BG).pack()

    # ── Control Bar ───────────────────────────────────────────────────────────
    ctrl_bar = tk.Frame(win, bg=NAVY, pady=8)
    ctrl_bar.pack(fill="x", side="bottom")

    election_status = get_election_status()

    def toggle_election():
        current = get_election_status()
        if current == "ongoing":
            if not messagebox.askyesno("End Election", "Are you sure you want to end the election?"):
                return
            set_election_status("ended")
            log_event("ELECTION_ENDED", admin_username, "Admin ended the election", "INFO")
            messagebox.showinfo("Done", "Election has been ended.")
        else:
            set_election_status("ongoing")
            log_event("ELECTION_REOPENED", admin_username, "Admin reopened the election", "WARNING")
            messagebox.showinfo("Done", "Election has been reopened.")
        build_home()
        win.destroy()

    def export_pdf():
        try:
            from reports import generate_report
            path = generate_report()
            messagebox.showinfo("Report Exported", f"PDF report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    end_label = "🛑  End Election" if election_status == "ongoing" else "▶  Reopen Election"
    end_color = RED if election_status == "ongoing" else TEAL

    btn_toggle = tk.Button(ctrl_bar, text=end_label, command=toggle_election)
    tk_style_button(btn_toggle, end_color)
    btn_toggle.pack(side="left", padx=16)

    btn_export = tk.Button(ctrl_bar, text="📄  Export PDF Report", command=export_pdf)
    tk_style_button(btn_export, AMBER)
    btn_export["fg"] = NAVY
    btn_export.pack(side="left", padx=8)

    btn_refresh = tk.Button(ctrl_bar, text="🔄  Refresh Dashboard",
                            command=lambda: [win.destroy(), show_admin_dashboard(admin_username)])
    tk_style_button(btn_refresh, "#6B7280")
    btn_refresh.pack(side="right", padx=16)


# ── Launch ────────────────────────────────────────────────────────────────────
build_home()
log_event("APP_STARTED", "system", "Voting system launched", "INFO")
root.mainloop()
