# 🗳️ AI-Powered Secure Voting System with Anomaly Detection & Fraud Prevention


> A production-grade secure electronic voting platform demonstrating AI-powered fraud detection, cryptographic security, SQLite database management, real-time analytics, and automated PDF reporting.

---

## 📌 Project Overview

This project began as a basic Tkinter voting application and was systematically upgraded into an enterprise-grade secure voting platform. The system now integrates:

- **Machine Learning** (scikit-learn Isolation Forest + Local Outlier Factor) for anomaly detection
- **Cryptographic Security** (bcrypt hashing, session tokens, account lockout)
- **Relational Database** (SQLite with 6 normalised tables)
- **Data Visualisation** (Matplotlib + Seaborn charts embedded in Tkinter)
- **PDF Reporting** (ReportLab-generated audit reports)
- **Complete Audit Trail** with severity-tiered logging

---

## 🧠 AI/ML Architecture

### Anomaly Detection Pipeline

```
Raw Vote Events
      │
      ▼
Feature Engineering
  ├── hour_of_day
  ├── seconds_since_last_vote  (inter-arrival time)
  ├── votes_last_5min           (rolling window count)
  └── candidate_entropy         (running Shannon entropy)
      │
      ▼
 ┌─────────────┐    ┌─────────────────────────┐
 │ Isolation   │    │  Local Outlier Factor   │
 │ Forest      │    │  (density-based, k=20)  │
 │ (200 trees) │    │                         │
 └─────┬───────┘    └──────────┬──────────────┘
       │                       │
       └─────── Combined ──────┘
                Score > 0.6
                    │
                    ▼
           Log to anomaly_logs
           Update integrity score
```

### Rule-Based Heuristics (Deterministic Layer)
| Rule | Trigger | Risk Score |
|------|---------|-----------|
| Rapid successive votes | < 5 seconds between votes | 0.95 |
| Vote spike | ≥ 7/10 recent votes for one candidate | 0.80 |
| Off-hours voting | Outside 08:00–20:00 | 0.60 |
| Brute-force login | ≥ 3 failed attempts | 0.50–0.99 |

### Election Integrity Score
```
Integrity Score = max(0, 100 - (anomaly_count / total_votes) × 200)

✅ ≥ 90% → Normal
⚠️ 70–89% → Mild Concerns
🔶 50–69% → Suspicious Activity
🚨 < 50% → HIGH RISK
```

---

## 🔐 Security Features

| Feature | Implementation |
|---------|---------------|
| Password hashing | bcrypt (cost factor 12) |
| Account lockout | 5 failed attempts → 15-minute lockout |
| Session tokens | `secrets.token_hex(32)` (256-bit entropy) |
| Vote integrity | SHA-256 fingerprint per vote record |
| Audit trail | Every action logged with timestamp + severity |
| Role-based access | Separate user/admin auth flows |
| Duplicate vote prevention | Roll number unique constraint in SQLite |

---

## 🗄️ Database Schema

```sql
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   users     │     │   admins    │     │    votes    │
│─────────────│     │─────────────│     │─────────────│
│ id (PK)     │     │ id (PK)     │     │ id (PK)     │
│ username    │──┐  │ username    │     │ username FK │
│ password_   │  │  │ password_   │     │ roll_number │
│   hash      │  │  │   hash      │     │ candidate   │
│ roll_number │  │  │ created_at  │     │ voted_at    │
│ failed_     │  │  └─────────────┘     │ ip_hash     │
│   attempts  │  │                      │ session_    │
│ locked_     │  └──────────────────────│   token     │
│   until     │                         └─────────────┘
└─────────────┘
┌──────────────┐     ┌──────────────┐     ┌─────────────────┐
│  audit_logs  │     │ anomaly_logs │     │ election_config │
│──────────────│     │──────────────│     │─────────────────│
│ id (PK)      │     │ id (PK)      │     │ key (PK)        │
│ event_type   │     │ anomaly_type │     │ value           │
│ username     │     │ username     │     └─────────────────┘
│ details      │     │ anomaly_score│
│ severity     │     │ details      │
│ timestamp    │     │ flagged      │
└──────────────┘     │ detected_at  │
                     └──────────────┘
```

---

## 📊 Dashboard Features

The Admin Dashboard contains 5 sections:

1. **Overview** — KPIs (total votes, leading candidate, integrity score, anomaly alerts) + bar chart + donut chart
2. **Results** — Candidate leaderboard table + votes-over-time line chart
3. **AI Anomaly Detection** — Flagged events table with risk scores + histogram of anomaly score distribution
4. **Audit Trail** — Searchable, colour-coded log of every system event
5. **Security Analytics** — Security event severity distribution chart

---

## 🚀 Getting Started

### Prerequisites
```bash
pip install bcrypt passlib scikit-learn matplotlib seaborn pandas numpy reportlab
```

### Run
```bash
cd voting_system
python voting_machine.py
```

### Default Credentials
| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | `Admin@2024!` |
| Voter | `voter1` | `Voter@123` |
| Voter | `voter2` | `Voter@456` |

> ⚠️ Change all default credentials immediately in production.

---

## 📁 Project Structure

```
voting_system/
├── voting_machine.py      # Main application (extended original)
├── database.py            # SQLite layer — all CRUD operations
├── security.py            # bcrypt, session tokens, account lockout
├── anomaly_detection.py   # Isolation Forest + LOF + rule-based checks
├── charts.py              # Matplotlib/Seaborn dashboard visualisations
├── reports.py             # ReportLab PDF report generation
├── voting_system.db       # SQLite database (auto-created)
└── README.md
```

---

## 📄 Sample PDF Report

The system exports a comprehensive PDF including:
- Election integrity score
- Vote distribution table with percentages
- All anomaly alerts with risk scores
- Full audit trail (last 20 entries)
- Methodology footnote

Export via Admin Dashboard → **Export PDF Report** button.



## 🔧 Technologies Used

| Category | Technology |
|----------|-----------|
| Language | Python 3.10+ |
| GUI | Tkinter |
| Database | SQLite3 |
| Security | bcrypt, secrets, hashlib |
| ML/AI | scikit-learn (IsolationForest, LOF) |
| Data | pandas, numpy |
| Visualisation | Matplotlib, Seaborn |
| Reporting | ReportLab |

---
