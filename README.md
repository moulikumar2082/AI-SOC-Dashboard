# AI-Powered Security Operations Center (SOC) Dashboard 🛡️

A production-ready, dark-themed **AI-Powered Security Operations Center (SOC) Dashboard** built with Python 3.12+, Flask, SQLAlchemy, SQLite, Flask-Login, Bootstrap 5, Chart.js, ReportLab, and OpenAI API / Local AI integration.

---

## 🌟 Key Features

1. **User Authentication & Role-Based Access Control (RBAC)**
   - Secure Registration, Login, Logout, and Session Management.
   - Role-based permissions (`Admin`, `Analyst`, `User`) enforcing administrative boundaries.
   - `Werkzeug` secure password hashing.

2. **Real-Time Cyber SOC Dashboard**
   - KPI metric counters for Total Logs, Critical, High, Medium, Low Alerts, and Active Incidents.
   - Interactive **Chart.js** visualizers:
     - **Severity Distribution** (Doughnut chart)
     - **Attack Types** (Bar chart)
     - **Daily Alert Volume** (Line trend chart)
     - **Top Source IPs** (Horizontal Bar chart)
   - Recent suspicious security telemetry alert feeds and active incident triage cards.

3. **Automated Threat Detection Engine**
   - Ingests and parses `.txt`, `.log`, and `.csv` files.
   - Rule-based detection rules for:
     - **SQL Injection (SQLi)**
     - **Cross-Site Scripting (XSS)**
     - **Brute Force & Password Spraying**
     - **Port Scanning & Network Reconnaissance**
     - **Malware C2 Beaconing & Executable Payloads**
     - **Suspicious Admin Logins & Anomaly Activity**
     - **Excessive Failed Logins**
   - Automated calculation of **Risk Score (0–100)**, **Severity**, and **MITRE ATT&CK Technique** mapping.

4. **AI Threat Analyzer**
   - Integrates with **OpenAI API** (`gpt-4o-mini` / `gpt-4o`) or local Ollama endpoints.
   - Generates structured JSON threat intelligence:
     - **Executive Threat Summary**
     - **Plain-Language Technical Explanation**
     - **MITRE ATT&CK Technique Mapping**
     - **Step-by-Step Remediation Guidance**
   - Includes a deterministic **Offline Fallback AI Engine** ensuring 100% operational functionality without external API keys!

5. **Incident Operations & Triage Workflow**
   - Create incidents manually or directly convert suspicious log events into active cases.
   - Priority levels (`Critical`, `High`, `Medium`, `Low`).
   - Status workflow transitions (`Open`, `In Progress`, `Resolved`, `Closed`).
   - Analyst assignment and interactive investigation timeline notes.

6. **Executive PDF Security Reports**
   - Built using **ReportLab** with custom cyber SOC branding.
   - Export options:
     - **Daily Summary (24h Alert Telemetry)**
     - **Weekly Summary (7-day Trend Analysis)**
     - **Incident Report (Active Triage Cases)**
     - **Attack Statistics (Vector Breakdown)**

7. **Admin Control Panel**
   - User account provisioning and role updates (`Admin`, `Analyst`, `User`).
   - Account activation / deactivation toggle.
   - System log purge and database maintenance operations.

---

## 🛠️ Tech Stack

- **Backend Framework**: Python 3.12+, Flask
- **Database & ORM**: SQLite 3, Flask-SQLAlchemy
- **Session & Auth**: Flask-Login, Werkzeug Security, Flask-WTF (CSRF Protection)
- **Frontend & Styling**: HTML5, Vanilla CSS3 (Custom Dark Cyber Theme), Bootstrap 5, FontAwesome 6
- **Data Visualizations**: Chart.js 4
- **PDF Generation**: ReportLab
- **AI Engine**: OpenAI API Python SDK + Offline Heuristic Fallback
- **Environment Management**: python-dotenv

---

## 📁 Project Directory Structure

```
AI-Powered-SOC-Dashboard/
│
├── app/
│   ├── __init__.py            # Application Factory (create_app)
│   ├── config.py              # Configuration & Environment loading
│   ├── models/                # SQLAlchemy ORM Data Models
│   │   ├── __init__.py
│   │   ├── user.py            # User model & RBAC
│   │   ├── log.py             # Security Log model
│   │   └── incident.py        # Incident model
│   ├── routes/                # Blueprint Route Handlers
│   │   ├── __init__.py
│   │   ├── auth.py            # Login, Register, Logout
│   │   ├── main.py            # Dashboard overview & Chart APIs
│   │   ├── logs.py            # Log listing, Upload, & Detail views
│   │   ├── incidents.py       # Incident creation & timeline notes
│   │   ├── reports.py         # PDF Report generation & downloads
│   │   ├── ai.py              # Dynamic AI threat analysis endpoint
│   │   └── admin.py           # Admin panel for user management
│   ├── services/              # Domain Logic & Engine Services
│   │   ├── __init__.py
│   │   ├── log_parser.py      # Automated Threat Detection Engine
│   │   ├── ai_analyzer.py     # OpenAI API + Fallback AI Analyzer
│   │   └── report_generator.py # ReportLab PDF Generator
│   ├── templates/             # Jinja2 Layouts & Views
│   │   ├── base.html          # Cyber SOC master layout & modals
│   │   ├── auth/              # login.html, register.html, profile.html
│   │   ├── dashboard/         # index.html
│   │   ├── logs/              # list.html, upload.html, detail.html
│   │   ├── incidents/         # list.html, create.html, detail.html
│   │   ├── reports/           # list.html
│   │   ├── admin/             # users.html
│   │   └── errors/            # 404.html, 500.html
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css      # Dark Cybersecurity Theme
│   │   ├── js/
│   │   │   └── dashboard.js   # Chart.js initialization & AI modal scripts
│   │   └── images/
│   └── utils/
│       ├── __init__.py
│       ├── decorators.py      # RBAC decorators (@admin_required, @analyst_required)
│       └── sample_data.py     # Automatic database startup seeder
│
├── uploads/                   # Ingested log file storage
├── reports/                   # Generated PDF report archive
├── .env.example               # Environment variables template
├── requirements.txt           # Dependency manifest
├── run.py                     # Entry point application script
└── README.md                  # Project Documentation
```

---

## ⚡ Quick Start & Installation

### 1. Clone or Open Workspace
```bash
cd AI-SOC-Dashboard
```

### 2. Set Up Virtual Environment & Dependencies
```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment (Linux/macOS)
source .venv/bin/activate

# On Windows:
# .venv\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
*(Optional)* Add your `OPENAI_API_KEY` to `.env` for live OpenAI GPT model queries. If omitted, the application automatically uses the offline AI threat engine.

### 4. Launch Application
```bash
python run.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000/`**

---

## 🔑 Default Credentials (Pre-seeded Demo Accounts)

The database automatically seeds realistic attack telemetry, incidents, and accounts on initial launch:

| Role | Username | Password | Email | Access |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `Admin@123` | `admin@soc.internal` | Full System & Admin Control |
| **Security Analyst** | `analyst` | `Analyst@123` | `analyst@soc.internal` | Logs, AI, Incidents, Reports |
| **Standard User** | `user` | `User@123` | `user@soc.internal` | View Dashboard |

---

## 🔒 Security Best Practices Implemented

- **CSRF Protection**: All HTML forms and AJAX requests are validated using `Flask-WTF` CSRF tokens.
- **ORM Parameterization**: All database operations use `SQLAlchemy ORM`, completely eliminating SQL injection risks.
- **Password Hashing**: User passwords are stored as PBKDF2 / Werkzeug salted hashes.
- **Secure Upload Handling**: Strict filename sanitization (`secure_filename`) and extension validation (`.txt`, `.log`, `.csv`).
- **Role-Based Access Control (RBAC)**: Custom Flask decorators (`@admin_required`, `@analyst_required`) restrict critical administrative routes.

---

## 🚀 Future Enhancements Roadmap

- [ ] Real-time WebSocket syslog streaming ingestion (WebSockets / Server-Sent Events).
- [ ] Integration with ElasticSearch / OpenSearch for multi-terabyte log indexing.
- [ ] Automated Firewall shunning & SOAR playbook webhooks (AWS Security Hub, IPTables, Cloudflare WAF).
- [ ] Interactive 3D Cyber Threat Map visualizer.
