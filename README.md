# CyberSentinel Suite

A collection of four standalone, interactive simulators built to demonstrate common cyberattack patterns and their corresponding detection/mitigation strategies. Each module runs independently and is designed for hands-on learning in a safe, sandboxed environment.

## Overview

| Module | Path | Description | Stack |
|--------|------|-------------|-------|
| **NetShield** | `Mini-Project/DdosDos/` | DoS/DDoS attack and mitigation simulator with live traffic charts | HTML, CSS, JavaScript |
| **NexaBank / SQLiWATCH** | `Mini-Project/sql_injection/` | SQL injection lab with a vulnerable banking UI and real-time threat monitor | HTML, CSS, JavaScript, BroadcastChannel |
| **RansomWatch** | `Mini-Project/ransomware-simulator/ransomware-simulator/` | Ransomware attack simulator with a detection engine and virtual file system | Python (Flask), React, Socket.IO |
| **Phishing Detector** | `Mini-Project/Phishing/` | URL scoring engine using heuristics and an optional VirusTotal API lookup, with a Chrome extension and dashboard | Python (Flask), Chrome Extension (MV3) |

## Quick Start (Windows)

Launch all four modules at once:

```bat
Mini-Project\start_all_projects.bat
```

This will open:

| Module | What Opens |
|--------|------------|
| NetShield | `DdosDos/index.html` in your default browser |
| SQLiWATCH | `sql_injection/dashboard.html` in your default browser |
| RansomWatch | Backend + frontend via `start.bat` (ports 5001 and 3000) |
| Phishing Detector | Flask server via `start.bat` (port 5000) |

## Prerequisites

| Requirement | Required For |
|-------------|---------------|
| Modern web browser (Chrome recommended) | All modules |
| Python 3.9+ | RansomWatch, Phishing Detector |
| Node.js 18+ and npm 9+ | RansomWatch frontend |
| Windows + PowerShell | `.bat` / `.ps1` launch scripts (optional) |
| VirusTotal API key (optional) | Enhanced phishing detection |
| Google Chrome | Phishing extension, optional Selenium script |

> Pre-bundled environments (`venv/`, `env/`, `node_modules/`) may already exist in the repo. If a launch fails, reinstall dependencies using the steps below.

## Running Each Module

### 1. NetShield — DoS/DDoS Simulation

**Path:** `Mini-Project/DdosDos/`

Open `index.html` in a browser, or use the all-in-one `netshield-dashboard.html`. Configure the attack type (SYN flood, UDP flood, HTTP flood, ICMP, Slowloris), packet rate, and botnet size, then toggle defenses on or off. Launch a DoS or DDoS simulation and observe traffic metrics update in real time.

No server or installation required.

### 2. NexaBank / SQLiWATCH — SQL Injection Lab

**Path:** `Mini-Project/sql_injection/`

1. Open `dashboard.html` — the SQLiWATCH threat monitor (recommended entry point).
2. Open the attack surfaces in separate tabs:
   - `index.html` — login form
   - `search.html` — account search
   - `profile.html` — profile lookup

Toggle between **Vulnerable** and **Secure** modes on the app pages, submit SQL payloads, and watch live queries and alerts appear on the dashboard. An auto-attack simulator is included for demonstration.

No server or installation required.

### 3. RansomWatch — Ransomware Detection Simulator

**Path:** `Mini-Project/ransomware-simulator/ransomware-simulator/`

**Quick start:**

```bat
cd Mini-Project\ransomware-simulator\ransomware-simulator
start.bat
```

**Manual setup:**

```bat
:: Backend (port 5001)
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py

:: Frontend (port 3000) — run in a separate terminal
cd frontend
npm install
npm start
```

Open [http://localhost:3000](http://localhost:3000), enable the monitor, select a ransomware variant (WannaCry, Locky, REvil, Petya), launch an attack, and observe detection alerts against the virtual file system.

Full API documentation and troubleshooting steps are available in the [RansomWatch README](Mini-Project/ransomware-simulator/ransomware-simulator/README.md).

### 4. Phishing URL Detector

**Path:** `Mini-Project/Phishing/`

**Quick start:**

```bat
cd Mini-Project\Phishing
start.bat
```

**Manual fallback:**

```bat
python app.py


Open [http://localhost:5000](http://localhost:5000) for the dashboard, or open `index.html` for the standalone UI (the backend must be running).

**One-time setup:** save a VirusTotal API key in the dashboard UI; it persists in `Phishing/config.json`.

**Chrome extension:** load the `Phishing/` folder as an unpacked extension via `chrome://extensions`.

Additional details are available in the [Phishing README](Mini-Project/Phishing/README.md).

## Port Summary

| Module | Port(s) |
|--------|---------|
| Phishing Detector | `5000` |
| RansomWatch backend | `5001` |
| RansomWatch frontend | `3000` |
| NetShield | None (static files) |
| SQLiWATCH | None (static files) |

## Project Structure


CyberSentinel-Suite/
└── Mini-Project/
    ├── start_all_projects.bat
    ├── DdosDos/                        # NetShield — DoS/DDoS simulator
    ├── sql_injection/                  # NexaBank + SQLiWATCH monitor
    ├── ransomware-simulator/
    │   └── ransomware-simulator/       # RansomWatch (Flask + React)
    ├── Phishing/                       # Phishing URL detector
    └── logs/                           # Shared URL logs (Phishing module)


## Learning Objectives

- **DoS/DDoS** — Understand attack patterns, traffic spikes, and mitigation strategies such as rate limiting, firewalls, and CDNs.
- **SQL Injection** — Recognize vulnerable query construction, common injection types (UNION-based, blind, authentication bypass), and the role of prepared statements.
- **Ransomware** — Observe encryption behavior, entropy analysis, honeypot triggers, and incident response workflows.
- **Phishing** — Analyze suspicious URLs using heuristics and threat intelligence APIs.

## License & Use

This project is intended for academic and educational use only. Use responsibly and exclusively in authorized environments.
