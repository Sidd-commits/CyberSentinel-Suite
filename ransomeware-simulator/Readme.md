# 🔐 RansomWatch — Ransomware Detection Simulator
### College Mini Project | Cybersecurity | Educational Use Only

---

## ⚠️ DISCLAIMER
This project is **strictly for educational purposes**. It simulates ransomware behavior in memory only — no actual files are encrypted on your system. All file operations are virtual/simulated.

---



## 🚀 STEP-BY-STEP SETUP GUIDE

### Quick Start (Recommended)

From the project root (`ransomware-simulator/ransomware-simulator`), run:

```bash
start.bat
```

This will:
- Stop old processes using ports `5001` (backend) and `3000` (frontend)
- Start backend and frontend in separate terminals automatically

### PREREQUISITES — Install These First

| Tool | Version | Download |
|------|---------|----------|
| Python | 3.9+ | https://python.org |
| Node.js | 18+ | https://nodejs.org |
| npm | 9+ | (comes with Node.js) |

---

### STEP 1 — Clone / Extract Project

If you downloaded a ZIP:
```bash
unzip ransomware-simulator.zip
cd ransomware-simulator
```

---

### STEP 2 — Set Up the Backend (Flask)

Open a terminal and run:

```bash
# Navigate to backend folder
cd ransomware-simulator/backend

# (Recommended) Create a virtual environment
python -m venv venv

# Activate it:
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install all Python dependencies
pip install -r requirements.txt
```

**Start the backend server:**
```bash
python app.py
```

✅ You should see:
```
 * Running on http://0.0.0.0:5001
```

Keep this terminal open. The backend runs on **port 5001**.

---

### STEP 3 — Set Up the Frontend (React)

Open a **NEW terminal window** (keep the backend running):

```bash
# Navigate to frontend folder
cd ransomware-simulator/frontend

# Install Node.js packages (first time only, takes ~2 min)
npm install

# Start the React development server
npm start
```

✅ A browser should auto-open at **http://localhost:3000**

If it doesn't open automatically, go to: **http://localhost:3000**

---

### STEP 4 — Verify Connection

In the app's top-right corner you should see a green **● LIVE** badge.
If it shows "OFFLINE", make sure your Flask backend is still running.

---

## 🎮 HOW TO USE THE SIMULATOR

### Step A — Enable the Monitor (Optional but recommended)
1. In the **Detection Engine** panel (bottom-left), click **"🛡 ENABLE MONITOR"**
2. Choose sensitivity: **Low** (detects late), **Medium** (balanced), **High** (detects early)

### Step B — Select Attack Variant
In the **Attack Simulator** panel, choose one of:
- **WannaCry** — Fast SMB-based attack, medium ransom
- **Locky** — Macro-based phishing variant, medium-high ransom
- **REvil** — Enterprise-targeted, very high ransom (ransomware-as-a-service)
- **Petya/NotPetya** — MBR-overwriting cyberweapon variant

### Step C — Launch Attack
Click **⚡ LAUNCH ATTACK**

Watch in real time:
- **File System** panel: files turning red 🔒 as they get "encrypted"
- **Alert Feed**: detection alerts appearing
- **Activity Log**: detailed timestamped events
- **Threat Score gauge**: rising from 0-100%

### Step D — Post-Attack
After all files are encrypted, a **Ransom Note** modal appears automatically.
It shows the simulated Bitcoin wallet, ransom amount, and deadline.

### Step E — Reset
Click **↺ RESET SIMULATION** to restore all files and start over.

---

## 🔬 FEATURES OVERVIEW

| Feature | Description |
|---------|-------------|
| 4 Ransomware Variants | WannaCry, Locky, REvil, Petya with unique behaviors |
| Simulated File System | 12 virtual files (documents, databases, photos, etc.) |
| Real-time Encryption | Files visually lock one by one with progress tracking |
| Entropy Detection | Simulates Shannon entropy analysis on file writes |
| Honeypot Detection | Decoy file triggers early alert |
| SMB Network Scanning | WannaCry/Petya simulate LAN port scanning |
| Process Monitoring | Malicious process names shown as they're "spawned" |
| WebSocket Live Feed | All events pushed in real-time via Socket.IO |
| Threat Score Gauge | Canvas-drawn threat level meter (0-100%) |
| Ransom Note Modal | Authentic-looking ransom notes per variant |
| Detection Rules | 5 behavioral rules: entropy, mass encryption, honeypot, etc. |
| Adjustable Sensitivity | Controls how many files trigger detection |
| Grid/List View | Toggle between icon grid and detailed list view |
| File Content Preview | Click any file to see its (simulated) content |
| Activity Log | Timestamped colored log of all events |

---

## 🛠️ TECH STACK

**Backend:**
- Python 3.x
- Flask (REST API)
- Flask-SocketIO (WebSocket real-time communication)
- Flask-CORS (Cross-origin requests)

**Frontend:**
- React 18 (component-based UI)
- Socket.IO Client (real-time events)
- Axios (HTTP requests)
- HTML5 Canvas (threat gauge)
- CSS3 (custom dark cyberpunk theme)

**Communication:**
- REST API: GET/POST endpoints for state management
- WebSocket: Real-time push events for file encryption, alerts, logs

---

## 🔌 API ENDPOINTS

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/status | Full current state |
| GET | /api/files | All simulated files |
| GET | /api/logs | Activity log entries |
| GET | /api/variants | Available ransomware variants |
| POST | /api/attack/start | Start attack `{"variant": "WannaCry"}` |
| POST | /api/attack/stop | Stop running attack |
| POST | /api/attack/reset | Reset entire simulation |
| POST | /api/monitor/toggle | Toggle/configure monitor |

**WebSocket Events (Server → Client):**
- `attack_state` — Full attack state update
- `file_encrypted` — Single file was encrypted
- `log_entry` — New log line
- `alert` — New security alert
- `ransomware_detected` — Detection triggered
- `attack_completed` — All files done
- `reset` — Simulation was reset
- `monitor_update` — Monitoring state changed

---

## ❓ TROUBLESHOOTING

**"Module not found" errors in Python:**
```bash
pip install flask flask-cors flask-socketio eventlet
```

**"OFFLINE" badge in browser:**
- Make sure `python app.py` is running in a separate terminal
- Check that port 5001 is not blocked by firewall

**"npm install" fails:**
- Make sure Node.js 18+ is installed: `node --version`
- Try: `npm install --legacy-peer-deps`

**Port already in use:**
- Flask: Change port in `app.py` last line: `socketio.run(app, port=5001)`
- React: It will ask to use another port automatically

**CORS errors in browser console:**
- Make sure Flask is running before starting React
- Check that proxy in `package.json` matches Flask port

---

## 📊 PROJECT COMPONENTS EXPLAINED (For Report)

### 1. Attack Engine (app.py)
The core simulation runs in a background thread using Python's `threading` module. Each variant has configurable speed, ransom amount, file extension, and network behavior. Files are "encrypted" by base64-encoding their content and reversing it — purely symbolic, not real encryption.

### 2. Detection Engine
The monitor tracks:
- **Entropy anomaly**: Files with >6.5 bits/byte (random-looking) trigger alerts
- **Honeypot**: A decoy file is monitored; accessing it triggers immediate detection
- **Mass modification**: Bulk file changes in short time window
- **Sensitivity control**: Changes how many files must be encrypted before detection fires

### 3. Real-time Communication
Flask-SocketIO broadcasts events to all connected React clients via WebSocket. This eliminates polling and provides instant UI updates when files are encrypted.

### 4. Frontend Architecture
React components are organized by responsibility: AttackPanel controls the simulation, FileSystem visualizes file state, MonitorPanel shows detection metrics, and AlertFeed/ActivityLog provide audit trails.

---

*Built for cybersecurity education — understand attacks to build better defenses.*
