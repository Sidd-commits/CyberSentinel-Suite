from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import time
import random
import threading
import hashlib
import base64
import json
from datetime import datetime
from collections import deque

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ransomware-sim-secret'
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ─────────────────────────────────────────────
# Simulated File System State
# ─────────────────────────────────────────────
SIMULATED_FILES = [
    {"id": "f1",  "name": "thesis_final.docx",      "path": "/Documents/thesis_final.docx",       "size": 245760,  "type": "document", "encrypted": False, "content": "Important thesis document with years of research..."},
    {"id": "f2",  "name": "family_photos.zip",       "path": "/Pictures/family_photos.zip",         "size": 15728640,"type": "image",    "encrypted": False, "content": "Precious family memories and photos..."},
    {"id": "f3",  "name": "salary_data.xlsx",        "path": "/Documents/salary_data.xlsx",         "size": 98304,   "type": "spreadsheet","encrypted": False,"content": "Confidential salary and financial records..."},
    {"id": "f4",  "name": "passwords.txt",           "path": "/Desktop/passwords.txt",              "size": 2048,    "type": "text",     "encrypted": False, "content": "admin:password123, bank:secure456..."},
    {"id": "f5",  "name": "project_source.zip",      "path": "/Projects/project_source.zip",        "size": 5242880, "type": "code",     "encrypted": False, "content": "Source code for main project..."},
    {"id": "f6",  "name": "client_database.sql",     "path": "/Database/client_database.sql",       "size": 3145728, "type": "database", "encrypted": False, "content": "Full client records and personal data..."},
    {"id": "f7",  "name": "annual_report.pdf",       "path": "/Documents/annual_report.pdf",        "size": 1048576, "type": "document", "encrypted": False, "content": "Company annual report with financials..."},
    {"id": "f8",  "name": "encryption_keys.pem",     "path": "/System/encryption_keys.pem",         "size": 4096,    "type": "security", "encrypted": False, "content": "Private encryption keys for system..."},
    {"id": "f9",  "name": "backup_2024.tar.gz",      "path": "/Backups/backup_2024.tar.gz",         "size": 20971520,"type": "backup",   "encrypted": False, "content": "System backup archive..."},
    {"id": "f10", "name": "medical_records.pdf",     "path": "/Health/medical_records.pdf",         "size": 512000,  "type": "document", "encrypted": False, "content": "Personal medical history and records..."},
    {"id": "f11", "name": "tax_returns_2023.xlsx",   "path": "/Finance/tax_returns_2023.xlsx",      "size": 163840,  "type": "spreadsheet","encrypted": False,"content": "Tax filing documents for 2023..."},
    {"id": "f12", "name": "vacation_video.mp4",     "path": "/Videos/vacation_video.mp4",          "size": 524288000,"type":"video",    "encrypted": False, "content": "Vacation memories captured on video..."},
]

# Attack state
attack_state = {
    "status": "idle",          # idle | scanning | encrypting | completed | detected | stopped
    "variant": "WannaCry",
    "progress": 0,
    "files_encrypted": 0,
    "files_total": len(SIMULATED_FILES),
    "start_time": None,
    "encryption_key": None,
    "ransom_amount": 0,
    "bitcoin_address": "",
    "detection_triggered": False,
    "alerts": [],
    "current_file": None,
    "encrypted_files": [],
    "attack_log": [],
    "scan_phase_done": False,
    "network_connections": [],
    "processes_spawned": [],
}

files_state = [dict(f) for f in SIMULATED_FILES]

monitor_state = {
    "active": False,
    "sensitivity": "medium",
    "alerts_count": 0,
    "rules_triggered": [],
    "file_ops_per_second": 0,
    "entropy_scores": {},
    "detection_score": 0,
}

activity_log = deque(maxlen=200)
stop_attack_flag = threading.Event()
attack_thread = None


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def timestamp():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def fake_encrypt(content: str) -> str:
    """Simulate encryption by base64-encoding + scrambling."""
    encoded = base64.b64encode(content.encode()).decode()
    scrambled = encoded[::-1]
    return f"ENCRYPTED:{scrambled}==RANSOMWARE_LOCKED"


def generate_bitcoin_address():
    chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return "1" + "".join(random.choices(chars, k=33))


def generate_key():
    return hashlib.sha256(str(time.time()).encode()).hexdigest().upper()


def add_log(event_type, message, severity="info", file_id=None):
    entry = {
        "id": f"log_{int(time.time()*1000)}_{random.randint(100,999)}",
        "timestamp": timestamp(),
        "type": event_type,
        "message": message,
        "severity": severity,
        "file_id": file_id,
    }
    activity_log.appendleft(entry)
    socketio.emit("log_entry", entry)
    return entry


def add_alert(title, detail, severity="high"):
    alert = {
        "id": f"alert_{int(time.time()*1000)}",
        "timestamp": timestamp(),
        "title": title,
        "detail": detail,
        "severity": severity,
    }
    attack_state["alerts"].append(alert)
    monitor_state["alerts_count"] += 1
    socketio.emit("alert", alert)
    return alert


VARIANT_CONFIG = {
    "WannaCry": {
        "speed_range": (0.6, 1.2),
        "ransom_range": (300, 600),
        "extension": ".WNCRY",
        "note": "Ooops, your files have been encrypted!\nYou have 3 days to pay the ransom.\nAfter that, the price will be doubled.",
        "scan_delay": 2,
        "uses_smb": True,
        "drops_processes": ["tasksche.exe", "mssecsvc.exe", "@WanaDecryptor@.exe"],
    },
    "Locky": {
        "speed_range": (0.3, 0.8),
        "ransom_range": (500, 1000),
        "extension": ".locky",
        "note": "YOUR FILES ARE ENCRYPTED!\nSend 0.5 BTC to recover them.",
        "scan_delay": 1.5,
        "uses_smb": False,
        "drops_processes": ["svchost_locky.exe", "locky_decrypt.exe"],
    },
    "REvil": {
        "speed_range": (0.2, 0.5),
        "ransom_range": (5000, 50000),
        "extension": ".revil",
        "note": "Your network has been compromised.\nAll files encrypted with military-grade AES-256.\nContact us within 72 hours.",
        "scan_delay": 3,
        "uses_smb": True,
        "drops_processes": ["agent.exe", "revil_service.exe", "data_exfil.exe"],
    },
    "Petya": {
        "speed_range": (0.4, 0.9),
        "ransom_range": (300, 500),
        "extension": ".petya",
        "note": "OOPS! YOUR IMPORTANT FILES ARE ENCRYPTED.\nYou can only recover files by purchasing decryption key.",
        "scan_delay": 2.5,
        "uses_smb": True,
        "drops_processes": ["perfc.dat", "petya_enc.exe"],
    },
}


# ─────────────────────────────────────────────
# Attack Simulation Thread
# ─────────────────────────────────────────────
def run_attack_simulation(variant):
    global files_state
    config = VARIANT_CONFIG.get(variant, VARIANT_CONFIG["WannaCry"])
    stop_attack_flag.clear()

    # Reset files
    files_state = [dict(f) for f in SIMULATED_FILES]
    attack_state["encrypted_files"] = []
    attack_state["alerts"] = []
    attack_state["files_encrypted"] = 0
    attack_state["detection_triggered"] = False
    attack_state["attack_log"] = []
    monitor_state["detection_score"] = 0
    monitor_state["rules_triggered"] = []

    # ── Phase 1: Dropper / Initial Access
    attack_state["status"] = "initializing"
    socketio.emit("attack_state", get_attack_state())
    add_log("DROPPER", f"[{variant}] Malicious payload dropped via phishing email attachment", "critical")
    time.sleep(0.8)

    for proc in config["drops_processes"]:
        add_log("PROCESS", f"Spawned malicious process: {proc} (PID {random.randint(1000,9999)})", "warning")
        attack_state["processes_spawned"].append(proc)
        time.sleep(0.3)

    # ── Phase 2: Scanning
    attack_state["status"] = "scanning"
    attack_state["scan_phase_done"] = False
    socketio.emit("attack_state", get_attack_state())
    add_log("SCAN", f"Initiating file system enumeration...", "warning")
    time.sleep(config["scan_delay"] * 0.3)

    if config["uses_smb"]:
        add_log("NETWORK", "Scanning local network for SMB shares (port 445)...", "critical")
        for i in range(3):
            ip = f"192.168.1.{random.randint(10,254)}"
            add_log("NETWORK", f"Probing {ip}:445 — {'OPEN' if random.random()>0.4 else 'closed'}", "warning")
            time.sleep(0.2)

    add_log("SCAN", f"Discovered {len(files_state)} target files matching extension filters", "warning")
    add_log("SCAN", "Prioritizing: .docx .xlsx .pdf .sql .zip .mp4 .txt .pem", "info")
    time.sleep(config["scan_delay"] * 0.4)

    attack_state["encryption_key"] = generate_key()
    attack_state["bitcoin_address"] = generate_bitcoin_address()
    attack_state["ransom_amount"] = random.randint(*config["ransom_range"])
    add_log("CRYPTO", f"Generated AES-256 session key: {attack_state['encryption_key'][:16]}...", "critical")
    add_log("CRYPTO", f"RSA-2048 public key loaded for key exchange", "critical")
    attack_state["scan_phase_done"] = True
    socketio.emit("attack_state", get_attack_state())
    time.sleep(0.5)

    # ── Phase 3: Encryption
    attack_state["status"] = "encrypting"
    socketio.emit("attack_state", get_attack_state())
    add_log("ENCRYPT", f"Beginning file encryption sequence...", "critical")

    detection_threshold = {"low": 4, "medium": 6, "high": 8}[monitor_state["sensitivity"]]
    ops_tracker = []

    for idx, file in enumerate(files_state):
        if stop_attack_flag.is_set():
            attack_state["status"] = "stopped"
            add_log("STOPPED", "Attack halted by user / detection system", "info")
            socketio.emit("attack_state", get_attack_state())
            return

        # Simulate per-file work
        attack_state["current_file"] = file["id"]
        speed = random.uniform(*config["speed_range"])
        time.sleep(speed)

        # Encrypt the file in state
        old_name = file["name"]
        new_name = old_name + config["extension"]
        file["encrypted"] = True
        file["name"] = new_name
        file["content"] = fake_encrypt(file["content"])
        attack_state["encrypted_files"].append(file["id"])
        attack_state["files_encrypted"] = len(attack_state["encrypted_files"])
        attack_state["progress"] = int((idx + 1) / len(files_state) * 100)

        ops_tracker.append(time.time())
        ops_tracker = [t for t in ops_tracker if time.time() - t < 1.0]
        monitor_state["file_ops_per_second"] = len(ops_tracker)

        # Calculate entropy score (simulated)
        entropy = round(random.uniform(6.5, 7.99), 2)
        monitor_state["entropy_scores"][file["id"]] = entropy

        add_log("ENCRYPT", f"Encrypted: {old_name} → {new_name} | Entropy: {entropy}", "critical", file["id"])

        # Detection logic
        monitor_state["detection_score"] = min(100, monitor_state["detection_score"] + random.randint(8, 18))
        socketio.emit("file_encrypted", {"file": file, "progress": attack_state["progress"]})
        socketio.emit("monitor_update", get_monitor_state())
        socketio.emit("attack_state", get_attack_state())

        # Trigger detection alerts progressively
        if idx == 2 and monitor_state["active"]:
            add_alert("High Entropy Write Detected", f"Rapid file modification with abnormal entropy (>6.5 bits/byte) on {file['name']}", "medium")
            monitor_state["rules_triggered"].append("ENTROPY_ANOMALY")

        if idx == detection_threshold and monitor_state["active"] and not attack_state["detection_triggered"]:
            attack_state["detection_triggered"] = True
            add_alert("🚨 RANSOMWARE DETECTED", f"Mass file encryption pattern confirmed — {attack_state['files_encrypted']} files affected. Attack variant: {variant}", "critical")
            add_alert("Honeypot File Triggered", "Monitored decoy file 'DO_NOT_OPEN.docx' was accessed and encrypted", "critical")
            monitor_state["rules_triggered"].append("MASS_ENCRYPTION")
            monitor_state["rules_triggered"].append("HONEYPOT_TRIGGERED")
            add_log("DETECT", f"⚠ DETECTION: Ransomware behavior confirmed. Score: {monitor_state['detection_score']}", "critical")
            socketio.emit("ransomware_detected", {"variant": variant, "files_hit": attack_state["files_encrypted"]})

    # ── Phase 4: Post-encryption
    attack_state["status"] = "completed"
    attack_state["current_file"] = None
    add_log("RANSOM", f"Dropping ransom note: README_{variant.upper()}.txt", "critical")
    add_log("RANSOM", f"Bitcoin address: {attack_state['bitcoin_address']}", "critical")
    add_log("RANSOM", f"Ransom amount: ${attack_state['ransom_amount']} USD / {round(attack_state['ransom_amount']/45000,4)} BTC", "critical")
    add_log("CLEANUP", "Deleting Volume Shadow Copies: vssadmin delete shadows /all /quiet", "critical")
    add_log("CLEANUP", "Disabling Windows Firewall: netsh advfirewall set allprofiles state off", "critical")
    add_log("CLEANUP", "Clearing event logs to hinder forensics", "warning")

    if not attack_state["detection_triggered"] and monitor_state["active"]:
        add_alert("Attack Completed Undetected", "All files encrypted before detection. Increase monitoring sensitivity.", "critical")

    socketio.emit("attack_state", get_attack_state())
    socketio.emit("attack_completed", {
        "files_encrypted": attack_state["files_encrypted"],
        "ransom_amount": attack_state["ransom_amount"],
        "bitcoin_address": attack_state["bitcoin_address"],
    })


# ─────────────────────────────────────────────
# State Getters
# ─────────────────────────────────────────────
def get_attack_state():
    return {
        **attack_state,
        "alerts": attack_state["alerts"][-10:],
    }


def get_monitor_state():
    return dict(monitor_state)


# ─────────────────────────────────────────────
# REST API
# ─────────────────────────────────────────────
@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify({
        "attack": get_attack_state(),
        "monitor": get_monitor_state(),
        "files": files_state,
        "logs": list(activity_log)[:50],
    })


@app.route("/api/files", methods=["GET"])
def get_files():
    return jsonify(files_state)


@app.route("/api/logs", methods=["GET"])
def get_logs():
    return jsonify(list(activity_log))


@app.route("/api/attack/start", methods=["POST"])
def start_attack():
    global attack_thread, files_state
    data = request.json or {}
    variant = data.get("variant", "WannaCry")

    if attack_state["status"] in ("scanning", "encrypting", "initializing"):
        return jsonify({"error": "Attack already running"}), 400

    attack_state["variant"] = variant
    attack_state["start_time"] = timestamp()
    attack_state["processes_spawned"] = []
    attack_state["network_connections"] = []

    add_log("SYSTEM", f"Attack simulation started — Variant: {variant}", "critical")

    attack_thread = threading.Thread(target=run_attack_simulation, args=(variant,), daemon=True)
    attack_thread.start()

    return jsonify({"status": "started", "variant": variant})


@app.route("/api/attack/stop", methods=["POST"])
def stop_attack():
    stop_attack_flag.set()
    attack_state["status"] = "stopped"
    add_log("SYSTEM", "Attack simulation stopped by user", "info")
    socketio.emit("attack_state", get_attack_state())
    return jsonify({"status": "stopped"})


@app.route("/api/attack/reset", methods=["POST"])
def reset_attack():
    global files_state
    stop_attack_flag.set()
    files_state = [dict(f) for f in SIMULATED_FILES]
    attack_state.update({
        "status": "idle",
        "progress": 0,
        "files_encrypted": 0,
        "start_time": None,
        "encryption_key": None,
        "ransom_amount": 0,
        "bitcoin_address": "",
        "detection_triggered": False,
        "alerts": [],
        "current_file": None,
        "encrypted_files": [],
        "attack_log": [],
        "scan_phase_done": False,
        "network_connections": [],
        "processes_spawned": [],
    })
    monitor_state.update({
        "alerts_count": 0,
        "rules_triggered": [],
        "file_ops_per_second": 0,
        "entropy_scores": {},
        "detection_score": 0,
    })
    activity_log.clear()
    add_log("SYSTEM", "Simulation reset. All files restored.", "info")
    socketio.emit("reset", {})
    socketio.emit("attack_state", get_attack_state())
    return jsonify({"status": "reset"})


@app.route("/api/monitor/toggle", methods=["POST"])
def toggle_monitor():
    data = request.json or {}
    monitor_state["active"] = data.get("active", not monitor_state["active"])
    monitor_state["sensitivity"] = data.get("sensitivity", monitor_state["sensitivity"])
    add_log("MONITOR", f"Monitoring {'ENABLED' if monitor_state['active'] else 'DISABLED'} | Sensitivity: {monitor_state['sensitivity']}", "info")
    socketio.emit("monitor_update", get_monitor_state())
    return jsonify(monitor_state)


@app.route("/api/variants", methods=["GET"])
def get_variants():
    return jsonify([
        {"id": "WannaCry", "name": "WannaCry",  "color": "#ff4444", "description": "Exploits SMB EternalBlue vulnerability. Caused $4B in damages in 2017.", "severity": "Critical"},
        {"id": "Locky",    "name": "Locky",     "color": "#ff8800", "description": "Spread via malicious Office macros in phishing emails.", "severity": "High"},
        {"id": "REvil",    "name": "REvil",     "color": "#cc00ff", "description": "Ransomware-as-a-Service. Targeted enterprises for millions.", "severity": "Critical"},
        {"id": "Petya",    "name": "Petya/NotPetya", "color": "#0099ff", "description": "Overwrites MBR. Used as destructive cyberweapon in Ukraine 2017.", "severity": "Critical"},
    ])


# ─────────────────────────────────────────────
# WebSocket Events
# ─────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    emit("connected", {"msg": "Connected to Ransomware Simulator"})
    emit("attack_state", get_attack_state())
    emit("monitor_update", get_monitor_state())


if __name__ == "__main__":
    port = int(os.environ.get("RANSOMWARE_BACKEND_PORT", 5001))
    debug_mode = os.environ.get("RANSOMWARE_DEBUG", "0") == "1"
    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=debug_mode,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )
