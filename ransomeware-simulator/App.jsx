import { useState, useEffect, useRef, useCallback } from "react";
import { io } from "socket.io-client";
import axios from "axios";
import AttackPanel from "./components/AttackPanel";
import FileSystem from "./components/FileSystem";
import MonitorPanel from "./components/MonitorPanel";
import AlertFeed from "./components/AlertFeed";
import ActivityLog from "./components/ActivityLog";
import RansomNote from "./components/RansomNote";
import StatsBar from "./components/StatsBar";
import "./App.css";

const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || "http://localhost:5001";
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || "http://localhost:5001";
const DEFAULT_FILES = [
  { id: "f1", name: "thesis_final.docx", path: "/Documents/thesis_final.docx", size: 245760, type: "document", encrypted: false },
  { id: "f2", name: "family_photos.zip", path: "/Pictures/family_photos.zip", size: 15728640, type: "image", encrypted: false },
  { id: "f3", name: "salary_data.xlsx", path: "/Documents/salary_data.xlsx", size: 98304, type: "spreadsheet", encrypted: false },
  { id: "f4", name: "passwords.txt", path: "/Desktop/passwords.txt", size: 2048, type: "text", encrypted: false },
  { id: "f5", name: "project_source.zip", path: "/Projects/project_source.zip", size: 5242880, type: "code", encrypted: false },
  { id: "f6", name: "client_database.sql", path: "/Database/client_database.sql", size: 3145728, type: "database", encrypted: false },
  { id: "f7", name: "annual_report.pdf", path: "/Documents/annual_report.pdf", size: 1048576, type: "document", encrypted: false },
  { id: "f8", name: "encryption_keys.pem", path: "/System/encryption_keys.pem", size: 4096, type: "security", encrypted: false },
  { id: "f9", name: "backup_2024.tar.gz", path: "/Backups/backup_2024.tar.gz", size: 20971520, type: "backup", encrypted: false },
  { id: "f10", name: "medical_records.pdf", path: "/Health/medical_records.pdf", size: 512000, type: "document", encrypted: false },
  { id: "f11", name: "tax_returns_2023.xlsx", path: "/Finance/tax_returns_2023.xlsx", size: 163840, type: "spreadsheet", encrypted: false },
  { id: "f12", name: "vacation_video.mp4", path: "/Videos/vacation_video.mp4", size: 524288000, type: "video", encrypted: false },
];

export default function App() {
  const [socket, setSocket] = useState(null);
  const [attackState, setAttackState] = useState({ status: "idle", progress: 0, files_encrypted: 0, files_total: 12 });
  const [monitorState, setMonitorState] = useState({ active: false, sensitivity: "medium", detection_score: 0, alerts_count: 0, rules_triggered: [], file_ops_per_second: 0 });
  const [files, setFiles] = useState(DEFAULT_FILES);
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [showRansom, setShowRansom] = useState(false);
  const [variants, setVariants] = useState([]);
  const [selectedVariant, setSelectedVariant] = useState("WannaCry");
  const [connected, setConnected] = useState(false);
  const [globalAlert, setGlobalAlert] = useState(null);
  const showApiError = useCallback((action, err) => {
    const status = err?.response?.status;
    const detail = err?.response?.data?.error || err?.message || "Unknown error";
    setGlobalAlert({
      title: `${action} failed${status ? ` (HTTP ${status})` : ""}`,
      detail,
      severity: "critical",
    });
    setTimeout(() => setGlobalAlert(null), 5000);
  }, []);

  // Init socket
  useEffect(() => {
    const s = io(SOCKET_URL, { transports: ["websocket", "polling"] });
    setSocket(s);

    s.on("connect", () => setConnected(true));
    s.on("disconnect", () => setConnected(false));

    s.on("attack_state", (data) => {
      setAttackState(data);
      if (data.alerts) setAlerts(prev => {
        const ids = new Set(prev.map(a => a.id));
        const newOnes = data.alerts.filter(a => !ids.has(a.id));
        return [...newOnes, ...prev].slice(0, 50);
      });
    });

    s.on("monitor_update", (data) => setMonitorState(data));

    s.on("file_encrypted", ({ file }) => {
      setFiles(prev => prev.map(f => f.id === file.id ? file : f));
    });

    s.on("log_entry", (entry) => {
      setLogs(prev => [entry, ...prev].slice(0, 200));
    });

    s.on("alert", (alert) => {
      setAlerts(prev => [alert, ...prev].slice(0, 50));
      if (alert.severity === "critical") {
        setGlobalAlert(alert);
        setTimeout(() => setGlobalAlert(null), 5000);
      }
    });

    s.on("ransomware_detected", () => {});

    s.on("attack_completed", () => {
      setTimeout(() => setShowRansom(true), 1000);
    });

    s.on("reset", () => {
      setLogs([]);
      setAlerts([]);
      setShowRansom(false);
      setGlobalAlert(null);
    });

    return () => s.disconnect();
  }, []);

  // Load initial data
  useEffect(() => {
    axios.get(`${API_BASE_URL}/api/files`)
      .then(r => {
        if (Array.isArray(r.data)) setFiles(r.data);
      })
      .catch(() => {});

    axios.get(`${API_BASE_URL}/api/variants`)
      .then(r => {
        if (Array.isArray(r.data)) setVariants(r.data);
      })
      .catch(() => {});

    axios.get(`${API_BASE_URL}/api/status`)
      .then(r => {
        const data = r.data || {};
        if (data.attack && typeof data.attack.status === "string") {
          setAttackState(data.attack);
        }
        if (data.monitor && typeof data.monitor === "object") {
          setMonitorState(data.monitor);
        }
        if (Array.isArray(data.files)) {
          setFiles(data.files);
        }
        if (Array.isArray(data.logs)) {
          setLogs(data.logs);
        }
      })
      .catch(() => {});
  }, []);

  const startAttack = () => {
    if (!connected) {
      showApiError("Start attack", { message: "Backend is offline on http://localhost:5001. Start backend first." });
      return;
    }
    axios.post(`${API_BASE_URL}/api/attack/start`, { variant: selectedVariant })
      .catch((err) => showApiError("Start attack", err));
  };

  const stopAttack = () => {
    axios.post(`${API_BASE_URL}/api/attack/stop`)
      .catch((err) => showApiError("Stop attack", err));
  };

  const resetSim = () => {
    axios.post(`${API_BASE_URL}/api/attack/reset`).then(() => {
      axios.get(`${API_BASE_URL}/api/files`)
        .then(r => setFiles(r.data))
        .catch((err) => showApiError("Reload files", err));
    }).catch((err) => showApiError("Reset simulation", err));
    setShowRansom(false);
  };

  const toggleMonitor = (sensitivity) => {
    axios.post(`${API_BASE_URL}/api/monitor/toggle`, {
      active: !monitorState.active,
      sensitivity: sensitivity || monitorState.sensitivity,
    }).then(r => setMonitorState(r.data))
      .catch((err) => showApiError("Toggle monitoring", err));
  };

  const setSensitivity = (s) => {
    axios.post(`${API_BASE_URL}/api/monitor/toggle`, { active: monitorState.active, sensitivity: s })
      .then(r => setMonitorState(r.data))
      .catch((err) => showApiError("Set sensitivity", err));
  };

  const isRunning = ["scanning", "encrypting", "initializing"].includes(attackState.status);

  return (
    <div className={`app ${globalAlert ? "has-alert" : ""}`}>
      {/* Global critical alert banner */}
      {globalAlert && (
        <div className="global-alert">
          <span className="ga-icon">⚠</span>
          <span className="ga-title">{globalAlert.title}</span>
          <span className="ga-detail">{globalAlert.detail}</span>
          <button onClick={() => setGlobalAlert(null)}>✕</button>
        </div>
      )}

      {/* Header */}
      <header className="app-header">
        <div className="header-left">
          <div className="logo">
            <span className="logo-icon">☠</span>
            <div>
              <h1>RansomWatch</h1>
              <p>Ransomware Detection Simulator</p>
            </div>
          </div>
        </div>
        <div className="header-center">
          <StatsBar attackState={attackState} monitorState={monitorState} />
        </div>
        <div className="header-right">
          <div className={`conn-badge ${connected ? "conn-on" : "conn-off"}`}>
            <span className="conn-dot"></span>
            {connected ? "LIVE" : "OFFLINE"}
          </div>
          <div className={`status-badge status-${attackState.status}`}>
            {attackState.status.toUpperCase()}
          </div>
        </div>
      </header>

      {/* Main Grid */}
      <main className="app-main">
        {/* Left column */}
        <div className="col-left">
          <AttackPanel
            variants={variants}
            selectedVariant={selectedVariant}
            setSelectedVariant={setSelectedVariant}
            attackState={attackState}
            isRunning={isRunning}
            onStart={startAttack}
            onStop={stopAttack}
            onReset={resetSim}
          />
          <MonitorPanel
            monitorState={monitorState}
            onToggle={toggleMonitor}
            onSensitivity={setSensitivity}
            isRunning={isRunning}
          />
        </div>

        {/* Center column - File System */}
        <div className="col-center">
          <FileSystem files={files} attackState={attackState} />
        </div>

        {/* Right column */}
        <div className="col-right">
          <AlertFeed alerts={alerts} />
          <ActivityLog logs={logs} />
        </div>
      </main>

      {/* Ransom note modal */}
      {showRansom && (
        <RansomNote
          attackState={attackState}
          onClose={() => setShowRansom(false)}
          variants={variants}
        />
      )}
    </div>
  );
}
