const API_BASE = "http://127.0.0.1:5000";

const apiStatus = document.getElementById("apiStatus");
const keyStatus = document.getElementById("keyStatus");
const urlInput = document.getElementById("urlInput");
const checkBtn = document.getElementById("checkBtn");
const refreshBtn = document.getElementById("refreshBtn");
const openDashBtn = document.getElementById("openDashBtn");
const saveKeyBtn = document.getElementById("saveKeyBtn");
const apiKeyInput = document.getElementById("apiKeyInput");

const resultWrap = document.getElementById("resultWrap");
const resultBadge = document.getElementById("resultBadge");
const resultScore = document.getElementById("resultScore");
const resultUrl = document.getElementById("resultUrl");
const resultReasons = document.getElementById("resultReasons");
const vtInfo = document.getElementById("vtInfo");

function normalizeUrl(value) {
  const url = (value || "").trim();
  if (!url) return "";
  if (url.startsWith("http://") || url.startsWith("https://")) return url;
  return "https://" + url;
}

async function refreshStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    if (!res.ok) throw new Error("Backend offline");
    const data = await res.json();
    apiStatus.textContent = data.vt_configured
      ? "Backend online. VirusTotal key configured."
      : "Backend online. VirusTotal key not configured.";
    apiStatus.className = "status online";
    keyStatus.textContent = data.vt_configured
      ? "Key is already saved in backend."
      : "No key saved yet.";
  } catch (err) {
    apiStatus.textContent = "Backend offline. Start Phishing/app.py first.";
    apiStatus.className = "status offline";
    keyStatus.textContent = "Cannot check key while backend is offline.";
  }
}

async function analyzeUrl() {
  const url = normalizeUrl(urlInput.value);
  if (!url) return;

  checkBtn.disabled = true;
  checkBtn.textContent = "Checking...";

  try {
    const res = await fetch(`${API_BASE}/api/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    showResult(data);
  } catch (err) {
    alert(`Could not analyze URL: ${err.message}`);
  } finally {
    checkBtn.disabled = false;
    checkBtn.textContent = "Analyze";
  }
}

function showResult(data) {
  const status = data.status || "safe";
  const score = (data.rule_analysis && data.rule_analysis.score) || 0;
  const reasons = (data.rule_analysis && data.rule_analysis.reasons) || [];
  const vt = data.virustotal || {};

  resultWrap.style.display = "block";
  resultBadge.textContent = status;
  resultBadge.className = `pill ${status}`;
  resultScore.textContent = `Risk Score: ${score}/100`;
  resultUrl.textContent = data.url || "";

  resultReasons.innerHTML = reasons.length
    ? reasons.map((r) => `<li>${r}</li>`).join("")
    : "<li>No suspicious patterns found</li>";

  if (vt.available) {
    vtInfo.textContent = `VirusTotal: malicious=${vt.malicious}, suspicious=${vt.suspicious}, engines=${vt.total_scanners}`;
  } else {
    vtInfo.textContent = `VirusTotal: ${vt.message || "Not available"}`;
  }
}

async function saveApiKey() {
  const key = (apiKeyInput.value || "").trim();
  try {
    const res = await fetch(`${API_BASE}/api/set-apikey`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apikey: key })
    });
    const data = await res.json();
    if (!res.ok || !data.success) throw new Error("Unable to save key");
    keyStatus.textContent = key
      ? "API key saved in backend config. You do not need to enter it again."
      : "API key cleared from backend config.";
    apiKeyInput.value = "";
    await refreshStatus();
  } catch (err) {
    keyStatus.textContent = `Failed to save key: ${err.message}`;
  }
}

checkBtn.addEventListener("click", analyzeUrl);
refreshBtn.addEventListener("click", refreshStatus);
saveKeyBtn.addEventListener("click", saveApiKey);
openDashBtn.addEventListener("click", () => window.open(`${API_BASE}/`, "_blank"));
urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") analyzeUrl();
});

refreshStatus();
