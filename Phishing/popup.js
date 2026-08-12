// ============================================================
//  Phishing Detector — Popup Script v3
//  All fetch calls go through background.js via chrome.runtime.sendMessage
//  so they are NOT blocked by popup CSP restrictions.
// ============================================================

const API = 'http://127.0.0.1:5000';

// DOM refs
const urlBox      = document.getElementById('urlBox');
const checkBtn    = document.getElementById('checkBtn');
const dashBtn     = document.getElementById('dashBtn');
const resultEl    = document.getElementById('result');
const rIcon       = document.getElementById('rIcon');
const rTitle      = document.getElementById('rTitle');
const rScore      = document.getElementById('rScore');
const rReasons    = document.getElementById('rReasons');
const connDot     = document.getElementById('connDot');
const connLabel   = document.getElementById('connLabel');
const queueBanner = document.getElementById('queueBanner');
const queueText   = document.getElementById('queueText');
const flushBtn    = document.getElementById('flushBtn');
const footerSt    = document.getElementById('footerStatus');

let currentUrl = '';

// ── 1. Check server connectivity ─────────────────────────────
async function checkServer() {
  try {
    const res = await fetch(`${API}/api/status`, { method: 'GET' });
    if (res.ok) {
      connDot.className   = 'conn-dot online';
      connLabel.textContent = 'Dashboard online';
      footerSt.textContent  = '✓ connected';
      return true;
    }
  } catch (_) {}
  connDot.className   = 'conn-dot offline';
  connLabel.textContent = 'Dashboard offline';
  footerSt.textContent  = '✗ start app.py';
  return false;
}

// ── 2. Load current tab URL ───────────────────────────────────
function loadCurrentTab() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (chrome.runtime.lastError) {
      urlBox.textContent = 'Error: ' + chrome.runtime.lastError.message;
      return;
    }

    const tab = tabs && tabs[0];
    if (!tab) {
      urlBox.textContent = 'No active tab found.';
      return;
    }

    const url = tab.url || tab.pendingUrl || '';

    if (!url) {
      urlBox.textContent = 'No URL available.';
      return;
    }

    const INTERNAL = ['chrome://', 'chrome-extension://', 'edge://', 'devtools://', 'about:'];
    if (INTERNAL.some(p => url.startsWith(p))) {
      urlBox.textContent = '(Chrome internal page — cannot check)';
      checkBtn.disabled  = true;
      return;
    }

    currentUrl = url;
    urlBox.textContent = url;
    checkBtn.disabled  = false;
  });
}

// ── 3. Check offline queue size ───────────────────────────────
function loadQueueSize() {
  chrome.runtime.sendMessage({ type: 'GET_QUEUE_SIZE' }, (res) => {
    if (chrome.runtime.lastError) return;
    if (res && res.size > 0) {
      queueText.textContent = `⚠️ ${res.size} URL(s) queued (dashboard was offline)`;
      queueBanner.classList.add('visible');
    } else {
      queueBanner.classList.remove('visible');
    }
  });
}

// ── 4. Check URL button ───────────────────────────────────────
checkBtn.addEventListener('click', () => {
  if (!currentUrl) return;

  checkBtn.disabled  = true;
  checkBtn.innerHTML = '<div class="spin"></div> Checking…';
  resultEl.style.display = 'none';

  // Send to background so it uses the background fetch (not popup fetch)
  chrome.runtime.sendMessage({ type: 'CHECK_URL', url: currentUrl }, (response) => {
    checkBtn.disabled  = false;
    checkBtn.innerHTML = '🔍 Check This URL';

    if (chrome.runtime.lastError || !response) {
      showResult('error', '❌', 'Extension error', '', [chrome.runtime.lastError?.message || 'No response from background']);
      return;
    }

    if (!response.ok) {
      showResult('error', '❌', 'Dashboard offline', 'Start python app.py first', [response.error || 'Cannot connect to localhost:5000']);
      return;
    }

    const d  = response.data;
    const ra = d.rule_analysis || {};
    const statusMap = {
      safe:       { icon: '✅', title: 'SAFE',              cls: 'safe'       },
      phishing:   { icon: '🚨', title: 'PHISHING DETECTED', cls: 'phishing'   },
      suspicious: { icon: '⚠️', title: 'SUSPICIOUS',        cls: 'suspicious' },
    };
    const s = statusMap[d.status] || { icon: '❓', title: d.status?.toUpperCase(), cls: 'error' };
    showResult(s.cls, s.icon, s.title, `Risk score: ${ra.score ?? '?'}/100`, ra.reasons || []);
  });
});

function showResult(cls, icon, title, score, reasons) {
  resultEl.className    = 'result ' + cls;
  resultEl.style.display = 'block';
  rIcon.textContent     = icon;
  rTitle.textContent    = title;
  rScore.textContent    = score;
  rReasons.innerHTML    = reasons.slice(0, 4).map(r => `<div>${r}</div>`).join('');
}

// ── 5. Open dashboard tab ────────────────────────────────────
dashBtn.addEventListener('click', () => {
  chrome.tabs.create({ url: API + '/' });
  window.close();
});

// ── 6. Flush offline queue ────────────────────────────────────
flushBtn.addEventListener('click', () => {
  flushBtn.textContent = 'Retrying…';
  flushBtn.disabled    = true;
  chrome.runtime.sendMessage({ type: 'FLUSH_QUEUE' }, () => {
    setTimeout(() => {
      loadQueueSize();
      flushBtn.textContent = 'Retry Now';
      flushBtn.disabled    = false;
    }, 1500);
  });
});

// ── Init ─────────────────────────────────────────────────────
async function init() {
  loadCurrentTab();
  await checkServer();
  loadQueueSize();
}

init();
