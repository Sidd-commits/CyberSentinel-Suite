// ============================================================
//  Phishing Detector — Background Service Worker v3
//  Uses webNavigation (fires for every real page load)
//  Queues URLs in chrome.storage so nothing is lost when the
//  service worker goes idle between navigations.
// ============================================================

const API_BASE = 'http://127.0.0.1:5000';

const SKIP = [
  'chrome://', 'chrome-extension://', 'devtools://',
  'edge://', 'about:', 'data:', 'blob:', 'javascript:'
];

// ── Helpers ──────────────────────────────────────────────────
function skip(url) {
  return !url || SKIP.some(p => url.startsWith(p));
}

// Read dedup cache from storage (SW-safe, persists across idle)
async function isRecent(url) {
  const key = 'recent_' + btoa(url).slice(0, 40);
  const res  = await chrome.storage.session.get(key).catch(() => ({}));
  if (!res[key]) return false;
  return (Date.now() - res[key]) < 60000;   // 60-second dedup window
}

async function markRecent(url) {
  const key = 'recent_' + btoa(url).slice(0, 40);
  await chrome.storage.session.set({ [key]: Date.now() }).catch(() => {});
}

// ── Send URL to Python dashboard ─────────────────────────────
async function sendUrl(url) {
  if (skip(url)) return;
  if (await isRecent(url)) return;
  await markRecent(url);

  try {
    const res = await fetch(`${API_BASE}/api/log-url`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url, source: 'chrome_extension' })
    });

    if (!res.ok) {
      console.warn('[PhishDetect] Server error:', res.status);
      return;
    }

    const data = await res.json();
    console.log('[PhishDetect]', data.status, '|', url);

    // Desktop notification for dangerous URLs
    if (data.status === 'phishing' || data.status === 'suspicious') {
      const isPhish = data.status === 'phishing';
      chrome.notifications.create('phish_' + Date.now(), {
        type:     'basic',
        iconUrl:  'icons/icon48.png',
        title:    isPhish ? '🚨 Phishing Site!' : '⚠️ Suspicious URL',
        message:  new URL(url).hostname + '\nRisk score: ' + (data.score || '?') + '/100',
        priority: isPhish ? 2 : 1
      });
    }

    // Update badge on the active tab
    updateBadge(data.status);

  } catch (err) {
    // Dashboard not running — save to queue for when it comes back
    console.warn('[PhishDetect] Dashboard offline, queuing:', url);
    queueUrl(url);
  }
}

// ── Offline queue (retry when dashboard comes back) ──────────
async function queueUrl(url) {
  const { offline_queue = [] } = await chrome.storage.local.get('offline_queue');
  if (!offline_queue.includes(url)) {
    offline_queue.push(url);
    if (offline_queue.length > 200) offline_queue.shift();  // cap at 200
    await chrome.storage.local.set({ offline_queue });
  }
}

async function flushQueue() {
  const { offline_queue = [] } = await chrome.storage.local.get('offline_queue');
  if (!offline_queue.length) return;

  const remaining = [];
  for (const url of offline_queue) {
    try {
      const res = await fetch(`${API_BASE}/api/log-url`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ url, source: 'chrome_extension_queued' })
      });
      if (!res.ok) remaining.push(url);
    } catch {
      remaining.push(url);
      break;  // still offline, stop trying
    }
  }
  await chrome.storage.local.set({ offline_queue: remaining });
}

// ── Badge helper ─────────────────────────────────────────────
function updateBadge(status) {
  const map = {
    safe:       { text: '✓',  color: '#22c55e' },
    suspicious: { text: '!',  color: '#f59e0b' },
    phishing:   { text: '!!', color: '#ef4444' },
  };
  const b = map[status];
  if (!b) return;
  chrome.action.setBadgeText({ text: b.text });
  chrome.action.setBadgeBackgroundColor({ color: b.color });
  // Clear badge after 8 seconds
  setTimeout(() => chrome.action.setBadgeText({ text: '' }), 8000);
}

// ── webNavigation: fires reliably on EVERY real page load ────
// onCompleted fires once the page finishes loading (not on redirects)
chrome.webNavigation.onCompleted.addListener((details) => {
  // Only track main frame (frameId === 0), not iframes
  if (details.frameId !== 0) return;
  if (skip(details.url)) return;
  sendUrl(details.url);
});

// Also catch pages that load very fast (before onCompleted fires)
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  if (skip(details.url)) return;
  // Only for actual user navigations (not history state changes, etc.)
  const userTypes = ['link', 'typed', 'auto_bookmark', 'generated', 'keyword', 'keyword_generated'];
  if (!userTypes.includes(details.transitionType)) return;
  sendUrl(details.url);
});

// ── Startup: flush any queued URLs ───────────────────────────
chrome.runtime.onStartup.addListener(() => {
  setTimeout(flushQueue, 3000);
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('[PhishDetect] Extension installed/updated');
  chrome.storage.local.set({ offline_queue: [] });
});

// ── Message handler (from popup) ─────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'CHECK_URL') {
    // Popup asks background to check URL and return result
    fetch(`${API_BASE}/api/check-url`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url: msg.url })
    })
    .then(r => r.json())
    .then(data => sendResponse({ ok: true, data }))
    .catch(err => sendResponse({ ok: false, error: err.message }));
    return true;  // keep channel open for async response
  }

  if (msg.type === 'FLUSH_QUEUE') {
    flushQueue().then(() => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === 'GET_QUEUE_SIZE') {
    chrome.storage.local.get('offline_queue').then(({ offline_queue = [] }) => {
      sendResponse({ size: offline_queue.length });
    });
    return true;
  }
});
