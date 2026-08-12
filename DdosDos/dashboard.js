/**
 * dashboard.js — UI controller, binds simulation + charts → DOM
 */

// ── Clock ────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toTimeString().slice(0,8);
}
setInterval(updateClock, 1000);
updateClock();

// ── Controls ─────────────────────────────────────────────
let currentAttack = null;

function toggleAttack(type) {
  if (currentAttack === type) {
    // Stop
    Simulation.stop();
    currentAttack = null;
    document.getElementById('dosBtn').classList.remove('active');
    document.getElementById('ddosBtn').classList.remove('active');
    document.getElementById('dosBtn').textContent  = '▶ LAUNCH DoS';
    document.getElementById('ddosBtn').textContent = '▶ LAUNCH DDoS';
    setSystemStatus('MONITORING', 'ok');
  } else {
    // Stop any existing
    if (currentAttack) Simulation.stop();
    currentAttack = type;
    Simulation.start(type);

    document.getElementById('dosBtn').classList.toggle('active', type==='dos');
    document.getElementById('ddosBtn').classList.toggle('active', type==='ddos');
    document.getElementById('dosBtn').textContent  = type==='dos'  ? '■ STOP DoS' : '▶ LAUNCH DoS';
    document.getElementById('ddosBtn').textContent = type==='ddos' ? '■ STOP DDoS': '▶ LAUNCH DDoS';
    setSystemStatus('UNDER ATTACK', 'danger');
  }
}

function setSystemStatus(text, level) {
  document.getElementById('systemStatus').textContent = text;
  const dot = document.getElementById('statusDot');
  dot.className = 'dot' + (level==='danger' ? ' danger' : level==='warning' ? ' warning' : '');
}

function resetAll() {
  if (currentAttack) toggleAttack(currentAttack); // stop
  Simulation.reset();
  currentAttack = null;
  setSystemStatus('MONITORING', 'ok');
  renderAll();
}

// ── Defense Controls ──────────────────────────────────────
function updateDefense() {
  const defenses = {};
  ['defRateLimit','defBlacklist','defSynCookie','defScrubbing',
   'defGeoBlock','defCaptcha','defAnycast'].forEach(id => {
    defenses[id] = document.getElementById(id).checked;
  });
  Simulation.updateDefenses(defenses);

  // Update score display
  const score = Simulation.state.defenseScore;
  document.getElementById('defenseBar').style.width = score + '%';
  document.getElementById('defensePct').textContent = score + '%';
}

// Initialise defenses
updateDefense();

// Range labels
function updateRateLabel(v)    { document.getElementById('rateLabel').textContent = Number(v).toLocaleString(); }
function updateBotLabel(v)     { document.getElementById('botLabel').textContent = v; }
function updatePayloadLabel(v) { document.getElementById('payloadLabel').textContent = Number(v).toLocaleString(); }

// ── Render: Metrics ───────────────────────────────────────
function renderMetrics(s) {
  const bw  = s.incomingTraffic;
  const pps = s.packetsPerSec;
  const blk = s.blockedPct;
  const lat = s.latency;

  document.getElementById('mvTraffic').innerHTML = `${Math.round(bw)} <span class="unit">Mbps</span>`;
  document.getElementById('mvPackets').innerHTML = `${pps.toLocaleString()} <span class="unit">pps</span>`;
  document.getElementById('mvBlocked').innerHTML = `${blk} <span class="unit">%</span>`;
  document.getElementById('mvLatency').innerHTML = `${lat} <span class="unit">ms</span>`;

  document.getElementById('barTraffic').style.width = Math.min(bw/10, 100) + '%';
  document.getElementById('barPackets').style.width = Math.min(pps/100, 100) + '%';
  document.getElementById('barBlocked').style.width = blk + '%';
  document.getElementById('barLatency').style.width = Math.min(lat/50, 100) + '%';

  const alert = s.running && blk < 50;
  document.getElementById('mcTraffic').classList.toggle('alert', alert);
  document.getElementById('mcPackets').classList.toggle('alert', alert);
}

// ── Render: Threat ────────────────────────────────────────
function renderThreat(s) {
  const ring = document.getElementById('threatRing');
  const val  = document.getElementById('threatValue');
  const tl   = s.threatLevel;

  val.textContent = tl;
  ring.className  = 'threat-ring ' + {
    LOW:'',MEDIUM:'medium',HIGH:'high',CRITICAL:'critical'
  }[tl] || '';
  val.style.color = tl==='LOW' ? 'var(--accent2)' : tl==='MEDIUM' ? 'var(--warning)' : 'var(--danger)';

  document.getElementById('tiVector').textContent    = s.running ? document.getElementById('attackType').value.toUpperCase() : '—';
  document.getElementById('tiBandwidth').textContent = s.running ? `${Math.round(s.incomingTraffic)} Mbps` : '0 Mbps';
  document.getElementById('tiSources').textContent   = s.running ? (s.activeNodes || 1).toString() : '0';
  document.getElementById('tiDuration').textContent  = s.running ? `${s.elapsedSeconds}s` : '0s';
  document.getElementById('tiConfidence').textContent= s.running ? (s.defenseScore > 60 ? 'HIGH' : 'MEDIUM') : '—';
}

// ── Render: Log ───────────────────────────────────────────
function renderLog(events) {
  const container = document.getElementById('logContainer');
  const html = events.slice(0, 40).map(e =>
    `<div class="log-line ${e.type}">[${e.ts}] ${e.msg}</div>`
  ).join('');
  container.innerHTML = html;
}

// ── Render: Mitigation ────────────────────────────────────
function renderMitigation(s) {
  const list = document.getElementById('mitigationList');
  if (!s.running) {
    list.innerHTML = '<div class="mit-item idle">Awaiting attack detection...</div>';
    return;
  }
  const actions = [];
  if (s.defenses.defRateLimit)  actions.push('Rate Limiting: ACTIVE — threshold 1K pps/IP');
  if (s.defenses.defBlacklist)  actions.push(`IP Blacklist: ${s.blockedIPs.size} entries`);
  if (s.defenses.defSynCookie)  actions.push('SYN Cookies: ENABLED — half-open queue cleared');
  if (s.defenses.defScrubbing)  actions.push('Traffic Scrubbing: ON — clean pipe forwarded');
  if (s.defenses.defGeoBlock)   actions.push('GeoBlocking: Active for high-risk regions');
  if (s.defenses.defCaptcha)    actions.push('CAPTCHA: Challenging suspicious sessions');
  if (s.defenses.defAnycast)    actions.push('Anycast: Load distributed across 12 PoPs');
  if (!actions.length) {
    list.innerHTML = '<div class="mit-item idle">⚠ No defenses active — system vulnerable!</div>';
    return;
  }
  list.innerHTML = actions.map(a =>
    `<div class="mit-item active">✓ ${a}</div>`
  ).join('');
}

// ── Render: Heatmap ───────────────────────────────────────
function renderHeatmap(s) {
  const container = document.getElementById('ipHeatmap');
  const count = Math.min(s.blockedIPs.size, 80);
  document.getElementById('blockedCount').textContent = `${count} IPs`;

  const cells = [];
  for (let i = 0; i < 80; i++) {
    const lvl = i < count
      ? (i < count * 0.3 ? 'hot' : i < count * 0.7 ? 'warm' : 'cool')
      : '';
    cells.push(`<div class="ip-cell ${lvl}" title="IP blocked"></div>`);
  }
  container.innerHTML = cells.join('');
}

// ── Render: Stats ─────────────────────────────────────────
function renderStats(s) {
  document.getElementById('statTotal').textContent     = s.stats.total;
  document.getElementById('statMitigated').textContent = s.stats.mitigated;
  document.getElementById('statPenetrated').textContent= s.stats.penetrated;
  document.getElementById('statOngoing').textContent   = s.stats.ongoing;
}

// ── Render: System Status ─────────────────────────────────
function renderSystemStatus(s) {
  if (!s.running) {
    setSystemStatus('MONITORING', 'ok');
    return;
  }
  if (s.threatLevel === 'CRITICAL') setSystemStatus('CRITICAL ATTACK', 'danger');
  else if (s.threatLevel === 'HIGH') setSystemStatus('HIGH SEVERITY', 'danger');
  else if (s.threatLevel === 'MEDIUM') setSystemStatus('UNDER ATTACK', 'warning');
  else setSystemStatus('MITIGATED', 'ok');
}

// ── Main Render Loop ──────────────────────────────────────
function renderAll() {
  const s = Simulation.state;

  renderMetrics(s);
  renderThreat(s);
  renderLog(s.events);
  renderMitigation(s);
  renderHeatmap(s);
  renderStats(s);
  renderSystemStatus(s);

  Charts.drawTrafficChart('trafficChart', s.history);
  Charts.drawPieChart('pieChart', Simulation.getPacketDistribution());
  Charts.drawResourceChart('resourceChart', s.history);
  Charts.drawMap('mapCanvas', s.sourceIPs);
}

// ── Simulation Loop ───────────────────────────────────────
let simInterval = null;

function startLoop() {
  if (simInterval) clearInterval(simInterval);
  simInterval = setInterval(() => {
    Simulation.tick();
    renderAll();
  }, 800);
}

startLoop();

// Initial render
setTimeout(renderAll, 100);

// Initial log messages
Simulation.state.events.push({ type:'info', ts: new Date().toISOString().substr(11,8), msg: 'System online. All monitors active.' });
Simulation.state.events.push({ type:'success', ts: new Date().toISOString().substr(11,8), msg: 'Intrusion Detection System ready.' });
Simulation.state.events.push({ type:'info', ts: new Date().toISOString().substr(11,8), msg: 'Baseline traffic learned. Anomaly detection ON.' });
