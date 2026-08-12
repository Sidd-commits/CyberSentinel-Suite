/**
 * simulation.js — DoS/DDoS Attack Simulation Engine
 * Simulates network attacks and defense mechanisms with
 * realistic traffic patterns and mitigation logic.
 */

const Simulation = (() => {
  // ── State ──────────────────────────────────────────────
  const state = {
    running: false,
    attackType: null,    // 'dos' | 'ddos' | null
    attackVector: null,  // 'syn' | 'udp' | 'http' | 'icmp' | 'slowloris'
    tick: 0,
    startTime: null,
    elapsedSeconds: 0,

    // Traffic metrics
    incomingTraffic: 0,   // Mbps
    packetsPerSec: 0,
    blockedPct: 0,
    latency: 12,          // ms

    // Defense
    defenseScore: 0,
    defenses: {},

    // Botnet
    botnetNodes: 50,
    activeNodes: 0,

    // History (for charts) — 60 samples
    history: {
      attackTraffic: new Array(60).fill(0),
      legitTraffic:  new Array(60).fill(0),
      blockedTraffic: new Array(60).fill(0),
      cpu:    new Array(60).fill(10),
      mem:    new Array(60).fill(30),
      conn:   new Array(60).fill(5),
    },

    // Stats
    stats: {
      total: 0,
      mitigated: 0,
      penetrated: 0,
      ongoing: 0,
    },

    // Blocked IPs
    blockedIPs: new Set(),
    sourceIPs: [],

    // Threat
    threatLevel: 'LOW',

    // Events queue
    events: [],
  };

  // ── Attack Profiles ───────────────────────────────────
  const ATTACK_PROFILES = {
    syn:      { name: 'SYN Flood',     bwFactor: 0.4, ppsFactor: 1.0, latFactor: 4.0, udpFactor: 0 },
    udp:      { name: 'UDP Flood',     bwFactor: 1.0, ppsFactor: 0.8, latFactor: 2.0, udpFactor: 1 },
    http:     { name: 'HTTP Flood',    bwFactor: 0.6, ppsFactor: 0.6, latFactor: 6.0, udpFactor: 0 },
    icmp:     { name: 'ICMP Flood',    bwFactor: 0.5, ppsFactor: 0.9, latFactor: 1.5, udpFactor: 0 },
    slowloris:{ name: 'Slowloris',     bwFactor: 0.1, ppsFactor: 0.2, latFactor: 10,  udpFactor: 0 },
  };

  // ── Defense Weights ────────────────────────────────────
  const DEFENSE_WEIGHTS = {
    defRateLimit:  15,
    defBlacklist:  14,
    defSynCookie:  18,
    defScrubbing:  20,
    defGeoBlock:   12,
    defCaptcha:    10,
    defAnycast:    11,
  };

  // ── Helpers ────────────────────────────────────────────
  function rand(min, max) { return Math.random() * (max - min) + min; }
  function randInt(min, max) { return Math.floor(rand(min, max)); }
  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

  function generateIP() {
    const prefixes = ['10.', '172.', '185.', '91.', '46.', '103.', '45.'];
    const p = prefixes[randInt(0, prefixes.length)];
    return p + randInt(0,255)+'.'+randInt(0,255)+'.'+randInt(0,255);
  }

  function jitter(v, pct = 0.12) {
    return v * (1 + (Math.random() - 0.5) * pct * 2);
  }

  // ── Compute Defense Score ──────────────────────────────
  function computeDefenseScore() {
    let score = 0;
    const vector = state.attackVector;
    for (const [key, weight] of Object.entries(DEFENSE_WEIGHTS)) {
      if (state.defenses[key]) score += weight;
    }
    // Synergy bonus
    if (state.defenses.defScrubbing && state.defenses.defRateLimit) score += 5;
    if (state.defenses.defBlacklist && state.defenses.defGeoBlock) score += 4;
    state.defenseScore = clamp(score, 0, 100);
    return state.defenseScore;
  }

  // ── Compute Threat Level ───────────────────────────────
  function computeThreat(bw, pps, blocked) {
    if (!state.running) return 'LOW';
    const effectiveBW = bw * (1 - blocked / 100);
    if (effectiveBW > 800) return 'CRITICAL';
    if (effectiveBW > 400) return 'HIGH';
    if (effectiveBW > 100) return 'MEDIUM';
    return 'LOW';
  }

  // ── Push History ───────────────────────────────────────
  function pushHistory(attack, legit, blocked, cpu, mem, conn) {
    const h = state.history;
    h.attackTraffic.push(attack); h.attackTraffic.shift();
    h.legitTraffic.push(legit);   h.legitTraffic.shift();
    h.blockedTraffic.push(blocked); h.blockedTraffic.shift();
    h.cpu.push(cpu);  h.cpu.shift();
    h.mem.push(mem);  h.mem.shift();
    h.conn.push(conn); h.conn.shift();
  }

  // ── Add Event ──────────────────────────────────────────
  function addEvent(type, msg) {
    const ts = new Date().toISOString().substr(11,8);
    state.events.unshift({ type, msg, ts });
    if (state.events.length > 100) state.events.pop();
  }

  // ── Tick (called every 800ms) ──────────────────────────
  function tick() {
    if (!state.running) return;
    state.tick++;
    state.elapsedSeconds = Math.round((Date.now() - state.startTime) / 1000);

    const rate = parseInt(document.getElementById('packetRate').value) || 1000;
    const bots = parseInt(document.getElementById('botnetSize').value) || 50;
    const vector = document.getElementById('attackType').value;
    const profile = ATTACK_PROFILES[vector] || ATTACK_PROFILES.syn;
    state.attackVector = vector;

    const isDoS  = state.attackType === 'dos';
    const isDDoS = state.attackType === 'ddos';
    const nodeMultiplier = isDDoS ? Math.min(bots / 10, 30) : 1;
    state.activeNodes = isDDoS ? Math.floor(bots * rand(0.7, 1.0)) : 1;

    const defScore = computeDefenseScore();
    const defEff = defScore / 100;

    // ── Raw attack traffic ──
    const rawBW  = jitter(rate * profile.bwFactor * nodeMultiplier / 10, 0.15);
    const rawPPS = jitter(rate * profile.ppsFactor * nodeMultiplier, 0.15);

    // ── Blocked pct ──
    const baseBlockPct = clamp(defEff * 90 + 5, 5, 98);
    const blockPct = jitter(baseBlockPct, 0.08);

    // ── Effective metrics ──
    const effectiveBW  = rawBW  * (1 - blockPct / 100);
    const effectivePPS = rawPPS * (1 - blockPct / 100);

    // ── Legit traffic ──
    const legitBW = jitter(20 + (1 - defEff) * 80, 0.1);

    // ── Latency ──
    const baseLatency = 12;
    const latencySpike = profile.latFactor * effectiveBW / 50;
    const latency = jitter(clamp(baseLatency + latencySpike, 12, 5000), 0.1);

    // ── CPU/MEM/CONN ──
    const cpuLoad = clamp(20 + effectiveBW / 5 + rand(0, 10), 10, 100);
    const memLoad = clamp(30 + effectiveBW / 8 + rand(0, 5), 20, 95);
    const connLoad = clamp(5  + effectivePPS / 200, 5, 100);

    // Update state
    state.incomingTraffic = rawBW;
    state.packetsPerSec   = Math.round(rawPPS);
    state.blockedPct      = Math.round(blockPct);
    state.latency         = Math.round(latency);
    state.threatLevel     = computeThreat(rawBW, rawPPS, blockPct);

    pushHistory(
      Math.round(rawBW),
      Math.round(legitBW),
      Math.round(rawBW * blockPct / 100),
      Math.round(cpuLoad),
      Math.round(memLoad),
      Math.round(connLoad)
    );

    // ── IP blocking events ──
    if (state.tick % 2 === 0) {
      const ip = generateIP();
      state.blockedIPs.add(ip);
      if (Math.random() > 0.5 && state.defenses.defBlacklist) {
        state.sourceIPs.push(ip);
        addEvent('danger', `BLOCKED: ${ip} — ${profile.name} packet dropped`);
      }
    }

    // ── Defense events ──
    if (state.tick % 5 === 0) {
      const mitigations = getMitigationMessages();
      if (mitigations.length) {
        addEvent('success', mitigations[randInt(0, mitigations.length)]);
      }
    }

    // ── Attack events ──
    if (state.tick % 3 === 0) {
      addEvent('warn', `${profile.name} from ${state.activeNodes} source(s) — ${Math.round(rawPPS)} pps`);
    }

    // ── Stats ──
    if (state.tick === 1) {
      state.stats.total++;
      state.stats.ongoing++;
    }
    if (blockPct > 80) {
      if (state.tick % 20 === 0) {
        state.stats.mitigated++;
        state.stats.ongoing = Math.max(0, state.stats.ongoing - 1);
      }
    } else {
      if (state.tick % 30 === 0) state.stats.penetrated++;
    }
  }

  function getMitigationMessages() {
    const msgs = [];
    if (state.defenses.defRateLimit)  msgs.push('Rate limit enforced — threshold exceeded');
    if (state.defenses.defBlacklist)  msgs.push('IP blacklisted and dropped');
    if (state.defenses.defSynCookie)  msgs.push('SYN cookie challenge sent');
    if (state.defenses.defScrubbing)  msgs.push('Traffic scrubbed at edge node');
    if (state.defenses.defGeoBlock)   msgs.push('GeoBlock: origin country filtered');
    if (state.defenses.defCaptcha)    msgs.push('CAPTCHA challenge issued');
    if (state.defenses.defAnycast)    msgs.push('Traffic diffused via Anycast');
    return msgs;
  }

  // ── Public API ─────────────────────────────────────────
  return {
    get state() { return state; },

    start(type) {
      state.running = true;
      state.attackType = type;
      state.startTime = Date.now();
      state.tick = 0;
      state.blockedIPs.clear();
      state.sourceIPs = [];
      addEvent('danger', `⚠ ${type.toUpperCase()} ATTACK INITIATED`);
    },

    stop() {
      state.running = false;
      state.attackType = null;
      state.incomingTraffic = 0;
      state.packetsPerSec = 0;
      state.blockedPct = 0;
      state.latency = 12;
      state.threatLevel = 'LOW';
      state.activeNodes = 0;
      addEvent('success', '✓ Attack simulation stopped');
    },

    tick,

    updateDefenses(defenses) {
      state.defenses = { ...defenses };
      computeDefenseScore();
    },

    reset() {
      this.stop();
      state.tick = 0;
      state.elapsedSeconds = 0;
      state.stats = { total:0, mitigated:0, penetrated:0, ongoing:0 };
      state.events = [];
      state.blockedIPs.clear();
      for (const k of Object.keys(state.history)) {
        const def = k.includes('cpu') ? 10 : k.includes('mem') ? 30 : 5;
        state.history[k] = new Array(60).fill(def);
      }
      addEvent('info', 'System reset. Monitoring resumed.');
    },

    getPacketDistribution() {
      const v = state.attackVector || 'syn';
      const profile = ATTACK_PROFILES[v];
      const blocked = state.blockedPct / 100;
      const attack  = state.incomingTraffic;
      const legit   = 20;
      return {
        labels: ['SYN', 'UDP', 'ICMP', 'HTTP', 'Legitimate', 'Blocked'],
        values: [
          v==='syn'  ? attack*0.6 : attack*0.1,
          v==='udp'  ? attack*0.6 : attack*0.1,
          v==='icmp' ? attack*0.5 : attack*0.08,
          v==='http' ? attack*0.6 : attack*0.1,
          legit,
          attack * blocked,
        ],
        colors: ['#ff3366','#ff6633','#ffaa00','#cc33ff','#00ff9f','#00d4ff'],
      };
    },
  };
})();
