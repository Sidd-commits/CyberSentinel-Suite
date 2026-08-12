/**
 * charts.js — Canvas-based chart rendering
 * All charts drawn manually on HTML5 Canvas for zero-dependency performance.
 */

const Charts = (() => {

  const COLORS = {
    accent:  '#00d4ff',
    accent2: '#00ff9f',
    danger:  '#ff3366',
    warning: '#ffaa00',
    muted:   '#1a3a5c',
    text:    '#3a6080',
    bg:      '#0d1a27',
  };

  // ── Utility ────────────────────────────────────────────
  function hexToRgba(hex, a) {
    const r = parseInt(hex.slice(1,3),16);
    const g = parseInt(hex.slice(3,5),16);
    const b = parseInt(hex.slice(5,7),16);
    return `rgba(${r},${g},${b},${a})`;
  }

  function clear(ctx, w, h) {
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = COLORS.bg;
    ctx.fillRect(0, 0, w, h);
  }

  // ── Line/Area Chart (Traffic) ──────────────────────────
  function drawTrafficChart(canvasId, history) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.parentElement.offsetWidth - 28;
    const H = 200;
    canvas.width = W; canvas.height = H;
    clear(ctx, W, H);

    const PAD = { top: 20, right: 20, bottom: 30, left: 50 };
    const pw = W - PAD.left - PAD.right;
    const ph = H - PAD.top - PAD.bottom;

    // Grid
    ctx.strokeStyle = COLORS.muted;
    ctx.lineWidth = 0.5;
    for (let i = 0; i <= 4; i++) {
      const y = PAD.top + (ph / 4) * i;
      ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(W - PAD.right, y); ctx.stroke();
    }

    // Compute max
    const allVals = [...history.attackTraffic, ...history.legitTraffic, ...history.blockedTraffic];
    const maxVal = Math.max(...allVals, 10);

    function toX(i) { return PAD.left + (i / (history.attackTraffic.length - 1)) * pw; }
    function toY(v) { return PAD.top + ph - (v / maxVal) * ph; }

    // Draw area + line for each series
    const series = [
      { data: history.blockedTraffic, stroke: COLORS.warning,  fill: hexToRgba(COLORS.warning,  0.08) },
      { data: history.legitTraffic,   stroke: COLORS.accent2,  fill: hexToRgba(COLORS.accent2,  0.08) },
      { data: history.attackTraffic,  stroke: COLORS.danger,   fill: hexToRgba(COLORS.danger,   0.12) },
    ];

    series.forEach(({ data, stroke, fill }) => {
      // Area
      ctx.beginPath();
      ctx.moveTo(toX(0), H - PAD.bottom);
      data.forEach((v, i) => ctx.lineTo(toX(i), toY(v)));
      ctx.lineTo(toX(data.length-1), H - PAD.bottom);
      ctx.closePath();
      ctx.fillStyle = fill;
      ctx.fill();

      // Line
      ctx.beginPath();
      data.forEach((v, i) => { i===0 ? ctx.moveTo(toX(i), toY(v)) : ctx.lineTo(toX(i), toY(v)); });
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Glow
      ctx.shadowColor = stroke;
      ctx.shadowBlur = 4;
      ctx.stroke();
      ctx.shadowBlur = 0;
    });

    // Y-axis labels
    ctx.fillStyle = COLORS.text;
    ctx.font = '10px Share Tech Mono';
    ctx.textAlign = 'right';
    for (let i = 0; i <= 4; i++) {
      const v = Math.round(maxVal * (1 - i/4));
      ctx.fillText(v + ' M', PAD.left - 4, PAD.top + (ph/4)*i + 4);
    }

    // X-axis
    ctx.fillStyle = COLORS.text;
    ctx.textAlign = 'center';
    ['60s', '45s', '30s', '15s', 'now'].forEach((lbl, i) => {
      ctx.fillText(lbl, PAD.left + pw * i/4, H - 8);
    });
  }

  // ── Donut/Pie Chart ────────────────────────────────────
  function drawPieChart(canvasId, data) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.parentElement.offsetWidth - 28;
    const H = 200;
    canvas.width = W; canvas.height = H;
    clear(ctx, W, H);

    const total = data.values.reduce((s, v) => s + v, 0);
    if (total === 0) {
      ctx.fillStyle = COLORS.text;
      ctx.font = '11px Share Tech Mono';
      ctx.textAlign = 'center';
      ctx.fillText('No traffic data', W/2, H/2);
      return;
    }

    const cx = W * 0.38, cy = H/2, r = Math.min(W*0.28, H*0.38);
    let angle = -Math.PI / 2;

    data.values.forEach((v, i) => {
      const slice = (v / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, angle, angle + slice);
      ctx.closePath();
      ctx.fillStyle = data.colors[i];
      ctx.fill();
      ctx.strokeStyle = COLORS.bg;
      ctx.lineWidth = 2;
      ctx.stroke();
      angle += slice;
    });

    // Donut hole
    ctx.beginPath();
    ctx.arc(cx, cy, r * 0.5, 0, Math.PI * 2);
    ctx.fillStyle = COLORS.bg;
    ctx.fill();

    // Center label
    ctx.fillStyle = '#fff';
    ctx.font = 'bold 13px Orbitron';
    ctx.textAlign = 'center';
    ctx.fillText(Math.round(total), cx, cy + 4);
    ctx.font = '9px Share Tech Mono';
    ctx.fillStyle = COLORS.text;
    ctx.fillText('Mbps', cx, cy + 16);

    // Legend
    const lx = cx + r + 20;
    let ly = cy - (data.labels.length * 14) / 2;
    ctx.textAlign = 'left';
    data.labels.forEach((lbl, i) => {
      ctx.fillStyle = data.colors[i];
      ctx.fillRect(lx, ly - 7, 10, 10);
      ctx.font = '10px Share Tech Mono';
      ctx.fillStyle = COLORS.text;
      ctx.fillText(`${lbl} (${Math.round(data.values[i])})`, lx + 14, ly + 3);
      ly += 16;
    });
  }

  // ── Resource Bar Chart ─────────────────────────────────
  function drawResourceChart(canvasId, history) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.parentElement.offsetWidth - 28;
    const H = 200;
    canvas.width = W; canvas.height = H;
    clear(ctx, W, H);

    const PAD = { top: 20, right: 20, bottom: 30, left: 50 };
    const pw = W - PAD.left - PAD.right;
    const ph = H - PAD.top - PAD.bottom;

    // Grid
    ctx.strokeStyle = COLORS.muted;
    ctx.lineWidth = 0.5;
    for (let i = 0; i <= 4; i++) {
      const y = PAD.top + (ph / 4) * i;
      ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(W - PAD.right, y); ctx.stroke();
    }

    const series = [
      { data: history.cpu,  stroke: COLORS.danger,  label: 'CPU' },
      { data: history.mem,  stroke: COLORS.warning,  label: 'MEM' },
      { data: history.conn, stroke: COLORS.accent,   label: 'CONN' },
    ];

    function toX(i) { return PAD.left + (i / (history.cpu.length - 1)) * pw; }
    function toY(v)  { return PAD.top + ph - (v / 100) * ph; }

    series.forEach(({ data, stroke }) => {
      ctx.beginPath();
      data.forEach((v, i) => i===0 ? ctx.moveTo(toX(i), toY(v)) : ctx.lineTo(toX(i), toY(v)));
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 1.5;
      ctx.shadowColor = stroke;
      ctx.shadowBlur = 4;
      ctx.stroke();
      ctx.shadowBlur = 0;
    });

    // Y-axis
    ctx.fillStyle = COLORS.text;
    ctx.font = '10px Share Tech Mono';
    ctx.textAlign = 'right';
    ['100%','75%','50%','25%','0%'].forEach((lbl, i) => {
      ctx.fillText(lbl, PAD.left - 4, PAD.top + (ph/4)*i + 4);
    });

    // Legend
    ctx.textAlign = 'left';
    series.forEach(({ stroke, label }, i) => {
      ctx.fillStyle = stroke;
      ctx.fillRect(PAD.left + i*60, H - 12, 14, 3);
      ctx.font = '10px Share Tech Mono';
      ctx.fillStyle = COLORS.text;
      ctx.fillText(label, PAD.left + i*60 + 18, H - 6);
    });
  }

  // ── World Map (SVG-style on canvas) ───────────────────
  function drawMap(canvasId, sourceIPs) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = 280, H = 160;
    clear(ctx, W, H);

    // Draw simple world outline (simplified continents)
    ctx.strokeStyle = '#1a3a5c';
    ctx.lineWidth = 0.5;
    ctx.fillStyle = '#0f2030';

    // Grid lines
    for (let i = 0; i <= 6; i++) {
      ctx.beginPath();
      ctx.moveTo(i * W/6, 0);
      ctx.lineTo(i * W/6, H);
      ctx.stroke();
    }
    for (let i = 0; i <= 4; i++) {
      ctx.beginPath();
      ctx.moveTo(0, i * H/4);
      ctx.lineTo(W, i * H/4);
      ctx.stroke();
    }

    // Draw simplified continents as polygons
    const continents = [
      // North America
      [[0.08,0.15],[0.22,0.12],[0.26,0.2],[0.24,0.45],[0.18,0.55],[0.1,0.5],[0.06,0.35]],
      // South America
      [[0.18,0.55],[0.25,0.55],[0.28,0.85],[0.2,0.92],[0.14,0.8],[0.15,0.65]],
      // Europe
      [[0.42,0.1],[0.55,0.08],[0.56,0.25],[0.5,0.32],[0.42,0.28],[0.4,0.18]],
      // Africa
      [[0.44,0.3],[0.57,0.28],[0.58,0.7],[0.52,0.82],[0.44,0.75],[0.41,0.55],[0.43,0.38]],
      // Asia
      [[0.55,0.08],[0.88,0.06],[0.9,0.35],[0.78,0.5],[0.7,0.45],[0.62,0.38],[0.57,0.25]],
      // Australia
      [[0.75,0.62],[0.88,0.6],[0.9,0.8],[0.8,0.85],[0.73,0.78]],
    ];

    continents.forEach(pts => {
      ctx.beginPath();
      pts.forEach(([x,y], i) => {
        const px = x*W, py = y*H;
        i===0 ? ctx.moveTo(px,py) : ctx.lineTo(px,py);
      });
      ctx.closePath();
      ctx.fillStyle = '#0f2840';
      ctx.fill();
      ctx.strokeStyle = '#1a4060';
      ctx.lineWidth = 1;
      ctx.stroke();
    });

    // Attack origin dots
    const origins = [
      [0.15,0.25],[0.5,0.15],[0.7,0.2],[0.6,0.4],[0.8,0.65],
      [0.45,0.5],[0.2,0.65],[0.65,0.15],[0.85,0.2],[0.35,0.2],
    ];

    const numActive = Math.min(Math.floor(sourceIPs.length / 3 + 1), origins.length);
    origins.slice(0, numActive).forEach(([x,y]) => {
      const px = x*W, py = y*H;
      const t = Date.now() / 1000;
      const pulse = Math.sin(t * 3 + x*10) * 0.5 + 0.5;

      // Ping ring
      ctx.beginPath();
      ctx.arc(px, py, 4 + pulse*5, 0, Math.PI*2);
      ctx.strokeStyle = `rgba(255,51,102,${0.6 - pulse*0.5})`;
      ctx.lineWidth = 1;
      ctx.stroke();

      // Dot
      ctx.beginPath();
      ctx.arc(px, py, 3, 0, Math.PI*2);
      ctx.fillStyle = '#ff3366';
      ctx.fill();
      ctx.shadowColor = '#ff3366';
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;

      // Line to target (center)
      ctx.beginPath();
      ctx.moveTo(px, py);
      ctx.lineTo(0.5*W, 0.4*H);
      ctx.strokeStyle = `rgba(255,51,102,${0.1 + pulse*0.15})`;
      ctx.lineWidth = 0.5;
      ctx.stroke();
    });

    // Target (server)
    ctx.beginPath();
    ctx.arc(0.5*W, 0.4*H, 5, 0, Math.PI*2);
    ctx.fillStyle = '#00d4ff';
    ctx.shadowColor = '#00d4ff';
    ctx.shadowBlur = 10;
    ctx.fill();
    ctx.shadowBlur = 0;
  }

  // Public
  return { drawTrafficChart, drawPieChart, drawResourceChart, drawMap };
})();
