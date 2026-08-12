// ═══════════════════════════════════════════════════════════════
//  NexaBank SQLi Lab — Shared Bridge (nexabridge.js)
//  Include in index.html, search.html, profile.html
// ═══════════════════════════════════════════════════════════════

const _ch = new BroadcastChannel('sqli_monitor');

// Simulated attacker IP pool
const _ATTACKER_IPS = [
  '185.220.101.47','45.142.212.100','194.165.16.11','91.108.4.24',
  '193.32.162.8','185.107.80.202','162.247.74.201','198.98.50.112',
  '89.234.157.254','178.17.170.135','104.244.72.115','176.10.104.240',
  '212.21.66.6','171.25.193.77','51.15.43.205','77.247.181.163',
  '192.42.116.16','5.39.216.150','46.166.148.142','198.50.200.129'
];
const _MY_IP = '127.0.0.1';

// Attack type classifier
const _CLASSIFIERS = [
  { type:'Auth Bypass',       color:'#ff3854', re:/('\s*(or|OR)\s*'?[^']*'?\s*=\s*'?|'\s*(or|OR)\s+\d+\s*=\s*\d+|--\s*$|#\s*$)/  },
  { type:'UNION Extraction',  color:'#ff7f00', re:/UNION\s+(ALL\s+)?SELECT/i  },
  { type:'Boolean Blind',     color:'#ffaa00', re:/AND\s+\d+=\d+|AND\s+'\w+'\s*=\s*'\w+'/i },
  { type:'Time-based Blind',  color:'#e040fb', re:/SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(/i },
  { type:'Error-based',       color:'#00bcd4', re:/EXTRACTVALUE|UPDATEXML|FLOOR\(RAND/i },
  { type:'Schema Enum',       color:'#ff6090', re:/INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS|SYS\.TABLES/i },
  { type:'Stacked Queries',   color:'#b0ff40', re:/;\s*(DROP|INSERT|UPDATE|DELETE|SELECT)\s/i },
  { type:'Comment Injection', color:'#40c4ff', re:/(--|#|\/\*.*\*\/)/ },
  { type:'Function Exploit',  color:'#69f0ae', re:/CHAR\s*\(|CONCAT\s*\(|GROUP_CONCAT\s*\(|LOAD_FILE\s*\(/i },
  { type:'Classic Tautology', color:'#ff5252', re:/'1'\s*=\s*'1|'a'\s*=\s*'a|1\s*=\s*1/i },
];

function _classifyAttack(payload) {
  for (const c of _CLASSIFIERS) {
    if (c.re.test(payload)) return c;
  }
  return { type:'Unknown Injection', color:'#9e9e9e' };
}

const _SQLI_PATTERNS = [
  { re:/(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b)/i, label:'SQL Keyword' },
  { re:/(--|#|\/\*|\*\/)/,   label:'SQL Comment' },
  { re:/('\s*(OR|AND)\s*'?\d*'?\s*=\s*'?\d*'?)/i, label:'Boolean Bypass' },
  { re:/('\s*OR\s*'1'\s*=\s*'1'?)/i, label:"Classic OR '1'='1'" },
  { re:/('|"|;)/,            label:'Quote/Semicolon' },
  { re:/(\bSLEEP\b|\bWAITFOR\b|\bBENCHMARK\b)/i, label:'Time-based Blind' },
  { re:/(\bINFORMATION_SCHEMA\b|\bSYSTABLES\b|\bSYSCOLUMNS\b)/i, label:'Schema Enum' },
  { re:/(CHAR\s*\(|CONCAT\s*\(|GROUP_CONCAT\s*\()/i, label:'Function Injection' },
  { re:/(UNION\s+SELECT)/i,  label:'UNION SELECT' },
  { re:/'\s*--/,             label:'Comment Bypass' },
];

function _detectSQLi(val) {
  return _SQLI_PATTERNS.filter(p => p.re.test(val)).map(p => p.label);
}

function _randomIP(isAttack) {
  if (!isAttack) return _MY_IP;
  return _ATTACKER_IPS[Math.floor(Math.random() * _ATTACKER_IPS.length)];
}

// Vulnerable vs Secure SQL mode
let _secureMode = false;
function _setSecureMode(v) { _secureMode = v; }

function _buildSQL_login(username, password) {
  if (_secureMode) {
    return `-- ✅ SECURE (Prepared Statement)\nSELECT * FROM users WHERE username = ? AND password = ?\n-- Parameters: ["${username}", "${password}"]`;
  }
  return `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
}
function _buildSQL_search(term, by) {
  if (_secureMode) {
    return by === 'id'
      ? `-- ✅ SECURE\nSELECT * FROM users WHERE id = ?\n-- Parameters: [${parseInt(term)||0}]`
      : `-- ✅ SECURE\nSELECT * FROM users WHERE username LIKE ?\n-- Parameters: ["%${term}%"]`;
  }
  return by === 'id'
    ? `SELECT id, username, role, balance FROM users WHERE id = '${term}'`
    : `SELECT id, username, role, balance FROM users WHERE username LIKE '%${term}%'`;
}
function _buildSQL_profile(username) {
  if (_secureMode) {
    return `-- ✅ SECURE (Prepared Statement)\nSELECT * FROM users WHERE username = ?\n-- Parameters: ["${username}"]`;
  }
  return `SELECT * FROM users WHERE username = '${username}'`;
}

function _broadcast(data) {
  _ch.postMessage({ ...data, ts: new Date().toISOString() });
}
