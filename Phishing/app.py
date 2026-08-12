"""
Phishing URL Detection System - Python Dashboard v2
Run: python app.py
Then open: http://localhost:5000
"""

import os
import re
import json
import csv
import time
import base64
import hashlib
import threading
import requests
from datetime import datetime
from urllib.parse import urlparse, quote
from flask import Flask, request, jsonify, render_template_string, make_response

app = Flask(__name__)

# ─── CORS (allows Chrome extension to call local API) ──────────────────────────
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        resp = make_response()
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp, 200

# ─── Configuration ──────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR  = os.path.join(BASE_DIR, '..', 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'url_logs.json')
CSV_FILE = os.path.join(LOG_DIR, 'url_logs.csv')
CONFIG_FILE = os.path.join(BASE_DIR, 'config.json')
os.makedirs(LOG_DIR, exist_ok=True)


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_config(config_data):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config_data, f, indent=2)


def load_virustotal_api_key():
    env_key = (os.environ.get('VIRUSTOTAL_API_KEY') or '').strip()
    if env_key:
        return env_key, 'environment'

    config_key = (load_config().get('virustotal_api_key') or '').strip()
    if config_key:
        return config_key, 'config_file'

    return '', 'not_configured'


VIRUSTOTAL_API_KEY, API_KEY_SOURCE = load_virustotal_api_key()

# ─── Phishing Detection Data ────────────────────────────────────────────────────

# Keywords that often appear in phishing domain names
PHISHING_DOMAIN_KEYWORDS = [
    'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
    'secure', 'security', 'update', 'confirm', 'confirmation',
    'account', 'accounts', 'banking', 'password', 'credential',
    'wallet', 'recover', 'recovery', 'validate', 'unlock',
    'suspend', 'suspended', 'alert', 'helpdesk', 'support-',
    'prize', 'winner', 'reward', 'free-', 'gift', 'lucky',
    'urgent', 'limited', 'offer', 'click-here'
]

# Well-known brands commonly impersonated in phishing
IMPERSONATED_BRANDS = {
    'paypal':       'paypal.com',
    'amazon':       'amazon.com',
    'apple':        'apple.com',
    'microsoft':    'microsoft.com',
    'google':       'google.com',
    'netflix':      'netflix.com',
    'facebook':     'facebook.com',
    'instagram':    'instagram.com',
    'twitter':      'twitter.com',
    'ebay':         'ebay.com',
    'chase':        'chase.com',
    'wellsfargo':   'wellsfargo.com',
    'citibank':     'citibank.com',
    'bankofamerica':'bankofamerica.com',
    'hsbc':         'hsbc.com',
    'irs':          'irs.gov',
    'dhl':          'dhl.com',
    'fedex':        'fedex.com',
    'ups':          'ups.com',
    'linkedin':     'linkedin.com',
    'dropbox':      'dropbox.com',
}

# Genuinely trusted base domains (only exact base domain match gets score reduction)
WHITELIST_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com',
    'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
    'reddit.com', 'wikipedia.org', 'amazon.com', 'apple.com', 'microsoft.com',
    'netflix.com', 'spotify.com', 'paypal.com', 'ebay.com', 'adobe.com',
    'dropbox.com', 'slack.com', 'zoom.us', 'notion.so', 'figma.com',
    'cloudflare.com', 'aws.amazon.com', 'azure.microsoft.com',
    'accounts.google.com', 'mail.google.com', 'drive.google.com',
}

# Free/suspicious TLDs heavily abused for phishing
HIGH_RISK_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq',   # Free Freenom TLDs — extremely abused
    '.xyz', '.top', '.club', '.online', '.site', '.website',
    '.space', '.fun', '.icu', '.vip', '.work', '.link',
    '.click', '.download', '.loan', '.win', '.bid', '.stream',
    '.gdn', '.racing', '.date', '.accountant', '.review', '.trade',
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.io',
    'rebrand.ly', 'is.gd', 'buff.ly', 'ift.tt', 'adf.ly', 'bc.vc',
    'cli.gs', 'tiny.cc', 'url4.eu', 'qr.ae', 'mcaf.ee', 'cutt.ly',
}


def get_base_domain(domain):
    """Extract the base domain (e.g. sub.example.com → example.com)."""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def analyze_url_rules(url):
    """
    Rule-based phishing detection.
    Returns dict with score (0-100), verdict, reasons, flags.
    """
    score = 0
    reasons = []
    flags = []

    try:
        parsed = urlparse(url)
        domain   = parsed.netloc.lower().split(':')[0]  # strip port
        path     = parsed.path.lower()
        query    = parsed.query.lower()
        full_url = url.lower()
        base     = get_base_domain(domain)

        # ── WHITELIST: exact base domain match → heavily reduce and early-exit ──
        if base in WHITELIST_DOMAINS or domain in WHITELIST_DOMAINS:
            # Still flag if path looks like a phish of a legit subdomain
            bad_path = any(k in path for k in ['verify', 'confirm', 'suspended', 'unlock'])
            if not bad_path:
                return {
                    'score': 0,
                    'verdict': 'safe',
                    'reasons': ['Domain is on the trusted whitelist'],
                    'flags': ['whitelisted']
                }

        # ── Rule 1: HTTP (no encryption) ──────────────────────────────────────
        if parsed.scheme == 'http':
            score += 20
            reasons.append("No HTTPS — connection is unencrypted")
            flags.append("no_https")

        # ── Rule 2: Raw IP address instead of domain ───────────────────────────
        ip_re = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
        if ip_re.match(domain):
            score += 50
            reasons.append("IP address used as host (no domain name)")
            flags.append("ip_address")

        # ── Rule 3: High-risk / free TLD ──────────────────────────────────────
        for tld in HIGH_RISK_TLDS:
            if domain.endswith(tld):
                score += 30
                reasons.append(f"High-risk free TLD used: {tld}")
                flags.append("suspicious_tld")
                break

        # ── Rule 4: Too many subdomains (phishers love long chains) ────────────
        dot_count = domain.count('.')
        if dot_count >= 4:
            score += 25
            reasons.append(f"Excessive subdomain depth ({dot_count} levels)")
            flags.append("excessive_subdomains")
        elif dot_count == 3:
            score += 12
            reasons.append("Multiple subdomain levels detected")
            flags.append("multiple_subdomains")

        # ── Rule 5: Very long URL ──────────────────────────────────────────────
        url_len = len(url)
        if url_len > 250:
            score += 25
            reasons.append(f"Very long URL ({url_len} chars) — common obfuscation")
            flags.append("very_long_url")
        elif url_len > 150:
            score += 12
            reasons.append(f"Unusually long URL ({url_len} chars)")
            flags.append("long_url")

        # ── Rule 6: Brand impersonation ────────────────────────────────────────
        for brand, legit_domain in IMPERSONATED_BRANDS.items():
            if brand in domain and base != legit_domain:
                score += 40
                reasons.append(f"Impersonates '{brand}' but domain is not {legit_domain}")
                flags.append("brand_impersonation")
                break

        # ── Rule 7: Phishing keywords IN the domain name ──────────────────────
        kw_hits = [kw for kw in PHISHING_DOMAIN_KEYWORDS if kw in domain]
        if kw_hits:
            pts = min(len(kw_hits) * 12, 35)
            score += pts
            reasons.append(f"Phishing keywords in domain: {', '.join(kw_hits)}")
            flags.append("phishing_keywords")

        # ── Rule 8: @ in URL (classic trick to hide real destination) ──────────
        if '@' in url:
            score += 35
            reasons.append("'@' symbol in URL — hides the true destination")
            flags.append("at_symbol")

        # ── Rule 9: Double-slash in path (open-redirect trick) ─────────────────
        if re.search(r'(?<!/)//', path):
            score += 18
            reasons.append("Double-slash in URL path — possible redirect trick")
            flags.append("double_slash")

        # ── Rule 10: URL shortener ─────────────────────────────────────────────
        if base in URL_SHORTENERS:
            score += 22
            reasons.append(f"URL shortener ({base}) hides the real destination")
            flags.append("url_shortener")

        # ── Rule 11: Lots of digits in domain name ─────────────────────────────
        label = domain.split('.')[0]   # first label, e.g. "amaz0n" or "pay-pal1"
        digit_count = len(re.findall(r'\d', label))
        if digit_count >= 3:
            score += 18
            reasons.append(f"Many digits in domain name ({digit_count}) — typosquatting?")
            flags.append("digits_in_domain")

        # ── Rule 12: Heavy URL-encoding / obfuscation ──────────────────────────
        pct_count = url.count('%')
        if pct_count >= 5:
            score += 25
            reasons.append(f"Heavy URL encoding ({pct_count} encoded chars) — obfuscation")
            flags.append("url_encoding")
        elif pct_count >= 2:
            score += 10
            reasons.append("URL-encoded characters detected")

        # ── Rule 13: Sensitive action words in path ────────────────────────────
        path_triggers = ['login', 'signin', 'sign-in', 'verify', 'verification',
                         'account', 'secure', 'update', 'confirm', 'password',
                         'credential', 'recover', 'unlock', 'validate', 'suspended']
        path_hits = [k for k in path_triggers if k in path]
        if path_hits:
            pts = min(len(path_hits) * 8, 28)
            score += pts
            reasons.append(f"Sensitive action words in path: {', '.join(path_hits)}")
            flags.append("sensitive_path")

        # ── Rule 14: Redirect / callback parameters ───────────────────────────
        redirect_params = ['redirect=', 'return_url=', 'callback=', 'next=',
                           'goto=', 'target=', 'destination=', 'redir=']
        redir_hits = [p for p in redirect_params if p in query]
        if redir_hits:
            score += 15
            reasons.append(f"Redirect parameters in query string: {', '.join(redir_hits)}")
            flags.append("redirect_param")

        # ── Rule 15: Hyphens in domain (common in phishing, e.g. pay-pal-secure) ─
        hyphen_count = label.count('-')
        if hyphen_count >= 2:
            score += 15
            reasons.append(f"Multiple hyphens in domain label ({hyphen_count}) — often used in phishing")
            flags.append("domain_hyphens")
        elif hyphen_count == 1 and any(b in domain for b in IMPERSONATED_BRANDS):
            score += 10
            reasons.append("Hyphen in domain containing a brand name")

        # ── Rule 16: Punycode / international domain (IDN homograph) ──────────
        if 'xn--' in domain:
            score += 40
            reasons.append("Punycode / IDN domain — possible homograph phishing attack")
            flags.append("punycode")

        # ── Rule 17: No meaningful TLD (just numbers or very short) ───────────
        tld_part = domain.split('.')[-1] if '.' in domain else ''
        if tld_part.isdigit():
            score += 20
            reasons.append("TLD is numeric — not a valid domain")
            flags.append("numeric_tld")

    except Exception as e:
        reasons.append(f"URL parse error: {str(e)}")

    # ── Final verdict ─────────────────────────────────────────────────────────
    score = min(score, 100)
    if score >= 55:
        verdict = 'phishing'
    elif score >= 25:
        verdict = 'suspicious'
    else:
        verdict = 'safe'

    return {
        'score': score,
        'verdict': verdict,
        'reasons': reasons if reasons else ['No suspicious patterns detected'],
        'flags': flags
    }


# ─── VirusTotal Integration ─────────────────────────────────────────────────────

def check_virustotal(url):
    """
    Check URL via VirusTotal v3 API.
    Uses URL ID lookup first (instant if already scanned), then submits for scan.
    """
    global VIRUSTOTAL_API_KEY
    if not VIRUSTOTAL_API_KEY:
        return {'available': False, 'message': 'VirusTotal API key not configured'}

    headers = {'x-apikey': VIRUSTOTAL_API_KEY, 'Accept': 'application/json'}

    try:
        # VT URL ID = base64url(url) without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')

        # Step 1: try direct lookup (avoids rate limits if URL was scanned before)
        lookup = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers=headers, timeout=15
        )

        if lookup.status_code == 200:
            return _parse_vt_response(lookup.json())

        # Step 2: submit URL for scanning
        submit = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers={**headers, 'Content-Type': 'application/x-www-form-urlencoded'},
            data=f'url={quote(url, safe="")}',
            timeout=15
        )

        if submit.status_code not in (200, 201, 202):
            return {'available': False, 'message': f'VT submit error: {submit.status_code} — {submit.text[:120]}'}

        analysis_id = submit.json()['data']['id']

        # Step 3: poll analysis result (up to 20s)
        for _ in range(4):
            time.sleep(5)
            analysis = requests.get(
                f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                headers=headers, timeout=15
            )
            if analysis.status_code == 200:
                data = analysis.json()
                if data['data']['attributes']['status'] == 'completed':
                    return _parse_vt_analysis(data)

        return {'available': False, 'message': 'VT analysis timed out — try again shortly'}

    except requests.exceptions.Timeout:
        return {'available': False, 'message': 'VirusTotal request timed out'}
    except Exception as e:
        return {'available': False, 'message': f'VT error: {str(e)}'}


def _parse_vt_response(data):
    """Parse a /urls/{id} response."""
    try:
        stats = data['data']['attributes']['last_analysis_stats']
        return _make_vt_result(stats)
    except Exception as e:
        return {'available': False, 'message': f'VT parse error: {e}'}


def _parse_vt_analysis(data):
    """Parse an /analyses/{id} response."""
    try:
        stats = data['data']['attributes']['stats']
        return _make_vt_result(stats)
    except Exception as e:
        return {'available': False, 'message': f'VT parse error: {e}'}


def _make_vt_result(stats):
    malicious  = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless   = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)
    total      = malicious + suspicious + harmless + undetected

    if malicious >= 3:
        verdict = 'phishing'
    elif malicious >= 1 or suspicious >= 4:
        verdict = 'suspicious'
    else:
        verdict = 'safe'

    return {
        'available': True,
        'malicious':  malicious,
        'suspicious': suspicious,
        'harmless':   harmless,
        'total_scanners': total,
        'verdict': verdict
    }


# ─── Combined checker ───────────────────────────────────────────────────────────

def check_url(url):
    """Run rule-based + VirusTotal checks and combine verdicts."""
    rule_result = analyze_url_rules(url)
    vt_result   = check_virustotal(url)

    # Combine: most severe verdict wins
    verdicts = [rule_result['verdict']]
    if vt_result.get('available'):
        verdicts.append(vt_result['verdict'])

    if 'phishing'   in verdicts: final_status = 'phishing'
    elif 'suspicious' in verdicts: final_status = 'suspicious'
    else:                          final_status = 'safe'

    return {
        'url':          url,
        'status':       final_status,
        'rule_analysis': rule_result,
        'virustotal':   vt_result,
        'timestamp':    datetime.now().isoformat(),
        'checked_at':   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }


# ─── Persistent Log Management ─────────────────────────────────────────────────

def load_logs():
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_log(entry):
    logs = load_logs()

    # Deduplicate: skip if same URL was logged within last 30 s
    if logs:
        last = logs[-1]
        if last.get('url') == entry['url']:
            try:
                diff = (datetime.fromisoformat(entry['timestamp']) -
                        datetime.fromisoformat(last['timestamp'])).total_seconds()
                if diff < 30:
                    return
            except Exception:
                pass

    logs.append(entry)
    logs = logs[-1000:]   # keep newest 1 000

    # JSON
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(logs, f, indent=2)

    # CSV (append)
    file_exists = os.path.exists(CSV_FILE)
    with open(CSV_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'timestamp', 'url', 'status', 'score', 'reasons', 'source',
            'vt_malicious', 'vt_suspicious', 'vt_total'
        ])
        if not file_exists:
            writer.writeheader()
        ra = entry.get('rule_analysis', {})
        vt = entry.get('virustotal', {})
        writer.writerow({
            'timestamp':     entry.get('checked_at', ''),
            'url':           entry.get('url', ''),
            'status':        entry.get('status', ''),
            'score':         ra.get('score', 0),
            'reasons':       '; '.join(ra.get('reasons', [])),
            'source':        entry.get('source', 'manual'),
            'vt_malicious':  vt.get('malicious', 'N/A'),
            'vt_suspicious': vt.get('suspicious', 'N/A'),
            'vt_total':      vt.get('total_scanners', 'N/A'),
        })


# ─── API Routes ────────────────────────────────────────────────────────────────

@app.route('/api/log-url', methods=['POST'])
def api_log_url():
    """Called by the Chrome extension on every page navigation."""
    data   = request.get_json(silent=True) or {}
    url    = (data.get('url') or '').strip()
    source = data.get('source', 'chrome_extension')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Quick rule-only result returned immediately; VT runs in background
    quick = analyze_url_rules(url)

    def async_full_check():
        result = check_url(url)
        result['source'] = source
        save_log(result)

    threading.Thread(target=async_full_check, daemon=True).start()
    return jsonify({'status': quick['verdict'], 'score': quick['score']})


@app.route('/api/check-url', methods=['POST'])
def api_check_url():
    """Manual check — full synchronous result including VirusTotal."""
    data = request.get_json(silent=True) or {}
    url  = (data.get('url') or '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = check_url(url)
    result['source'] = 'manual'
    save_log(result)
    return jsonify(result)


@app.route('/api/logs', methods=['GET'])
def api_get_logs():
    logs = load_logs()
    logs.reverse()
    return jsonify(logs)


@app.route('/api/stats', methods=['GET'])
def api_get_stats():
    logs     = load_logs()
    total    = len(logs)
    phishing = sum(1 for l in logs if l.get('status') == 'phishing')
    susp     = sum(1 for l in logs if l.get('status') == 'suspicious')
    safe     = sum(1 for l in logs if l.get('status') == 'safe')
    return jsonify({'total': total, 'phishing': phishing, 'suspicious': susp, 'safe': safe})


@app.route('/api/clear-logs', methods=['POST'])
def api_clear_logs():
    with open(LOG_FILE, 'w') as f:
        json.dump([], f)
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)
    return jsonify({'success': True})


@app.route('/api/set-apikey', methods=['POST'])
def api_set_apikey():
    global VIRUSTOTAL_API_KEY, API_KEY_SOURCE
    data = request.get_json(silent=True) or {}
    VIRUSTOTAL_API_KEY = (data.get('apikey') or '').strip()
    config_data = load_config()
    if VIRUSTOTAL_API_KEY:
        config_data['virustotal_api_key'] = VIRUSTOTAL_API_KEY
        API_KEY_SOURCE = 'config_file'
    else:
        config_data.pop('virustotal_api_key', None)
        API_KEY_SOURCE = 'not_configured'
    save_config(config_data)
    return jsonify({'success': True, 'configured': bool(VIRUSTOTAL_API_KEY)})


@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({'running': True, 'vt_configured': bool(VIRUSTOTAL_API_KEY)})


# ─── Dashboard (single-page HTML) ──────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🛡️ Phishing URL Detector</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#060d1a;--surf:#0d1b2e;--surf2:#132338;--surf3:#1a2f45;
  --border:#1e3a5f;--accent:#3b82f6;--safe:#22c55e;--phish:#ef4444;--susp:#f59e0b;
  --text:#e2e8f0;--muted:#64748b;--muted2:#94a3b8;
}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}

/* NAV */
.nav{background:var(--surf);border-bottom:1px solid var(--border);height:60px;
  padding:0 2rem;display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:100}
.logo{font-size:1.2rem;font-weight:700;color:var(--accent);display:flex;align-items:center;gap:8px}
.live{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--safe)}
.pulse{width:8px;height:8px;background:var(--safe);border-radius:50%;
  animation:pulse 2s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,.4)}50%{box-shadow:0 0 0 6px rgba(34,197,94,0)}}

/* LAYOUT */
.main{max-width:1440px;margin:0 auto;padding:1.5rem 2rem}

/* STATS */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1.25rem;margin-bottom:1.5rem}
.stat{background:var(--surf);border:1px solid var(--border);border-radius:12px;
  padding:1.25rem 1.5rem;position:relative;overflow:hidden}
.stat::after{content:'';position:absolute;top:0;left:0;right:0;height:3px}
.stat.total::after{background:var(--accent)}
.stat.safe-c::after{background:var(--safe)}
.stat.susp-c::after{background:var(--susp)}
.stat.phish-c::after{background:var(--phish)}
.stat-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px}
.stat-val{font-size:2.2rem;font-weight:800}
.stat.total .stat-val{color:var(--accent)}
.stat.safe-c .stat-val{color:var(--safe)}
.stat.susp-c .stat-val{color:var(--susp)}
.stat.phish-c .stat-val{color:var(--phish)}

/* GRID */
.grid{display:grid;grid-template-columns:1fr 360px;gap:1.25rem;margin-bottom:1.5rem}

/* PANELS */
.panel{background:var(--surf);border:1px solid var(--border);border-radius:12px;padding:1.25rem}
.ptitle{font-size:.95rem;font-weight:600;color:var(--accent);margin-bottom:1rem;display:flex;align-items:center;gap:7px}

/* INPUTS */
.irow{display:flex;gap:8px;margin-bottom:1rem}
.inp{flex:1;background:var(--surf2);border:1px solid var(--border);border-radius:8px;
  padding:11px 14px;color:var(--text);font-size:13px;outline:none;transition:border .2s}
.inp:focus{border-color:var(--accent)}
.inp::placeholder{color:var(--muted)}

/* BUTTONS */
.btn{padding:11px 18px;border:none;border-radius:8px;cursor:pointer;font-size:13px;
  font-weight:600;transition:all .2s;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#2563eb;transform:translateY(-1px)}
.btn-primary:disabled{background:var(--surf3);color:var(--muted);cursor:not-allowed;transform:none}
.btn-danger{background:#450a0a;color:#fca5a5;border:1px solid #991b1b}
.btn-danger:hover{background:#7f1d1d}
.btn-sm{padding:7px 13px;font-size:12px}
.btn-ghost{background:var(--surf2);color:var(--muted2);border:1px solid var(--border)}
.btn-ghost:hover{background:var(--surf3);color:var(--text)}

/* RESULT CARD */
.rcard{border-radius:10px;padding:1.1rem;margin-top:1rem;border:1px solid;display:none;
  animation:fadeIn .3s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
.rcard.safe{background:#052e16;border-color:#166534}
.rcard.phishing{background:#450a0a;border-color:#991b1b}
.rcard.suspicious{background:#422006;border-color:#92400e}
.rhead{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.rstatus{font-size:1rem;font-weight:700}
.rscore{font-size:11px;background:rgba(255,255,255,.1);padding:2px 8px;border-radius:20px}
.rurl{font-size:11px;color:var(--muted2);margin-bottom:8px;word-break:break-all}
.rlist{list-style:none}
.rlist li{font-size:12px;padding:3px 0;color:#cbd5e1;display:flex;align-items:flex-start;gap:5px}
.rlist li::before{content:'›';color:var(--accent);flex-shrink:0;font-weight:700}
.vtbadge{display:inline-flex;align-items:center;gap:6px;
  background:var(--surf2);border:1px solid var(--border);
  border-radius:6px;padding:5px 10px;font-size:11px;margin-top:8px}

/* TABLE */
.tpanel{background:var(--surf);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.thead{padding:.9rem 1.25rem;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;flex-wrap:gap}
.filters{display:flex;gap:5px;flex-wrap:wrap}
.ftab{padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;
  border:1px solid transparent;background:var(--surf2);color:var(--muted);transition:all .2s}
.ftab.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.ftab:hover:not(.on){border-color:var(--border);color:var(--text)}
.tsearch{padding:.8rem 1.25rem;border-bottom:1px solid var(--border)}
.sinp{width:100%;background:var(--surf2);border:1px solid var(--border);
  border-radius:7px;padding:9px 14px;color:var(--text);font-size:12px;outline:none}
.sinp:focus{border-color:var(--accent)}
.twrap{overflow:auto;max-height:500px}
table{width:100%;border-collapse:collapse}
th{padding:10px 14px;text-align:left;font-size:10px;font-weight:600;text-transform:uppercase;
  letter-spacing:.5px;color:var(--muted);background:var(--surf);position:sticky;top:0;
  border-bottom:1px solid var(--border)}
td{padding:11px 14px;font-size:12px;border-bottom:1px solid #0d1b2e;vertical-align:middle}
tr:hover td{background:var(--surf2)}
tr:last-child td{border-bottom:none}
.ucell{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  color:#93c5fd;font-size:11px}
.badge{display:inline-flex;align-items:center;gap:3px;padding:3px 9px;
  border-radius:20px;font-size:10px;font-weight:700;text-transform:uppercase}
.badge.safe{background:#052e16;color:var(--safe);border:1px solid #166534}
.badge.phishing{background:#450a0a;color:#fca5a5;border:1px solid #991b1b}
.badge.suspicious{background:#422006;color:#fde68a;border:1px solid #92400e}
.sbar{display:flex;align-items:center;gap:7px}
.track{flex:1;height:4px;background:var(--surf2);border-radius:2px;overflow:hidden;min-width:55px}
.fill{height:100%;border-radius:2px}
.snum{font-size:10px;color:var(--muted);width:25px}

/* CHART */
.cbox{height:190px;display:flex;align-items:center;justify-content:center}

/* CONFIG */
.cfgrow{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.cfginp{background:var(--surf2);border:1px solid var(--border);border-radius:7px;
  padding:8px 12px;color:var(--text);font-size:12px;outline:none;flex:1;min-width:180px}
.cfginp:focus{border-color:var(--accent)}
.cfgst{font-size:11px}
.cfgst.ok{color:var(--safe)}
.cfgst.no{color:var(--susp)}

/* SPINNER */
.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.2);
  border-top-color:#fff;border-radius:50%;animation:sp .6s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}

/* TOAST */
.toast{position:fixed;bottom:1.5rem;right:1.5rem;background:var(--surf2);
  border:1px solid var(--border);border-radius:10px;padding:.9rem 1.3rem;font-size:13px;
  z-index:999;animation:fadeIn .3s ease;display:flex;align-items:center;gap:8px;
  box-shadow:0 8px 32px rgba(0,0,0,.4)}

/* RULES CHIPS */
.chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:.75rem}
.chip{font-size:10px;background:var(--surf2);padding:3px 8px;border-radius:4px;
  color:var(--muted2);border:1px solid var(--border)}

/* EMPTY */
.empty{text-align:center;padding:3rem;color:var(--muted)}
.empty .icon{font-size:2.5rem;margin-bottom:.75rem}

@media(max-width:900px){
  .stats{grid-template-columns:repeat(2,1fr)}
  .grid{grid-template-columns:1fr}
}
</style>
</head>
<body>

<nav class="nav">
  <div class="logo">🛡️ Phishing Detector</div>
  <div style="display:flex;align-items:center;gap:1rem">
    <div class="live"><div class="pulse"></div>Live Monitoring</div>
    <button class="btn btn-ghost btn-sm" onclick="refresh()">↻ Refresh</button>
  </div>
</nav>

<div class="main">

  <!-- STATS -->
  <div class="stats">
    <div class="stat total"><div class="stat-label">Total Checked</div><div class="stat-val" id="sTotal">0</div></div>
    <div class="stat safe-c"><div class="stat-label">Safe</div><div class="stat-val" id="sSafe">0</div></div>
    <div class="stat susp-c"><div class="stat-label">Suspicious</div><div class="stat-val" id="sSusp">0</div></div>
    <div class="stat phish-c"><div class="stat-label">Phishing</div><div class="stat-val" id="sPhish">0</div></div>
  </div>

  <!-- MAIN GRID -->
  <div class="grid">

    <div style="display:flex;flex-direction:column;gap:1.25rem">

      <!-- MANUAL CHECK -->
      <div class="panel">
        <div class="ptitle">🔍 Manual URL Check</div>
        <div class="irow">
          <input id="manualUrl" class="inp" type="text"
            placeholder="Paste any URL to analyse (e.g. https://example.com)"
            onkeydown="if(event.key==='Enter')doCheck()">
          <button id="checkBtn" class="btn btn-primary" onclick="doCheck()">Analyse</button>
        </div>
        <div id="rcard" class="rcard">
          <div class="rhead">
            <span id="ricon" style="font-size:1.4rem"></span>
            <span id="rstatus" class="rstatus"></span>
            <span id="rscore" class="rscore"></span>
          </div>
          <div id="rurl" class="rurl"></div>
          <ul id="rlist" class="rlist"></ul>
          <div id="rvt"></div>
        </div>
      </div>

      <!-- VT CONFIG -->
      <div class="panel">
        <div class="ptitle">⚙️ VirusTotal API Key</div>
        <div class="cfgrow">
          <input id="apiKey" class="cfginp" type="password" placeholder="Paste your free VirusTotal API key here…">
          <button class="btn btn-primary btn-sm" onclick="saveKey()">Save</button>
          <span id="cfgSt" class="cfgst no">⚠ Not configured</span>
        </div>
        <p style="font-size:11px;color:var(--muted);margin-top:8px">
          Free key at <a href="https://www.virustotal.com" target="_blank" style="color:var(--accent)">virustotal.com</a>
          (500 req/day). Without it, rule-based detection still runs for all URLs.
        </p>
      </div>
    </div>

    <!-- CHART + RULES -->
    <div class="panel" style="display:flex;flex-direction:column">
      <div class="ptitle">📊 Threat Distribution</div>
      <div class="cbox"><canvas id="chart" width="200" height="190"></canvas></div>
      <div style="margin-top:1rem">
        <div style="font-size:11px;color:var(--muted);margin-bottom:6px">17 Active Detection Rules</div>
        <div class="chips">
          <span class="chip">HTTPS Check</span>
          <span class="chip">IP Host</span>
          <span class="chip">High-risk TLD</span>
          <span class="chip">Subdomains</span>
          <span class="chip">URL Length</span>
          <span class="chip">Brand Impersonation</span>
          <span class="chip">Domain Keywords</span>
          <span class="chip">@ Symbol</span>
          <span class="chip">URL Shorteners</span>
          <span class="chip">Digit Count</span>
          <span class="chip">URL Encoding</span>
          <span class="chip">Sensitive Path</span>
          <span class="chip">Redirect Params</span>
          <span class="chip">Domain Hyphens</span>
          <span class="chip">Punycode/IDN</span>
          <span class="chip">Numeric TLD</span>
          <span class="chip">VirusTotal API</span>
        </div>
      </div>
    </div>
  </div>

  <!-- URL LOG TABLE -->
  <div class="tpanel">
    <div class="thead">
      <div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap">
        <span class="ptitle" style="margin:0">📋 URL History</span>
        <div class="filters">
          <div class="ftab on"  onclick="setF('all',this)">All</div>
          <div class="ftab" onclick="setF('safe',this)">✅ Safe</div>
          <div class="ftab" onclick="setF('suspicious',this)">⚠️ Suspicious</div>
          <div class="ftab" onclick="setF('phishing',this)">🚨 Phishing</div>
        </div>
      </div>
      <button class="btn btn-danger btn-sm" onclick="clearLogs()">🗑 Clear</button>
    </div>
    <div class="tsearch">
      <input id="srch" class="sinp" placeholder="🔎  Search URLs…" oninput="render()">
    </div>
    <div class="twrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>URL</th>
            <th>Status</th>
            <th>Risk Score</th>
            <th>Source</th>
            <th>Top Reasons</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </div>

</div>

<script>
let logs=[], filt='all', chart=null;

// ── init ──────────────────────────────────────────────────────────────────────
async function init(){
  await refresh();
  initChart();
  setInterval(refresh, 12000);
}

async function refresh(){
  await loadStats();
  await loadLogs();
}

// ── stats ─────────────────────────────────────────────────────────────────────
async function loadStats(){
  try{
    const d=await(await fetch('/api/stats')).json();
    document.getElementById('sTotal').textContent=d.total;
    document.getElementById('sSafe').textContent=d.safe;
    document.getElementById('sSusp').textContent=d.suspicious;
    document.getElementById('sPhish').textContent=d.phishing;
    updateChart(d.safe,d.suspicious,d.phishing);
  }catch(e){}
}

// ── logs ──────────────────────────────────────────────────────────────────────
async function loadLogs(){
  try{
    logs=await(await fetch('/api/logs')).json();
    render();
  }catch(e){}
}

function setF(f,el){
  filt=f;
  document.querySelectorAll('.ftab').forEach(t=>t.classList.remove('on'));
  el.classList.add('on');
  render();
}

function render(){
  const q=document.getElementById('srch').value.toLowerCase();
  const rows=logs.filter(l=>{
    const mf=filt==='all'||l.status===filt;
    const ms=!q||l.url.toLowerCase().includes(q);
    return mf&&ms;
  });
  const tb=document.getElementById('tbody');
  if(!rows.length){
    tb.innerHTML=`<tr><td colspan="6"><div class="empty"><div class="icon">📭</div>No matching entries</div></td></tr>`;
    return;
  }
  tb.innerHTML=rows.map(l=>{
    const ra=l.rule_analysis||{};
    const sc=ra.score||0;
    const col=sc>=55?'#ef4444':sc>=25?'#f59e0b':'#22c55e';
    const ic=l.status==='phishing'?'🚨':l.status==='suspicious'?'⚠️':'✅';
    const reasons=(ra.reasons||[]).slice(0,2).join('; ')||'—';
    const ts=l.checked_at||l.timestamp?.substring(0,19).replace('T',' ')||'—';
    const src=l.source==='chrome_extension'?'Chrome':'Manual';
    return `<tr>
      <td style="white-space:nowrap;color:var(--muted);font-size:11px">${ts}</td>
      <td><div class="ucell" title="${l.url}">${l.url}</div></td>
      <td><span class="badge ${l.status}">${ic} ${l.status}</span></td>
      <td><div class="sbar">
        <div class="track"><div class="fill" style="width:${sc}%;background:${col}"></div></div>
        <div class="snum">${sc}</div>
      </div></td>
      <td style="font-size:10px;color:var(--muted)">${src}</td>
      <td style="font-size:11px;color:var(--muted2);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${(ra.reasons||[]).join('; ')}">${reasons}</td>
    </tr>`;
  }).join('');
}

// ── manual check ─────────────────────────────────────────────────────────────
async function doCheck(){
  let url=(document.getElementById('manualUrl').value||'').trim();
  if(!url)return;
  if(!url.startsWith('http://') && !url.startsWith('https://')) url='https://'+url;

  const btn=document.getElementById('checkBtn');
  btn.disabled=true;
  btn.innerHTML='<div class="spin"></div> Checking…';

  try{
    const res=await fetch('/api/check-url',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({url})
    });
    const d=await res.json();
    showResult(d);
    await refresh();
  }catch(e){
    toast('❌ Could not reach backend');
  }
  btn.disabled=false;
  btn.innerHTML='Analyse';
}

function showResult(d){
  const s=d.status;
  const ra=d.rule_analysis||{};
  const rc=document.getElementById('rcard');
  rc.className='rcard '+s;
  rc.style.display='block';
  const icons={safe:'✅',phishing:'🚨',suspicious:'⚠️'};
  const labels={safe:'SAFE',phishing:'PHISHING DETECTED',suspicious:'SUSPICIOUS'};
  document.getElementById('ricon').textContent=icons[s]||'❓';
  document.getElementById('rstatus').textContent=labels[s]||s.toUpperCase();
  document.getElementById('rscore').textContent='Risk Score: '+(ra.score||0)+'/100';
  document.getElementById('rurl').textContent=d.url;
  const reasons=ra.reasons||[];
  document.getElementById('rlist').innerHTML=reasons.length
    ? reasons.map(r=>`<li>${r}</li>`).join('')
    :'<li>No suspicious patterns found</li>';
  const vt=d.virustotal||{};
  document.getElementById('rvt').innerHTML=vt.available
    ? `<div class="vtbadge">🔬 VirusTotal: <strong>${vt.malicious}</strong> malicious / <strong>${vt.suspicious}</strong> suspicious / ${vt.total_scanners} engines</div>`
    : `<div class="vtbadge" style="color:var(--muted)">🔬 VirusTotal: ${vt.message||'N/A'}</div>`;
}

// ── chart ─────────────────────────────────────────────────────────────────────
function initChart(){
  chart=new Chart(document.getElementById('chart').getContext('2d'),{
    type:'doughnut',
    data:{labels:['Safe','Suspicious','Phishing'],datasets:[{
      data:[0,0,0],
      backgroundColor:['rgba(34,197,94,.15)','rgba(245,158,11,.15)','rgba(239,68,68,.15)'],
      borderColor:['#22c55e','#f59e0b','#ef4444'],borderWidth:2
    }]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#94a3b8',font:{size:11}}}},cutout:'60%'}
  });
}

function updateChart(s,su,p){
  if(!chart)return;
  chart.data.datasets[0].data=[s,su,p];
  chart.update();
}

// ── utilities ─────────────────────────────────────────────────────────────────
async function clearLogs(){
  if(!confirm('Clear all URL history? This cannot be undone.'))return;
  await fetch('/api/clear-logs',{method:'POST'});
  logs=[];render();await loadStats();
  toast('🗑️ Logs cleared');
}

async function saveKey(){
  const key=document.getElementById('apiKey').value.trim();
  await fetch('/api/set-apikey',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({apikey:key})});
  const st=document.getElementById('cfgSt');
  if(key){st.textContent='✓ API key saved';st.className='cfgst ok';}
  else{st.textContent='⚠ Not configured';st.className='cfgst no';}
  toast(key?'✅ VirusTotal API key saved':'⚠️ API key cleared');
}

function toast(msg){
  const t=document.createElement('div');
  t.className='toast';t.textContent=msg;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(),3000);
}

init();
</script>
</body>
</html>"""

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML)


if __name__ == '__main__':
    print("\n🛡️  Phishing URL Detector — v2")
    print("━" * 42)
    print(f"  Dashboard  → http://localhost:5000")
    print(f"  Logs       → {os.path.abspath(LOG_FILE)}")
    if VIRUSTOTAL_API_KEY:
        if API_KEY_SOURCE == 'environment':
            print(f"  VirusTotal → ✅ Key loaded from environment")
        elif API_KEY_SOURCE == 'config_file':
            print(f"  VirusTotal → ✅ Key loaded from config.json")
        else:
            print(f"  VirusTotal → ✅ Key configured")
    else:
        print(f"  VirusTotal → ⚠  No key set (configure in dashboard UI)")
    print("━" * 42 + "\n")
    app.run(debug=False, host='127.0.0.1', port=5000)
