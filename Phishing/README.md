# Phishing Project

## What changed
- Added `Phishing/index.html` + `Phishing/standalone.js` so you can run the phishing UI by directly opening the HTML file (similar to your SQL injection project style).
- API key is now persistent in backend `Phishing/config.json`, so you only set it once.

## Run steps
1. Open PowerShell in `Phishing` folder.
2. Run:
   - `.\start.bat`

This will:
- Stop any old process already using port `5000`
- Start the backend in a new terminal
- Open the dashboard automatically at `http://localhost:5000`

Manual fallback:
1. `python app.py`
2. Open `http://localhost:5000`

## One-time API key setup
- In the direct HTML page, paste VirusTotal key and click **Save Key**.
- It is saved to `Phishing/config.json`.
- Next runs will auto-load it (unless you clear it).

## Notes
- Backend still runs on `http://127.0.0.1:5000`.
- Existing Chrome extension files are kept unchanged; you can still use them if needed.
