# PhishGuard — Threat Intelligence Platform

A real-time threat intelligence phishing detection system that scans **URLs**, **emails**, and **SMS messages** for cyber threats using live APIs (VirusTotal, Google Safe Browsing), domain age (WHOIS), SSL certificate validation, and keyword heuristic analysis.

---

## Features

- **Threat Scanner** — Analyze URLs, emails, and SMS for phishing patterns
- **Risk Scoring Engine** — Live signals (API checks, WHOIS, SSL, keyword heuristics) calculate a weighted 0-100 risk score
- **Live Dashboard** — Real-time stats: total scans, threats detected, safe verified, threat rate
- **Scan History** — Timestamped log of all recent analyses with detailed reasoning lists
- **Batch URL Scanner** — Paste multiple URLs and scan them all at once
- **Browser Extension** — Chrome extension to scan the current page or right-click any link
- **Modular Integration** — Seamless fallback mode: fully operational with heuristics when API keys are not supplied

---

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Google Chrome (for the browser extension)

---

## Getting Started

### Step 1: Install Dependencies

Make sure your virtual environment is active, then run:

```bash
pip install -r requirements.txt
```

### Step 2: Configure API Keys (Optional but Recommended)

Copy the `.env.example` file to `.env`:

```bash
cp .env.example .env
```

Open `.env` in a text editor and configure:
1. `GOOGLE_SAFE_BROWSING_API_KEY` (Free keys at [Google Cloud Console](https://console.cloud.google.com/))
2. `VIRUSTOTAL_API_KEY` (Free keys at [VirusTotal](https://www.virustotal.com/))

*Note: If no API keys are provided, the scanner degrades gracefully to run WHOIS, SSL, and keyword checks.*

### Step 3: Run the Web Application

```bash
python app.py
```

Open your browser and navigate to: **http://127.0.0.1:5000**

---

## Browser Extension Setup

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer Mode** (toggle in the top-right)
3. Click **Load Unpacked** and select the `phishguard-extension` folder
4. The PhishGuard icon will appear in your toolbar
5. Make sure the Flask server is running (`python app.py`)

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Main web interface |
| `/predict` | POST | Scan content (URL/email/SMS) — returns status + risk score + detailed reasons |
| `/check` | POST | Extension-compatible alias for `/predict` |
| `/api/stats` | GET | Aggregated scan statistics |
| `/api/history` | GET | Recent scan history (last 50) |
| `/api/batch` | POST | Batch scan multiple URLs at once |
| `/api/clear-history` | POST | Clear all scan history |

---

## Tech Stack

- **Backend**: Python, Flask, requests, python-whois, python-dotenv
- **Frontend**: HTML5, Vanilla CSS3, JavaScript (Dashboard, stats, dynamic updates)
- **Threat Intelligence**: Google Safe Browsing Lookup v4, VirusTotal v3, WHOIS registry, SSL certificate checker
- **Extension**: Chrome Extension (Manifest V3)
