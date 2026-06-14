# 🛡️ PhishGuard — Real-Time Threat Intelligence Platform

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Flask Version](https://img.shields.io/badge/flask-3.1%2B-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

PhishGuard is a high-performance, real-time threat intelligence and phishing detection platform. It dynamically assesses URLs, emails, and SMS messages for security vulnerabilities and malicious indicators using live feeds (Google Safe Browsing, VirusTotal), automated domain registrations registry checks (WHOIS), SSL/TLS handshake verifications, and custom heuristic algorithms.

---

## 🔍 Architecture & Pipeline Flow

The platform executes a multi-layered analysis to inspect potential phishing vectors. Here is the operational sequence for URL scans:

```
[URL Input]
    │
    ├──► Whitelist Bypass Check (Instant Safe Verdict for trusted domains)
    │
    └──► Real-Time Inspection Pipeline
            ├──► Domain Extraction & IP Detection
            ├──► Google Safe Browsing API v4 Lookup
            ├──► VirusTotal API v3 Scan
            ├──► WHOIS Registrar Registry Check (Domain Age Assessment)
            ├──► SSL/TLS Certificate Handshake & Validation
            └──► Keyword & Pattern Heuristic Scan
                    │
                    ▼
          [Risk Scoring Engine] (0 - 100)
                    │
            ┌───────┼───────┐
            ▼       ▼       ▼
          [Safe] [Suspicious] [Malicious]
          (0-20)   (21-50)   (51-100)
```

### Risk Scoring Matrix
The final classification is determined by a weighted summation of detected signals:

| Security Signal | Risk Contribution | Description |
| :--- | :---: | :--- |
| **Google Safe Browsing Warning** | `+50` | Blacklisted on Google's social engineering database. |
| **VirusTotal Flags** | `+50` | Flagged as malicious by one or more VT engines. |
| **Critical Domain Age (< 30 days)** | `+20` | Domain was registered in the last 30 days. |
| **New Domain Age (< 180 days)** | `+5` | Domain is less than 6 months old. |
| **Missing SSL / Port 443 Closed** | `+15` | HTTPS/TLS connection cannot be established. |
| **Invalid SSL Certificate** | `+15` | SSL handshake succeeds but certificate verification fails (e.g. self-signed). |
| **Insecure Protocol (HTTP)** | `+15` | Scheme explicitly uses `http://` instead of `https://`. |
| **Numeric IP Address in URL** | `+10` | Uses a raw IP address (e.g., `http://192.168.1.1`) to mask identity. |
| **Suspicious Keywords in URL** | `+10` | Subdomain or path contains keywords like `login`, `verify`, `secure`. |
| **Excessive URL Length (> 75 chars)**| `+5` | Long URL string designed to hide malicious target hosts. |
| **Excessive Subdomain Count** | `+5` | Uses 4 or more subdomains (e.g., `login.bank.com.verify.net`). |

---

## ⚡ Core Features

- **Multi-Vector Scanning**: Tailored threat intelligence paths for URLs, raw Emails, and SMS bodies.
- **Deep URL Extraction**: Automatically parses unstructured email/SMS texts, extracts all embedded hyperlinks, and scans them sequentially.
- **Dynamic Dashboard**: Displays telemetry data including total scans, threat ratios, and logs in real-time.
- **Browser Extension**: A Chrome extension (Manifest V3 compatible) to verify page safety with one-click menu options or right-click scans.
- **Heuristic Autonomy**: Gracefully falls back to SSL, WHOIS, and pattern analysis if external API keys are missing.

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher installed on your system.
- Google Chrome browser (optional, for browser extension testing).

### 1. Clone & Set Up Directory
Open your terminal and navigate to your project directory.

### 2. Create and Activate Virtual Environment
Choose the commands appropriate for your operating system and shell:

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Windows (CMD):**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

**macOS / Linux (Bash/Zsh):**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Secrets
Copy the template configuration file:

**Windows (PowerShell/CMD):**
```powershell
copy .env.example .env
```

**macOS / Linux:**
```bash
cp .env.example .env
```

Open `.env` in your preferred editor and supply your keys:
- `GOOGLE_SAFE_BROWSING_API_KEY`: Get a free key at [Google Cloud Console](https://console.cloud.google.com/).
- `VIRUSTOTAL_API_KEY`: Get a free API key at [VirusTotal](https://www.virustotal.com/).

---

## 🖥️ Running the Application

Start the Flask command center:
```bash
python app.py
```
After the server initializes, launch your browser and navigate to:
👉 **http://127.0.0.1:5000**

---

## 🛡️ Chrome Extension Installation

1. Open Google Chrome and go to the Extensions page: `chrome://extensions/`
2. Toggle the **Developer mode** switch in the top-right corner to **On**.
3. Click the **Load unpacked** button in the top-left corner.
4. Select the `phishguard-extension` directory from this repository.
5. The extension is now active. Click the shield icon in your toolbar to scan active pages in real-time!

---

## 🛠️ Troubleshooting

#### 1. WHOIS Timezone Errors or Flaky Lookups
- **Symptom**: `TypeError: can't subtract offset-naive and offset-aware datetimes`
- **Resolution**: This error is already handled natively in `threat_intel.py` by converting WHOIS outputs to naive datetimes. If lookups timeout, ensure port 43 (WHOIS) is not blocked by your firewall.

#### 2. Address Already in Use (Port 5000)
- **Symptom**: Flask server fails to start, claiming the port is occupied.
- **Resolution**: On macOS, turn off AirPlay Receiver in system settings (which listens on port 5000) or specify a different port in `app.py`:
  ```python
  app.run(debug=True, port=5001)
  ```

#### 3. API Key Missing/Quotas
- **Symptom**: VirusTotal scans show as unchecked or return rate errors.
- **Resolution**: The system degrades gracefully to run WHOIS, SSL, and heuristics. If you are using free tiers:
  - **VirusTotal**: Rate-limited to 4 queries/minute.
  - **Google Safe Browsing**: Rate-limited to 10,000 queries/day.
