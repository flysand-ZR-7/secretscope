# 🔍 SecretScope

[![CI](https://github.com/flysand-ZR-7/secretscope/actions/workflows/ci.yml/badge.svg)](https://github.com/flysand-ZR-7/secretscope/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Tests](https://img.shields.io/badge/Tests-5%20Passed-brightgreen.svg)](tests/)

**SecretScope** is a fast, local-first bug bounty reconnaissance, OSINT intelligence, and secret-detection framework — inspired by tools like TruffleHog, Recon-ng, OnionScan, and Gitleaks. It features a browser-based dashboard, async URL recon via Wayback Machine, passive Certificate Transparency subdomain discovery, security header misconfiguration audits, Ahmia Dark Web leak queries, regex + Shannon entropy filtering, and scope protection.

---

## 🚀 Quickstart on Linux

### Method 1: Direct Bash Script (Automated Virtualenv)
```bash
# Make script executable
chmod +x run.sh

# Start SecretScope (creates venv and installs dependencies on first run)
./run.sh
```

### Method 2: Manual Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
```

### Method 3: Docker / Docker Compose
```bash
docker compose up --build
```

Access the web dashboard in your browser:
👉 **`http://localhost:8077`**

---

## 🎯 Key Features

1. **Local-First Web UI**:
   - Real-time dark mode security dashboard (runs on port `8077`, configurable via `SECRETSCOPE_PORT`).
   - One-click scan triggers for single URLs, full domains, and GitHub dorks.
   - Severity badges (Critical, High, Medium, Low), line numbers, redacted values, and context previews.
   - Scan history stored in SQLite (`secretscope.db`).

2. **Multi-Category Secret Detection (30+ Rules)**:
   - **Cloud**: AWS Access/Secret Keys, GCP Service Accounts, Firebase keys, Azure Storage.
   - **Version Control & CI**: GitHub PATs, OAuth tokens, App tokens, GitLab PATs, Docker Hub, npm.
   - **Chat & Webhooks**: Slack bot tokens, Slack incoming webhooks, Discord webhooks, Telegram bots.
   - **Payment**: Stripe secret/publishable keys, PayPal/Braintree access tokens.
   - **Private Keys**: RSA, DSA, EC, OpenSSH, PGP private key headers.
   - **Databases & URIs**: Embedded credentials in PostgreSQL, MySQL, MongoDB URLs.
   - **Generic High-Entropy**: Assignments gated by **Shannon entropy** calculation (`> 3.5`) to eliminate false positives.

3. **Recon & Discovery Pipeline (Wayback + JS)**:
   - Queries `web.archive.org/cdx` to harvest archived paths for `*.target.com/*`.
   - Crawls target homepage and extracts script sources (`<script src="...">`).
   - High-signal filtering on sensitive extensions (`.env`, `.json`, `.config`, `.yml`, `.sql`, `.bak`, etc.) and sensitive paths (`/api/`, `/admin/`, `/backup/`, `/.git/`, etc.).

4. **OSINT Reconnaissance (Inspired by Recon-ng)**:
   - Passive Certificate Transparency log queries via `crt.sh/?q=%.domain&output=json` to uncover hidden subdomains (`api`, `dev`, `staging`, `vpn`) without triggering defensive alerts or IDS.

5. **Security Header & Information Disclosure Audits (Inspired by OnionScan)**:
   - Automated inspection for missing `Content-Security-Policy` (CSP) and `Strict-Transport-Security` (HSTS).
   - Flags dangerous wildcard CORS configurations (`Access-Control-Allow-Origin: *`).
   - Identifies technology disclosures in `X-Powered-By` and granular server version banners.

6. **Ahmia Dark Web Threat Intelligence (Inspired by Ahmia & TorBot)**:
   - Automatically queries Ahmia indexers for target domain references in Tor breach dumps, paste sites, and underground forums.

7. **GitHub Code Search**:
   - Runs 20+ targeted dorks against the GitHub Code Search API using `GITHUB_TOKEN`.
   - Handles rate-limiting with exponential backoff and 2.2s query delays.

5. **Scope Guard**:
   - Target allowlist loaded from `scope.txt`.
   - Prevents accidental out-of-scope requests before any scanning or fetching happens.
   - Configurable via the Web UI or `/api/scope` endpoints.

6. **Non-Destructive Validation**:
   - Safe validation layer for GitHub tokens and Slack webhooks that confirms validity without saving or leaking secrets.

---

## 🛠️ Configuration & Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `SECRETSCOPE_PORT` | `8077` | Port for the web interface and API |
| `GITHUB_TOKEN` | *empty* | GitHub Personal Access Token (for GitHub Dork Scanner) |

---

## 📡 REST API Reference

- `POST /api/scan/url` — Body: `{"url": "https://..."}`
- `POST /api/scan/domain` — Body: `{"domain": "example.com"}`
- `POST /api/scan/github` — Body: `{"domain": "example.com"}`
- `GET /api/scans` — List past scans
- `GET /api/scans/{id}` — Get scan details and full findings
- `GET /api/scope` — Get active target scope
- `POST /api/scope/add` — Body: `{"domain": "example.com"}`
- `GET /api/health` — Health check endpoint
