# 🔍 SecretScope

**SecretScope** is a fast, local-first bug bounty reconnaissance and secret-detection framework — inspired by tools like MobSF, TruffleHog, and Gitleaks. It features a browser-based dashboard, async URL recon via Wayback Machine CDX API, regex + Shannon entropy filtering, safe token validation, and scope protection.

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

4. **GitHub Code Search**:
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
