"""SecretScope — Browser-based secret and API key scanner for bug bounty recon."""
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from app.models import ScanTarget, ScanResult, Finding, ScopeUpdate, ReconTarget, ReconResult
from app.storage import init_db, save_scan, get_scans, get_scan
from app.scope import scope_manager
from app.scanners.engine import scan_content, scan_urls
from app.scanners.discovery import wayback_urls, extract_js_urls, interesting_paths
from app.scanners.fetcher import fetch_url
from app.scanners.github_search import GitHubDorkScanner
from app.scanners.recon import perform_full_recon

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("secretscope")

github_scanner = GitHubDorkScanner()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup."""
    init_db()
    logger.info("SecretScope started — database initialized")
    yield


app = FastAPI(
    title="SecretScope",
    description="Browser-based secret and API key scanner for bug bounty recon",
    version="1.0.0",
    lifespan=lifespan,
)

# Serve static files (dashboard)
static_dir = Path(__file__).parent.parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def index():
    """Serve the dashboard."""
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"status": "ok", "message": "SecretScope API is running. Dashboard not found — place index.html in /static/"}


@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


# ── Scan Endpoints ────────────────────────────────────────────────

@app.post("/api/scan/url")
async def scan_single_url(target: ScanTarget):
    """Scan a single URL for secrets."""
    if not target.url:
        raise HTTPException(status_code=400, detail="url is required")

    if not scope_manager.is_in_scope(target.url):
        raise HTTPException(status_code=403, detail=f"Target '{target.url}' is not in scope. Add it via /api/scope first.")

    logger.info(f"Scanning URL: {target.url}")
    content = await fetch_url(target.url)
    if content is None:
        raise HTTPException(status_code=502, detail=f"Failed to fetch URL: {target.url}")

    findings = scan_content(target.url, content)
    result = save_scan(target=target.url, scan_type="url", findings=findings)
    logger.info(f"URL scan complete: {len(findings)} finding(s)")
    return result


@app.post("/api/scan/domain")
async def scan_domain(target: ScanTarget):
    """Run full domain recon: Wayback discovery + filter interesting paths + scan."""
    if not target.domain:
        raise HTTPException(status_code=400, detail="domain is required")

    if not scope_manager.is_in_scope(target.domain):
        raise HTTPException(status_code=403, detail=f"Target '{target.domain}' is not in scope. Add it via /api/scope first.")

    logger.info(f"Starting domain scan: {target.domain}")

    # Step 1: Discover URLs via Wayback Machine
    discovered = await wayback_urls(target.domain)
    logger.info(f"Wayback discovered {len(discovered)} URLs")

    # Step 2: Also fetch the main page and extract JS URLs
    main_url = f"https://{target.domain}"
    main_content = await fetch_url(main_url)
    if main_content:
        js_urls = extract_js_urls(main_content, main_url)
        discovered.extend(js_urls)
        logger.info(f"Extracted {len(js_urls)} JS URLs from main page")

    # Step 3: Filter to interesting paths
    filtered = interesting_paths(discovered)
    logger.info(f"Filtered to {len(filtered)} interesting paths")

    # Cap at 200 URLs to avoid extremely long scans
    if len(filtered) > 200:
        logger.warning(f"Capping scan to 200 URLs (from {len(filtered)})")
        filtered = filtered[:200]

    # Step 4: Fetch and scan
    all_findings = await scan_urls(filtered)

    # Also scan the main page content if we fetched it
    if main_content:
        main_findings = scan_content(main_url, main_content)
        all_findings.extend(main_findings)

    result = save_scan(target=target.domain, scan_type="domain", findings=all_findings)
    logger.info(f"Domain scan complete: {len(all_findings)} finding(s) from {len(filtered)} URLs")
    return result


@app.post("/api/scan/github")
async def scan_github(target: ScanTarget):
    """Search GitHub for leaked secrets related to the domain."""
    if not target.domain:
        raise HTTPException(status_code=400, detail="domain is required")

    if not scope_manager.is_in_scope(target.domain):
        raise HTTPException(status_code=403, detail=f"Target '{target.domain}' is not in scope. Add it via /api/scope first.")

    logger.info(f"Starting GitHub dork scan: {target.domain}")
    findings = await github_scanner.search(target.domain)
    result = save_scan(target=target.domain, scan_type="github", findings=findings)
    logger.info(f"GitHub scan complete: {len(findings)} finding(s)")
    return result


@app.post("/api/recon", response_model=ReconResult)
async def recon_domain(target: ReconTarget):
    """
    Perform OSINT reconnaissance (crt.sh Certificate Transparency),
    security header audit (OnionScan/Recon-ng), and Ahmia Dark Web leak lookup.
    """
    if not target.domain:
        raise HTTPException(status_code=400, detail="domain is required")

    logger.info(f"Starting OSINT recon & dark web breach lookup: {target.domain}")
    recon_data = await perform_full_recon(target.domain)
    return ReconResult(**recon_data)


# ── History Endpoints ─────────────────────────────────────────────

@app.get("/api/scans")
async def list_scans():
    """List all past scan results."""
    return get_scans()


@app.get("/api/scans/{scan_id}")
async def get_scan_detail(scan_id: int):
    """Get a specific scan's full findings."""
    result = get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


# ── Scope Endpoints ───────────────────────────────────────────────

@app.get("/api/scope")
async def get_scope():
    """View current scope (allowed domains)."""
    return {"domains": scope_manager.get_domains()}


@app.post("/api/scope")
async def update_scope(update: ScopeUpdate):
    """Update the scope (allowed domains)."""
    scope_manager.set_domains(update.domains)
    return {"status": "updated", "domains": scope_manager.get_domains()}


@app.post("/api/scope/add")
async def add_to_scope(target: ScanTarget):
    """Add a domain to scope."""
    domain = target.domain
    if not domain:
        raise HTTPException(status_code=400, detail="domain is required")
    scope_manager.add_domain(domain)
    return {"status": "added", "domain": domain, "domains": scope_manager.get_domains()}
