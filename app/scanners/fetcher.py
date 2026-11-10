"""Async HTTP fetcher with concurrency control."""
import httpx
import asyncio
import logging

logger = logging.getLogger("secretscope.fetcher")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

async def fetch_url(url: str, timeout: float = 10.0) -> str | None:
    """Fetch a single URL. Returns response text or None on failure."""
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(timeout),
            verify=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.text
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        return None


async def fetch_many(
    urls: list[str], concurrency: int = 10
) -> dict[str, str]:
    """Fetch multiple URLs concurrently with a concurrency cap.
    Returns dict of url -> content (only successful fetches).
    """
    results: dict[str, str] = {}
    semaphore = asyncio.Semaphore(concurrency)

    async def _fetch_one(url: str):
        async with semaphore:
            content = await fetch_url(url)
            if content is not None:
                results[url] = content

    tasks = [asyncio.create_task(_fetch_one(u)) for u in urls]
    await asyncio.gather(*tasks, return_exceptions=True)
    return results
