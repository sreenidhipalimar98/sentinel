"""
Screenshot capture using Playwright (headless Chromium).

Takes screenshots when:
- A page returns a 4xx/5xx error
- A page has JavaScript console errors
- Explicitly requested for a URL

Screenshots are saved to the reports/screenshots/<scan_id>/ directory.
"""

import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

SCREENSHOTS_DIR = Path("reports/screenshots")


def _safe_filename(url):
    """Turn a URL into a safe, short filename."""
    parsed = urlparse(url)
    path_part = parsed.path.strip("/").replace("/", "_") or "index"
    # Remove non-alphanumeric chars
    cleaned = re.sub(r'[^a-zA-Z0-9_\-]', '', path_part)
    return cleaned[:80]


def capture_screenshots(urls, scan_id, cookies=None, timeout_ms=15000):
    """
    Capture screenshots for a list of URLs.
    
    Args:
        urls: list of dicts with keys: url, reason (why we're screenshotting)
        scan_id: scan identifier for organizing output
        cookies: list of Playwright cookie dicts to inject (for auth)
        timeout_ms: page load timeout
    
    Returns:
        list of dicts: {url, reason, screenshot_path, js_errors}
    """
    if not urls:
        return []

    from playwright.sync_api import sync_playwright

    scan_dir = SCREENSHOTS_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    results = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1280, "height": 900},
            ignore_https_errors=True,
        )

        # Inject auth cookies if provided
        if cookies:
            context.add_cookies(cookies)

        for i, item in enumerate(urls):
            url = item["url"]
            reason = item.get("reason", "error")
            js_errors = []

            page = context.new_page()

            # Capture JS console errors
            page.on("console", lambda msg: (
                js_errors.append(msg.text) if msg.type == "error" else None
            ))
            page.on("pageerror", lambda err: js_errors.append(str(err)))

            try:
                page.goto(url, timeout=timeout_ms, wait_until="networkidle")
            except Exception:
                try:
                    page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                except Exception:
                    pass

            # Small wait for any late-rendering
            page.wait_for_timeout(500)

            filename = f"{i:03d}_{_safe_filename(url)}.png"
            filepath = scan_dir / filename

            try:
                page.screenshot(path=str(filepath), full_page=True)
            except Exception:
                # If full_page fails (very tall pages), try viewport only
                try:
                    page.screenshot(path=str(filepath), full_page=False)
                except Exception:
                    filepath = None

            results.append({
                "url": url,
                "reason": reason,
                "screenshot_path": str(filepath) if filepath else None,
                "js_errors": js_errors,
            })

            page.close()

        context.close()
        browser.close()

    return results


def capture_full_crawl_screenshots(pages_with_issues, scan_id, cookies=None):
    """
    Given crawl results, capture screenshots for pages that had problems.
    
    Args:
        pages_with_issues: list of CrawlResult objects that had errors/issues
        scan_id: scan identifier
        cookies: Playwright cookies for auth
    
    Returns:
        list of screenshot result dicts
    """
    urls_to_capture = []

    for page in pages_with_issues:
        if page.error:
            urls_to_capture.append({"url": page.url, "reason": f"Error: {page.error}"})
        elif page.status_code and page.status_code >= 400:
            urls_to_capture.append({"url": page.url, "reason": f"HTTP {page.status_code}"})

    return capture_screenshots(urls_to_capture, scan_id, cookies=cookies)
