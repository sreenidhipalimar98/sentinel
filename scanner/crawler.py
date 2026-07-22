"""
Lightweight, polite crawler shared by security & functionality checks.

Design goals:
- Stay within the target's own domain (no wandering off to third parties)
- Respect a request budget and per-request timeout so a scan can't run forever
- Add a small delay between requests to avoid hammering the target
- Never submit forms or send anything other than safe GET requests while crawling
"""

import time
from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

DEFAULT_HEADERS = {
    "User-Agent": "WebTesterBot/1.0 (+authorized-security-scan)"
}


class CrawlResult:
    def __init__(self, url, status_code=None, error=None, response=None,
                 response_time_ms=None, redirect_chain=None):
        self.url = url
        self.status_code = status_code
        self.error = error
        self.response = response
        self.response_time_ms = response_time_ms
        self.redirect_chain = redirect_chain or []

    def to_dict(self):
        return {
            "url": self.url,
            "status_code": self.status_code,
            "error": self.error,
            "response_time_ms": self.response_time_ms,
            "redirect_chain": self.redirect_chain,
        }


def _normalize(url):
    """Normalize a URL so equivalent forms (with/without trailing slash on
    the bare domain, fragments) are treated as the same page."""
    url = url.split("#")[0]
    parsed = urlparse(url)
    path = parsed.path or "/"
    normalized = parsed._replace(path=path).geturl()
    return normalized


def _same_domain(base_netloc, candidate_netloc):
    # Treat www.example.com and example.com as the same site
    def strip_www(netloc):
        return netloc[4:] if netloc.startswith("www.") else netloc
    return strip_www(base_netloc) == strip_www(candidate_netloc)


def fetch(url, timeout=8, allow_redirects=True, session=None):
    """Perform a single safe GET request and time it."""
    sess = session or requests
    start = time.time()
    try:
        resp = sess.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=True,
        )
        elapsed_ms = round((time.time() - start) * 1000, 1)
        redirect_chain = [r.url for r in resp.history]
        return CrawlResult(
            url=url,
            status_code=resp.status_code,
            response=resp,
            response_time_ms=elapsed_ms,
            redirect_chain=redirect_chain,
        )
    except requests.exceptions.SSLError as e:
        return CrawlResult(url=url, error=f"SSL error: {e}")
    except requests.exceptions.Timeout:
        return CrawlResult(url=url, error="Timeout")
    except requests.exceptions.ConnectionError as e:
        return CrawlResult(url=url, error=f"Connection error: {e}")
    except requests.exceptions.RequestException as e:
        return CrawlResult(url=url, error=str(e))


def crawl_site(start_url, max_pages=40, max_depth=3, delay=0.3, timeout=8, session=None):
    """
    Breadth-first crawl restricted to the same domain as start_url.
    Returns (pages: list[CrawlResult], forms: list[dict], link_map: dict[url -> [links]])
    
    If session is provided (e.g. an authenticated session), it will be used
    for all requests instead of creating a new one.
    """
    parsed_start = urlparse(start_url)
    base_netloc = parsed_start.netloc

    if session is None:
        session = requests.Session()
    visited = set()
    queue = deque([(_normalize(start_url), 0)])
    pages = []
    forms = []
    link_map = {}

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        norm_url = _normalize(url)
        if norm_url in visited:
            continue
        visited.add(norm_url)

        result = fetch(norm_url, timeout=timeout, session=session)
        pages.append(result)

        if result.error or not result.response:
            continue

        content_type = result.response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            continue

        soup = BeautifulSoup(result.response.text, "lxml")

        # collect forms for functionality checks
        for form in soup.find_all("form"):
            forms.append({
                "page": norm_url,
                "action": form.get("action", ""),
                "method": form.get("method", "get").lower(),
                "inputs": [
                    {"name": i.get("name"), "type": i.get("type", "text")}
                    for i in form.find_all(["input", "textarea", "select"])
                ],
            })

        if depth >= max_depth:
            continue

        page_links = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            full_url = _normalize(urljoin(norm_url, href))
            parsed = urlparse(full_url)
            if parsed.scheme not in ("http", "https"):
                continue
            page_links.append(full_url)
            if _same_domain(base_netloc, parsed.netloc) and full_url not in visited:
                queue.append((full_url, depth + 1))

        link_map[norm_url] = page_links
        time.sleep(delay)

    return pages, forms, link_map
