"""
Functionality / QA checks: crawl the site and verify it behaves the way a
normal visitor would expect. Read-only GETs only during the crawl; the one
exception (form submission smoke-test) is opt-in and only ever sends
harmless placeholder values, never during the default crawl.
"""

from urllib.parse import urlparse

from .crawler import crawl_site


SLOW_THRESHOLD_MS = 2000


def analyze_pages(pages):
    """Turn raw CrawlResult objects into functionality findings."""
    findings = []
    broken = []
    slow = []
    redirect_chains = []
    server_errors = []

    for page in pages:
        if page.error:
            broken.append({"url": page.url, "reason": page.error})
            continue

        if page.status_code and page.status_code >= 500:
            server_errors.append({"url": page.url, "status": page.status_code})
        elif page.status_code == 404:
            broken.append({"url": page.url, "reason": "404 Not Found"})
        elif page.status_code and page.status_code >= 400:
            broken.append({"url": page.url, "reason": f"HTTP {page.status_code}"})

        if page.response_time_ms and page.response_time_ms > SLOW_THRESHOLD_MS:
            slow.append({"url": page.url, "ms": page.response_time_ms})

        if len(page.redirect_chain) > 2:
            redirect_chains.append({"url": page.url, "chain": page.redirect_chain})

    if broken:
        findings.append({
            "check": "broken_links",
            "severity": "medium",
            "message": f"{len(broken)} broken link(s)/error page(s) found.",
            "detail": broken,
        })
    if server_errors:
        findings.append({
            "check": "server_errors",
            "severity": "high",
            "message": f"{len(server_errors)} page(s) returned a 5xx server error.",
            "detail": server_errors,
        })
    if slow:
        findings.append({
            "check": "slow_pages",
            "severity": "low",
            "message": f"{len(slow)} page(s) took longer than {SLOW_THRESHOLD_MS}ms to respond.",
            "detail": slow,
        })
    if redirect_chains:
        findings.append({
            "check": "redirect_chains",
            "severity": "info",
            "message": f"{len(redirect_chains)} page(s) go through long redirect chains.",
            "detail": redirect_chains,
        })

    return findings


def analyze_forms(forms):
    """Passive review of forms found while crawling (no submission)."""
    findings = []
    issues = []
    for form in forms:
        problems = []
        if form["method"] == "get" and any(
            i["type"] == "password" for i in form["inputs"]
        ):
            problems.append("password field submitted via GET (would leak into URL/logs)")
        if not form["action"]:
            problems.append("form has no explicit action (submits to current URL, verify this is intended)")

        has_csrf_hint = any(
            i["name"] and "csrf" in i["name"].lower() for i in form["inputs"]
        )
        if form["method"] == "post" and not has_csrf_hint:
            problems.append("no obvious CSRF token field found (may still be handled via cookies/headers)")

        if problems:
            issues.append({"page": form["page"], "action": form["action"], "problems": problems})

    if issues:
        findings.append({
            "check": "forms",
            "severity": "medium",
            "message": f"{len(issues)} form(s) have potential issues worth a manual look.",
            "detail": issues,
        })
    else:
        findings.append({
            "check": "forms",
            "severity": "info",
            "message": f"{len(forms)} form(s) found, no obvious issues from passive review.",
        })

    return findings


def check_broken_link_targets(link_map, known_status):
    """Cross-check internal links against pages we already have status for."""
    findings = []
    dead_targets = []
    for source_page, links in link_map.items():
        for link in links:
            status = known_status.get(link)
            if status is not None and status >= 400:
                dead_targets.append({"on_page": source_page, "links_to": link, "status": status})
    if dead_targets:
        findings.append({
            "check": "dead_link_targets",
            "severity": "medium",
            "message": f"{len(dead_targets)} internal link(s) point to pages that return errors.",
            "detail": dead_targets[:25],
        })
    return findings


def run_all_functionality_checks(base_url, max_pages=40, max_depth=3, session=None):
    pages, forms, link_map = crawl_site(base_url, max_pages=max_pages, max_depth=max_depth, session=session)

    known_status = {p.url: p.status_code for p in pages if p.status_code is not None}

    findings = []
    findings += analyze_pages(pages)
    findings += analyze_forms(forms)
    findings += check_broken_link_targets(link_map, known_status)

    summary = {
        "pages_crawled": len(pages),
        "forms_found": len(forms),
        "unique_internal_links": sum(len(v) for v in link_map.values()),
    }

    return findings, summary
