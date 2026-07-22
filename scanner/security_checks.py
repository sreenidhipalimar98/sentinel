"""
Passive & safe security checks.

Everything here is non-destructive: we only ever read what a normal browser
would read (headers, TLS cert info, well-known paths) or request URLs that
are widely published for exactly this purpose (checking whether sensitive
files are accidentally exposed). We never attempt to inject payloads,
brute-force credentials, or exploit anything found.
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

from .crawler import DEFAULT_HEADERS, fetch

SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _finding(check, severity, message, detail=None):
    return {
        "check": check,
        "severity": severity,
        "message": message,
        "detail": detail or "",
    }


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "advice": "Add HSTS so browsers always use HTTPS for this domain.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "advice": "Add a CSP to reduce impact of any injected scripts (XSS).",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "advice": "Add 'X-Content-Type-Options: nosniff' to stop MIME-sniffing.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "advice": "Add X-Frame-Options or CSP frame-ancestors to prevent clickjacking.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "advice": "Add a Referrer-Policy to limit data leaked via the Referer header.",
    },
    "Permissions-Policy": {
        "severity": "info",
        "advice": "Consider a Permissions-Policy to restrict powerful browser features.",
    },
}


def check_security_headers(url):
    findings = []
    result = fetch(url)
    if result.error or not result.response:
        findings.append(_finding("headers", "info", f"Could not fetch {url}: {result.error}"))
        return findings

    headers = result.response.headers

    for header, meta in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(_finding(
                "headers", meta["severity"],
                f"Missing header: {header}", meta["advice"],
            ))

    # clickjacking double-check via CSP frame-ancestors
    csp = headers.get("Content-Security-Policy", "")
    xfo = headers.get("X-Frame-Options", "")
    if not xfo and "frame-ancestors" not in csp:
        findings.append(_finding(
            "clickjacking", "medium",
            "No clickjacking protection (X-Frame-Options / frame-ancestors) detected.",
        ))

    # server / tech disclosure
    server = headers.get("Server")
    powered_by = headers.get("X-Powered-By")
    if server:
        findings.append(_finding(
            "info_disclosure", "info",
            f"Server header discloses: {server}",
            "Consider suppressing or genericizing the Server header.",
        ))
    if powered_by:
        findings.append(_finding(
            "info_disclosure", "low",
            f"X-Powered-By header discloses: {powered_by}",
            "Remove X-Powered-By to avoid revealing framework/version.",
        ))

    # cookies
    set_cookie_headers = None
    raw_headers = getattr(result.response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        set_cookie_headers = raw_headers.getlist("Set-Cookie")
    if set_cookie_headers:
        for cookie in set_cookie_headers:
            lc = cookie.lower()
            issues = []
            if "secure" not in lc:
                issues.append("missing Secure flag")
            if "httponly" not in lc:
                issues.append("missing HttpOnly flag")
            if "samesite" not in lc:
                issues.append("missing SameSite attribute")
            if issues:
                name = cookie.split("=")[0]
                findings.append(_finding(
                    "cookies", "medium",
                    f"Cookie '{name}' is {', '.join(issues)}.",
                ))

    return findings


# ---------------------------------------------------------------------------
# TLS / SSL
# ---------------------------------------------------------------------------

def check_tls(url):
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(_finding("tls", "high", "Site is not served over HTTPS."))
        return findings

    host = parsed.hostname
    port = parsed.port or 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days

        if days_left < 0:
            findings.append(_finding("tls", "high", "TLS certificate has expired.", f"Expired {abs(days_left)} days ago"))
        elif days_left < 14:
            findings.append(_finding("tls", "medium", f"TLS certificate expires very soon ({days_left} days).", ))
        elif days_left < 30:
            findings.append(_finding("tls", "low", f"TLS certificate expires in {days_left} days."))
        else:
            findings.append(_finding("tls", "info", f"TLS certificate valid for {days_left} more days."))

        if tls_version in ("TLSv1", "TLSv1.1"):
            findings.append(_finding("tls", "high", f"Outdated TLS version in use: {tls_version}"))
        else:
            findings.append(_finding("tls", "info", f"TLS version: {tls_version}, cipher: {cipher[0] if cipher else 'unknown'}"))

    except ssl.SSLCertVerificationError as e:
        findings.append(_finding("tls", "high", "TLS certificate verification failed.", str(e)))
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        findings.append(_finding("tls", "info", f"Could not establish TLS connection: {e}"))
    except Exception as e:
        findings.append(_finding("tls", "info", f"TLS check error: {e}"))

    return findings


# ---------------------------------------------------------------------------
# Exposed sensitive files / paths (publicly documented "well-known" checks)
# ---------------------------------------------------------------------------

SENSITIVE_PATHS = [
    (".git/config", "high", "Exposed .git directory can leak full source history."),
    (".env", "high", "Exposed .env file can leak credentials/secrets."),
    (".env.local", "high", "Exposed .env.local file can leak credentials/secrets."),
    ("wp-config.php.bak", "high", "Backup of WordPress config may leak DB credentials."),
    ("config.php.bak", "high", "Backup config file may leak credentials."),
    (".DS_Store", "low", "Exposed .DS_Store can leak directory structure."),
    ("backup.zip", "medium", "Exposed backup archive."),
    ("phpinfo.php", "medium", "phpinfo() page discloses detailed server configuration."),
    (".well-known/security.txt", "info", "security.txt present (good practice, not a vulnerability)."),
    ("server-status", "medium", "Apache server-status may expose live request/traffic info."),
    ("admin/", "info", "Admin path is reachable and returns a response."),
]


def check_exposed_paths(base_url):
    findings = []
    session = requests.Session()
    for path, severity, message in SENSITIVE_PATHS:
        target = urljoin(base_url if base_url.endswith("/") else base_url + "/", path)
        result = fetch(target, timeout=6, session=session)
        if result.error:
            continue
        if result.status_code == 200:
            # security.txt being present is good, not a problem -- keep its info severity
            findings.append(_finding("exposed_paths", severity, f"{path} is accessible (HTTP 200).", target))
    return findings


# ---------------------------------------------------------------------------
# robots.txt / sitemap.xml disclosure review
# ---------------------------------------------------------------------------

def check_robots_and_sitemap(base_url):
    findings = []
    robots_url = urljoin(base_url, "/robots.txt")
    result = fetch(robots_url, timeout=6)
    if result.response and result.status_code == 200:
        disallowed = [
            line.split(":", 1)[1].strip()
            for line in result.response.text.splitlines()
            if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()
        ]
        interesting = [p for p in disallowed if any(k in p.lower() for k in
                       ["admin", "backup", "config", "private", "internal", "staging", "test"])]
        if interesting:
            findings.append(_finding(
                "robots_txt", "low",
                f"robots.txt hints at sensitive paths: {', '.join(interesting[:8])}",
                "Disallowed paths in robots.txt are still publicly requestable; don't rely on it for access control.",
            ))

    sitemap_url = urljoin(base_url, "/sitemap.xml")
    result = fetch(sitemap_url, timeout=6)
    if result.response and result.status_code == 200:
        findings.append(_finding("sitemap", "info", "sitemap.xml is present and accessible."))

    return findings


# ---------------------------------------------------------------------------
# CORS misconfiguration (passive: reflect an Origin header, see what comes back)
# ---------------------------------------------------------------------------

def check_cors(url):
    findings = []
    try:
        probe_origin = "https://cors-test.invalid-example.com"
        resp = requests.get(url, headers={**DEFAULT_HEADERS, "Origin": probe_origin}, timeout=8)
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")
        if acao == "*" and acac and acac.lower() == "true":
            findings.append(_finding(
                "cors", "high",
                "CORS allows '*' together with Allow-Credentials: true, which is invalid/dangerous if a browser honors it.",
            ))
        elif acao == probe_origin:
            findings.append(_finding(
                "cors", "high",
                "Server reflects arbitrary Origin header back in Access-Control-Allow-Origin.",
                "This can allow any website to make authenticated cross-origin requests on a victim's behalf.",
            ))
        elif acao == "*":
            findings.append(_finding("cors", "info", "CORS Access-Control-Allow-Origin is '*' (fine for public APIs, risky for anything session-authenticated)."))
    except requests.exceptions.RequestException as e:
        findings.append(_finding("cors", "info", f"CORS check could not complete: {e}"))
    return findings


# ---------------------------------------------------------------------------
# Mixed content (HTTPS page loading HTTP resources)
# ---------------------------------------------------------------------------

def check_mixed_content(url, html_text):
    findings = []
    if not url.startswith("https://"):
        return findings
    import re
    http_refs = set(re.findall(r'(?:src|href)=["\']http://[^"\']+', html_text))
    if http_refs:
        examples = list(http_refs)[:5]
        findings.append(_finding(
            "mixed_content", "medium",
            f"Page served over HTTPS references {len(http_refs)} insecure http:// resource(s).",
            "; ".join(examples),
        ))
    return findings


def run_all_security_checks(base_url):
    """Run every security check and return a flat list of findings."""
    all_findings = []
    all_findings += check_security_headers(base_url)
    all_findings += check_tls(base_url)
    all_findings += check_exposed_paths(base_url)
    all_findings += check_robots_and_sitemap(base_url)
    all_findings += check_cors(base_url)

    home = fetch(base_url)
    if home.response and "text/html" in home.response.headers.get("Content-Type", ""):
        all_findings += check_mixed_content(base_url, home.response.text)

    return all_findings
