# WebTester

A local dashboard for checking a website's **security posture** and **functional health**. Enter a URL, click "Run scan," and get a categorized report you can keep or export.

⚠️ **Only scan sites you own or have explicit authorization to test** (e.g. a bug bounty program's in-scope assets, or your own client's site under a signed agreement). Automated scanning of sites you don't have permission for can violate terms of service or the law, and can get you disqualified from bounty programs that have specific scope/rate-limit rules — check the program's policy first.

## What it checks

**Security** (all passive/non-destructive — no exploit payloads are sent):
- Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Cookie flags (Secure / HttpOnly / SameSite)
- TLS certificate validity, expiry, and protocol version
- Clickjacking protection
- CORS misconfiguration (wildcard + credentials, reflected Origin)
- Mixed content on HTTPS pages
- Exposed sensitive paths (`.git/config`, `.env`, backup files, `phpinfo.php`, etc.)
- `robots.txt` / `sitemap.xml` review
- Server/framework version disclosure

**Functionality**:
- Crawls internal pages (same-domain only, capped at 40 pages / depth 3 by default)
- Broken links / 404s / 5xx errors
- Internal links that point to dead pages
- Slow-responding pages (>2s)
- Long redirect chains
- Forms found on the site, with a passive review (GET forms carrying passwords, missing CSRF token field, missing form action)

**Authentication** (scan behind login):
- Form-based login (POST username/password to a login URL)
- Bearer token (paste a JWT or API key)
- Cookie injection (paste session cookies from your browser DevTools)
- HTTP Basic auth
- Crawler uses the authenticated session to discover and check protected pages

**Screenshot Capture**:
- Automatically captures screenshots of pages that return errors (4xx, 5xx)
- Captures JavaScript console errors alongside the screenshot
- Screenshots viewable in the dashboard "Screenshots" tab
- Full-page captures using headless Chromium (via Playwright)

What it deliberately does **not** do: SQL injection / XSS payload testing, brute-forcing, authentication bypass attempts, or anything that writes/modifies data on the target. Those require active exploitation and are out of scope for an automated, no-questions-asked tool — for that kind of testing under an authorized engagement, tools like Burp Suite or OWASP ZAP (used manually, within agreed scope) are the standard.

## Setup

```bash
cd webtester
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium      # one-time browser download
python3 app.py
```

Then open **http://127.0.0.1:5050** in your browser.

## Using it

1. Paste a URL (with or without `https://`) into the bar at the top and click **Run scan**.
2. (Optional) Click **🔐** to expand the auth panel — choose a method (form login, bearer token, cookie, or basic auth) and fill in credentials. The scan will log in first, then crawl authenticated pages.
3. The status line updates while it crawls and checks the site (usually 10–60 seconds depending on site size).
4. Once done, results appear split into **Security**, **Functionality**, and **Screenshots** tabs, with severity badges (High / Medium / Low / Info).
5. If any pages returned errors, their screenshots appear in the Screenshots tab — click to view full-size.
6. Click **Download full report (HTML)** to save a standalone report you can attach to a bounty submission or client email.
7. Past scans are listed in the left sidebar — click any to reload its results.

## Project structure

```
webtester/
├── app.py                        # Flask API + serves the dashboard
├── requirements.txt
├── reports.db                    # created on first run (SQLite scan history)
├── reports/screenshots/          # auto-captured error screenshots
├── scanner/
│   ├── auth.py                   # authenticated session management
│   ├── crawler.py                # shared same-domain crawler
│   ├── screenshots.py            # Playwright-based screenshot capture
│   ├── security_checks.py        # security findings
│   ├── functionality_checks.py   # functionality findings
│   └── report.py                 # standalone HTML report builder
├── templates/
│   └── dashboard.html
└── static/
    ├── style.css
    └── app.js
```

## Extending it

Some natural next additions, if useful:
- **Module-aware scanning** — group findings by URL path prefix/navigation section so results map to app modules.
- **JS console error capture** — already captured alongside screenshots; could expand to monitor all pages, not just errored ones.
- **API endpoint discovery** — intercept XHR/fetch calls via Playwright to map the hidden API surface.
- **DOM-based XSS detection** — check for unsafe patterns (`innerHTML`, `document.write`, `eval`) in page scripts.
- **Content diff / regression** — re-scan periodically, diff results, surface new findings only.
- **Session fixation / logout checks** — verify session token rotates after login and invalidates after logout.
- **Rate limit testing** — send rapid identical requests, check if the app rate-limits.
- **File upload testing** — if upload forms exist, probe with edge-case MIME types.
- **Subdomain enumeration** — discover related subdomains (crt.sh, DNS) and optionally include them in scope.
- **Custom check plugins** — let users drop Python scripts into a `checks/` folder that run per-page.
- **Slack/email alerts** — notify when a scheduled re-scan finds new HIGH findings.
- **Scheduled re-scans** — cron/APScheduler to re-run against the same target periodically and diff results.
- **Export to Markdown** for bounty platforms that expect that format instead of HTML.

Let me know which of these matters most for how you're using it and I'll build it in.
