"""
Authenticated session management.

Supports multiple auth strategies so the crawler can access pages behind login:
- Form-based login (POST username/password to a login URL)
- Bearer token (Authorization header)
- Cookie injection (paste a session cookie from your browser)
- Basic auth (HTTP Basic)

After authenticating, returns a requests.Session (for the crawler) and
optionally Playwright browser cookies (for screenshot capture).
"""

import requests
from urllib.parse import urljoin

from .crawler import DEFAULT_HEADERS


class AuthConfig:
    """Container for authentication settings provided by the user."""

    def __init__(self, method, **kwargs):
        """
        method: one of 'form', 'bearer', 'cookie', 'basic', 'none'
        kwargs vary by method:
          form:   login_url, username_field, password_field, username, password, extra_fields={}
          bearer: token
          cookie: cookies (dict of name->value)
          basic:  username, password
        """
        self.method = method
        self.params = kwargs

    def to_dict(self):
        safe = {**self.params}
        # Mask secrets for storage/display
        for key in ('password', 'token'):
            if key in safe:
                safe[key] = '***'
        return {"method": self.method, **safe}

    @classmethod
    def from_dict(cls, data):
        method = data.pop("method", "none")
        return cls(method, **data)


def create_authenticated_session(base_url, auth_config):
    """
    Build a requests.Session with auth applied.
    Returns (session, auth_cookies_for_playwright, error_or_none)
    """
    if auth_config is None or auth_config.method == "none":
        return requests.Session(), [], None

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    pw_cookies = []

    try:
        if auth_config.method == "bearer":
            token = auth_config.params["token"]
            session.headers["Authorization"] = f"Bearer {token}"

        elif auth_config.method == "basic":
            session.auth = (
                auth_config.params["username"],
                auth_config.params["password"],
            )

        elif auth_config.method == "cookie":
            cookies = auth_config.params.get("cookies", {})
            for name, value in cookies.items():
                session.cookies.set(name, value)
                pw_cookies.append({"name": name, "value": value, "url": base_url})

        elif auth_config.method == "form":
            p = auth_config.params
            login_url = p.get("login_url") or urljoin(base_url, "/login")
            payload = {
                p.get("username_field", "username"): p["username"],
                p.get("password_field", "password"): p["password"],
            }
            # Merge any extra hidden fields (CSRF token name, etc.)
            payload.update(p.get("extra_fields", {}))

            resp = session.post(login_url, data=payload, allow_redirects=True, timeout=15)

            if resp.status_code >= 400:
                return None, [], f"Login POST returned HTTP {resp.status_code}"

            # Check we actually got a session cookie back
            if not session.cookies:
                return None, [], "Login appeared to succeed (HTTP 200) but no session cookie was set."

            # Convert session cookies for Playwright
            for cookie in session.cookies:
                pw_cookies.append({
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path or "/",
                    "url": base_url,
                })

        else:
            return None, [], f"Unknown auth method: {auth_config.method}"

    except requests.exceptions.RequestException as e:
        return None, [], f"Auth request failed: {e}"

    return session, pw_cookies, None


def verify_session(session, base_url, expected_indicator=None):
    """
    Quick check that the session is actually authenticated.
    If expected_indicator is provided (a string that should appear on the
    logged-in page), we verify it's present.
    Returns (is_authenticated: bool, detail: str)
    """
    try:
        resp = session.get(base_url, timeout=10)
        if resp.status_code == 401 or resp.status_code == 403:
            return False, f"Got HTTP {resp.status_code} \u2014 session likely not authenticated."
        if expected_indicator and expected_indicator not in resp.text:
            return False, f"Expected indicator '{expected_indicator}' not found on page \u2014 login may have failed."
        return True, "Session appears authenticated."
    except requests.exceptions.RequestException as e:
        return False, f"Could not verify session: {e}"
