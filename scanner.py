"""
Website Security Scanner (v0.4) - scan engine
Checks: HTTPS, SSL certificate, HTTP->HTTPS redirect, HSTS, security headers.
Gives a score out of 100 and a fix suggestion for every failed check.
 
Install:  pip install requests
Run:      python scanner.py example.com     (scan one site)
          python scanner.py                 (paste links one after another)
For the web page version run:  python app.py
"""
 
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse
 
import requests
 
TIMEOUT = 10  # seconds to wait for each request
HEADERS = {"User-Agent": "WebSecurityScanner/0.4 (educational project)"}
EXPIRY_WARNING_DAYS = 30
HSTS_MIN_AGE = 15552000  # 180 days
 
# Points per check (they add up to 100)
POINTS = {
    "HTTPS": 20,
    "SSL certificate": 20,
    "HTTP to HTTPS redirect": 15,
    "HSTS": 15,
    "Content-Security-Policy": 10,
    "X-Frame-Options": 8,
    "X-Content-Type-Options": 6,
    "Referrer-Policy": 6,
}
 
 
def make_check(name, passed, message, fix="", skipped=False):
    max_points = POINTS[name]
    return {
        "name": name,
        "passed": passed,
        "skipped": skipped,
        "points": max_points if passed else 0,
        "max": max_points,
        "message": message,
        "fix": fix,
    }
 
 
def skip_check(name, reason):
    return make_check(name, False, f"Skipped - {reason}", skipped=True)
 
 
# ---------- Step 1: URL handling ----------
 
def get_hostname(raw_url: str) -> str:
    """Accepts example.com or https://example.com/page and returns the hostname."""
    raw_url = raw_url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
 
    hostname = urlparse(raw_url).hostname
    if not hostname or "." not in hostname:
        raise ValueError(f"Invalid URL: {raw_url}")
    return hostname
 
 
# ---------- Step 2: HTTPS checks ----------
 
def check_https_available(hostname: str):
    """Returns (check, response_headers)."""
    name = "HTTPS"
    fix = "Install an SSL certificate and serve the site over HTTPS (Let's Encrypt is free)."
    try:
        response = requests.get(
            f"https://{hostname}", timeout=TIMEOUT, headers=HEADERS
        )
        return make_check(name, True, "Site supports HTTPS"), response.headers
    except requests.exceptions.SSLError:
        return make_check(
            name, False, "HTTPS is enabled but the certificate has a problem", fix
        ), {}
    except requests.exceptions.RequestException as error:
        return make_check(
            name, False, f"Could not connect over HTTPS ({type(error).__name__})", fix
        ), {}
 
 
def check_http_redirect(hostname: str) -> dict:
    name = "HTTP to HTTPS redirect"
    fix = (
        "Configure the server to redirect all HTTP requests to HTTPS (301). "
        "Note: sites on the browsers' HSTS preload list may still be safe without it."
    )
    try:
        response = requests.get(
            f"http://{hostname}",
            timeout=TIMEOUT,
            headers=HEADERS,
            allow_redirects=True,
        )
        if response.url.startswith("https://"):
            return make_check(name, True, "HTTP redirects to HTTPS")
        return make_check(
            name, False, "HTTP does not redirect to HTTPS (visitor data is unprotected)", fix
        )
    except requests.exceptions.RequestException as error:
        return make_check(
            name, False, f"Could not test the redirect ({type(error).__name__})", fix
        )
 
 
def check_hsts(headers) -> dict:
    name = "HSTS"
    fix = "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    value = headers.get("Strict-Transport-Security")
    if not value:
        return make_check(
            name, False, "HSTS header is missing (browsers are not forced to use HTTPS)", fix
        )
 
    max_age = 0
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass
 
    if max_age >= HSTS_MIN_AGE:
        return make_check(name, True, f"HSTS enabled (max-age={max_age})")
    return make_check(
        name, False, f"HSTS max-age is too short ({max_age}s)", fix
    )
 
 
# ---------- Step 3: SSL certificate ----------
 
def check_ssl_certificate(hostname: str, port: int = 443, context=None) -> dict:
    """Reads the SSL certificate: issuer, expiry date, days remaining."""
    name = "SSL certificate"
    fix = "Renew or replace the certificate with one from a trusted authority."
    context = context or ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as error:
        return make_check(
            name, False, f"Certificate rejected: {error.verify_message}", fix
        )
    except ssl.SSLError as error:
        return make_check(name, False, f"TLS handshake failed ({error.reason})", fix)
    except OSError as error:
        return make_check(
            name, False, f"Could not read the certificate ({type(error).__name__})", fix
        )
 
    expires = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc
    )
    days_left = (expires - datetime.now(timezone.utc)).days
    issuer = dict(item[0] for item in cert["issuer"]).get("organizationName", "Unknown")
    details = f"issuer: {issuer}, expires: {expires:%Y-%m-%d} ({days_left} days left)"
 
    if days_left < EXPIRY_WARNING_DAYS:
        return make_check(name, False, f"Certificate expires soon - {details}", fix)
    return make_check(name, True, f"Certificate is valid - {details}")
 
 
# ---------- Step 4: Security headers ----------
 
def check_security_headers(headers) -> list:
    checks = []
 
    csp = headers.get("Content-Security-Policy")
    checks.append(
        make_check("Content-Security-Policy", True, "Content-Security-Policy is set")
        if csp
        else make_check(
            "Content-Security-Policy",
            False,
            "Content-Security-Policy header is missing",
            "Add a Content-Security-Policy header to limit where scripts and resources can load from.",
        )
    )
 
    # Clickjacking protection: X-Frame-Options, or frame-ancestors inside the CSP
    xfo = headers.get("X-Frame-Options")
    if xfo or (csp and "frame-ancestors" in csp.lower()):
        checks.append(make_check("X-Frame-Options", True, "Clickjacking protection is set"))
    else:
        checks.append(
            make_check(
                "X-Frame-Options",
                False,
                "No clickjacking protection (X-Frame-Options is missing)",
                "Add X-Frame-Options: DENY (or SAMEORIGIN) to prevent clickjacking.",
            )
        )
 
    xcto = headers.get("X-Content-Type-Options", "")
    checks.append(
        make_check("X-Content-Type-Options", True, "X-Content-Type-Options: nosniff")
        if xcto.lower() == "nosniff"
        else make_check(
            "X-Content-Type-Options",
            False,
            "X-Content-Type-Options is missing or not 'nosniff'",
            "Add X-Content-Type-Options: nosniff.",
        )
    )
 
    checks.append(
        make_check("Referrer-Policy", True, "Referrer-Policy is set")
        if headers.get("Referrer-Policy")
        else make_check(
            "Referrer-Policy",
            False,
            "Referrer-Policy header is missing",
            "Add Referrer-Policy: strict-origin-when-cross-origin.",
        )
    )
    return checks
 
 
# ---------- Score ----------
 
def calculate_score(checks: list) -> int:
    """Skipped checks are left out, so a site never loses points twice for one problem."""
    active = [c for c in checks if not c["skipped"]]
    total = sum(c["max"] for c in active)
    if total == 0:
        return 0
    return round(100 * sum(c["points"] for c in active) / total)
 
 
def get_grade(score: int) -> str:
    for limit, grade in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if score >= limit:
            return grade
    return "F"
 
 
# ---------- Run ----------
 
def scan(raw_url: str) -> dict:
    hostname = get_hostname(raw_url)
    https_check, headers = check_https_available(hostname)
    ssl_check = check_ssl_certificate(hostname)
 
    if https_check["passed"]:
        checks = [
            https_check,
            ssl_check,
            check_http_redirect(hostname),
            check_hsts(headers),
            *check_security_headers(headers),
        ]
    else:
        reason = "HTTPS is not working on this site"
        checks = [
            https_check,
            ssl_check,
            skip_check("HTTP to HTTPS redirect", reason),
            skip_check("HSTS", reason),
            skip_check("Content-Security-Policy", reason),
            skip_check("X-Frame-Options", reason),
            skip_check("X-Content-Type-Options", reason),
            skip_check("Referrer-Policy", reason),
        ]
 
    score = calculate_score(checks)
    return {
        "hostname": hostname,
        "checks": checks,
        "score": score,
        "grade": get_grade(score),
    }
 
 
def print_report(result: dict) -> None:
    print(f"\nScan report: {result['hostname']}")
    print("-" * 60)
    for check in result["checks"]:
        if check["skipped"]:
            mark = "[SKIP]"
        else:
            mark = "[PASS]" if check["passed"] else "[FAIL]"
        print(f"{mark} {check['message']}")
        if check["fix"] and not check["passed"]:
            print(f"       Fix: {check['fix']}")
    print("-" * 60)
    print(f"Security score: {result['score']}/100 (grade {result['grade']})\n")
 
 
def run_one(raw_url: str) -> None:
    try:
        print_report(scan(raw_url))
    except ValueError as error:
        print(error)
 
 
if __name__ == "__main__":
    if len(sys.argv) == 2:
        run_one(sys.argv[1])
    elif len(sys.argv) == 1:
        print("Paste a link and press Enter (type q to quit).")
        while True:
            try:
                link = input("\nLink: ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if link.lower() in ("q", "quit", "exit"):
                break
            if link:
                run_one(link)
    else:
        print("Usage: python scanner.py example.com")
        sys.exit(1)