from scanner.core import Finding, Severity, ScanSession


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "description": "HTTP Strict Transport Security (HSTS) header is missing. This allows downgrade attacks and cookie hijacking.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        "cwe": "CWE-319",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, leading to XSS via content type confusion.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
        "cwe": "CWE-16",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options header is missing. The site may be vulnerable to clickjacking attacks.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
        "cwe": "CWE-1021",
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "Content-Security-Policy header is missing. This increases the impact of XSS vulnerabilities.",
        "remediation": "Implement a strict Content-Security-Policy header.",
        "cwe": "CWE-16",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy header is missing. Sensitive URL paths and query params may leak via Referer header.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
        "cwe": "CWE-16",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy header is missing. Browser features like camera, microphone, geolocation are not restricted.",
        "remediation": "Add a Permissions-Policy header restricting unnecessary browser features.",
        "cwe": "CWE-16",
    },
}

DANGEROUS_HEADERS = {
    "X-Powered-By": "Technology stack disclosed",
    "X-AspNet-Version": "ASP.NET version disclosed",
    "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
}

SESSION_COOKIE_NAMES = {
    "sessionid", "session_id", "phpsessid", "jsessionid", "asp.net_sessionid",
    "connect.sid", "laravel_session", "ci_session", "cakephp", "_session",
    "sid", "sess", "token", "auth", "jwt",
}


def _is_session_cookie(cookie) -> bool:
    name_lower = cookie.name.lower()
    if any(s in name_lower for s in SESSION_COOKIE_NAMES):
        return True
    if len(cookie.value) >= 20:
        return True
    return False


def run(session: ScanSession) -> None:
    print("\n[*] Checking security headers...")
    resp = session.get(session.config.target)
    if not resp:
        return

    headers = resp.headers

    for header_name, info in SECURITY_HEADERS.items():
        if header_name.lower() not in {k.lower() for k in headers}:
            session.add_finding(Finding(
                title=f"Missing Security Header: {header_name}",
                severity=info["severity"],
                description=info["description"],
                evidence=f"Response headers do not contain '{header_name}'",
                remediation=info["remediation"],
                url=session.config.target,
                module="headers",
                cwe=info["cwe"],
                confirmed=True,
            ))

    csp = headers.get("Content-Security-Policy", "")
    if csp:
        if "unsafe-inline" in csp:
            session.add_finding(Finding(
                title="CSP Allows unsafe-inline",
                severity=Severity.MEDIUM,
                description="Content-Security-Policy contains 'unsafe-inline' which weakens XSS protection.",
                evidence=f"CSP: {csp}",
                remediation="Remove 'unsafe-inline' and use nonce-based or hash-based CSP.",
                url=session.config.target,
                module="headers",
                cwe="CWE-16",
                confirmed=True,
            ))
        if "unsafe-eval" in csp:
            session.add_finding(Finding(
                title="CSP Allows unsafe-eval",
                severity=Severity.MEDIUM,
                description="Content-Security-Policy contains 'unsafe-eval' which allows JavaScript eval().",
                evidence=f"CSP: {csp}",
                remediation="Remove 'unsafe-eval' from CSP.",
                url=session.config.target,
                module="headers",
                cwe="CWE-16",
                confirmed=True,
            ))

    for header_name, desc in DANGEROUS_HEADERS.items():
        value = headers.get(header_name, "")
        if value:
            session.add_finding(Finding(
                title=f"Information Disclosure: {desc}",
                severity=Severity.LOW,
                description=f"The '{header_name}' header reveals server information.",
                evidence=f"{header_name}: {value}",
                remediation=f"Remove or suppress the '{header_name}' header in production.",
                url=session.config.target,
                module="headers",
                cwe="CWE-200",
                confirmed=True,
            ))

    for cookie in resp.cookies:
        if not _is_session_cookie(cookie):
            continue

        if session.config.target.startswith("https") and not cookie.secure:
            session.add_finding(Finding(
                title=f"Cookie Missing Secure Flag: {cookie.name}",
                severity=Severity.MEDIUM,
                description=f"Session cookie '{cookie.name}' is not marked Secure.",
                evidence=f"Cookie: {cookie.name}={cookie.value[:20]}...",
                remediation="Add the Secure flag to all session cookies.",
                url=session.config.target,
                module="headers",
                cwe="CWE-614",
                confirmed=True,
            ))

        if not cookie.has_nonstandard_attr("HttpOnly"):
            session.add_finding(Finding(
                title=f"Cookie Missing HttpOnly Flag: {cookie.name}",
                severity=Severity.MEDIUM,
                description=f"Session cookie '{cookie.name}' is not marked HttpOnly.",
                evidence=f"Cookie: {cookie.name}",
                remediation="Add the HttpOnly flag to session cookies.",
                url=session.config.target,
                module="headers",
                cwe="CWE-1004",
                confirmed=True,
            ))

        if not cookie.has_nonstandard_attr("SameSite"):
            session.add_finding(Finding(
                title=f"Cookie Missing SameSite Attribute: {cookie.name}",
                severity=Severity.LOW,
                description=f"Session cookie '{cookie.name}' lacks the SameSite attribute.",
                evidence=f"Cookie: {cookie.name}",
                remediation="Add 'SameSite=Strict' or 'SameSite=Lax' to cookies.",
                url=session.config.target,
                module="headers",
                cwe="CWE-1275",
                confirmed=True,
            ))
