from scanner.core import Finding, Severity, ScanSession


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "description": "HTTP Strict Transport Security (HSTS) header is missing. This allows downgrade attacks and cookie hijacking.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        "cwe": "CWE-319",
        "dev_fix": "Web Server Config",
        "dev_detail": (
            "Apache: Add to .htaccess or VirtualHost:\n"
            "  Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
            "Nginx: Add to server block:\n"
            "  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
            "Express.js: Use helmet middleware:\n"
            "  app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }))"
        ),
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, leading to XSS via content type confusion.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
        "cwe": "CWE-16",
        "dev_fix": "Web Server Config",
        "dev_detail": (
            "Apache: Header always set X-Content-Type-Options \"nosniff\"\n"
            "Nginx: add_header X-Content-Type-Options \"nosniff\" always;\n"
            "Express.js: app.use(helmet.noSniff())"
        ),
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options header is missing. The site may be vulnerable to clickjacking attacks.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
        "cwe": "CWE-1021",
        "dev_fix": "Web Server Config",
        "dev_detail": (
            "Apache: Header always set X-Frame-Options \"DENY\"\n"
            "Nginx: add_header X-Frame-Options \"DENY\" always;\n"
            "Express.js: app.use(helmet.frameguard({ action: 'deny' }))\n"
            "Alternatively use CSP frame-ancestors directive: Content-Security-Policy: frame-ancestors 'none'"
        ),
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "Content-Security-Policy header is missing. This increases the impact of XSS vulnerabilities.",
        "remediation": "Implement a strict Content-Security-Policy header.",
        "cwe": "CWE-16",
        "dev_fix": "Web Server Config / Application Code",
        "dev_detail": (
            "Start with a restrictive policy and loosen as needed:\n"
            "  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;\n"
            "Use nonce-based approach for inline scripts:\n"
            "  Content-Security-Policy: script-src 'nonce-{random}'\n"
            "  <script nonce=\"{random}\">...</script>"
        ),
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy header is missing. Sensitive URL paths and query params may leak via Referer header.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
        "cwe": "CWE-16",
        "dev_fix": "Web Server Config",
        "dev_detail": (
            "Apache: Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
            "Nginx: add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
            "HTML meta: <meta name=\"referrer\" content=\"strict-origin-when-cross-origin\">"
        ),
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy header is missing. Browser features like camera, microphone, geolocation are not restricted.",
        "remediation": "Add a Permissions-Policy header restricting unnecessary browser features.",
        "cwe": "CWE-16",
        "dev_fix": "Web Server Config",
        "dev_detail": (
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()\n"
            "This disables camera, mic, geolocation, and payment APIs for the page.\n"
            "Adjust based on your application's actual feature requirements."
        ),
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
    all_headers_str = "\n".join(f"  {k}: {v}" for k, v in headers.items())
    curl_cmd = f"curl -kI '{session.config.target}'"

    for header_name, info in SECURITY_HEADERS.items():
        if header_name.lower() not in {k.lower() for k in headers}:
            session.add_finding(Finding(
                title=f"Missing Security Header: {header_name}",
                severity=info["severity"],
                description=info["description"],
                evidence=f"Response headers do not contain '{header_name}'\n\nAll response headers:\n{all_headers_str}",
                remediation=info["remediation"],
                url=session.config.target,
                module="headers",
                cwe=info["cwe"],
                confirmed=True,
                location=f"HTTP response headers from {session.config.target}",
                request_method="GET",
                response_status=resp.status_code,
                response_headers=all_headers_str,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Send an HTTP request to {session.config.target}\n"
                    f"2. Inspect the response headers.\n"
                    f"3. The '{header_name}' header is absent from the response.\n"
                    f"4. Run: {curl_cmd}"
                ),
                developer_fix=(
                    f"Component: {info['dev_fix']}\n\n{info['dev_detail']}"
                ),
                affected_component=info["dev_fix"],
                references=f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header_name}",
                detection_method="Inspected HTTP response headers for missing or misconfigured security headers (X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, etc.) by comparing against OWASP recommended values.",
            ))

    csp = headers.get("Content-Security-Policy", "")
    if csp:
        if "unsafe-inline" in csp:
            session.add_finding(Finding(
                title="CSP Allows unsafe-inline",
                severity=Severity.MEDIUM,
                description="Content-Security-Policy contains 'unsafe-inline' which weakens XSS protection by allowing inline script execution.",
                evidence=f"CSP Header Value: {csp}",
                remediation="Remove 'unsafe-inline' and use nonce-based or hash-based CSP instead.",
                url=session.config.target,
                module="headers",
                cwe="CWE-16",
                confirmed=True,
                location="Content-Security-Policy response header",
                curl_command=curl_cmd,
                developer_fix=(
                    "Replace 'unsafe-inline' with nonce-based CSP:\n"
                    "1. Generate a random nonce per request.\n"
                    "2. Set header: Content-Security-Policy: script-src 'nonce-{random}'\n"
                    "3. Add nonce attribute to all inline scripts: <script nonce=\"{random}\">"
                ),
                detection_method="Inspected HTTP response headers for missing or misconfigured security headers (X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, etc.) by comparing against OWASP recommended values.",
            ))
        if "unsafe-eval" in csp:
            session.add_finding(Finding(
                title="CSP Allows unsafe-eval",
                severity=Severity.MEDIUM,
                description="Content-Security-Policy contains 'unsafe-eval' which allows JavaScript eval() and similar dynamic code execution.",
                evidence=f"CSP Header Value: {csp}",
                remediation="Remove 'unsafe-eval' from CSP. Refactor code to avoid eval().",
                url=session.config.target,
                module="headers",
                cwe="CWE-16",
                confirmed=True,
                location="Content-Security-Policy response header",
                curl_command=curl_cmd,
                developer_fix="Remove 'unsafe-eval' from your CSP directive. Refactor JavaScript to avoid eval(), new Function(), and setTimeout/setInterval with string arguments.",
                detection_method="Inspected HTTP response headers for missing or misconfigured security headers (X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, etc.) by comparing against OWASP recommended values.",
            ))

    for header_name, desc in DANGEROUS_HEADERS.items():
        value = headers.get(header_name, "")
        if value:
            session.add_finding(Finding(
                title=f"Information Disclosure: {desc}",
                severity=Severity.LOW,
                description=f"The '{header_name}' header reveals server information. Attackers use this to identify known vulnerabilities in specific software versions.",
                evidence=f"{header_name}: {value}\n\nFull response headers:\n{all_headers_str}",
                remediation=f"Remove or suppress the '{header_name}' header in production.",
                url=session.config.target,
                module="headers",
                cwe="CWE-200",
                confirmed=True,
                location=f"HTTP response header '{header_name}'",
                curl_command=curl_cmd,
                response_headers=f"{header_name}: {value}",
                developer_fix=(
                    f"Apache: Header unset {header_name}\n"
                    f"Nginx: proxy_hide_header {header_name};\n"
                    f"PHP: header_remove('{header_name}'); in php.ini set expose_php = Off\n"
                    f"Express.js: app.disable('x-powered-by') or use helmet()"
                ),
                affected_component="Web server / application configuration",
                detection_method="Inspected HTTP response headers for missing or misconfigured security headers (X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, etc.) by comparing against OWASP recommended values.",
            ))

    for cookie in resp.cookies:
        if not _is_session_cookie(cookie):
            continue

        cookie_detail = f"Cookie Name: {cookie.name}\nCookie Domain: {cookie.domain or 'not set'}\nCookie Path: {cookie.path or '/'}\nValue (truncated): {cookie.value[:20]}..."

        if session.config.target.startswith("https") and not cookie.secure:
            session.add_finding(Finding(
                title=f"Cookie Missing Secure Flag: {cookie.name}",
                severity=Severity.MEDIUM,
                description=f"Session cookie '{cookie.name}' is not marked Secure. It will be transmitted over unencrypted HTTP connections, exposing it to network sniffing.",
                evidence=cookie_detail,
                remediation="Add the Secure flag to all session cookies.",
                url=session.config.target,
                module="headers",
                cwe="CWE-614",
                confirmed=True,
                location=f"Set-Cookie response header for '{cookie.name}'",
                developer_fix=(
                    f"Add Secure flag when setting the '{cookie.name}' cookie:\n"
                    f"PHP: session.cookie_secure = 1\n"
                    f"Express: res.cookie('{cookie.name}', value, {{ secure: true }})\n"
                    f"Django: SESSION_COOKIE_SECURE = True"
                ),
                detection_method="Inspected HTTP response headers for missing or misconfigured security headers (X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, etc.) by comparing against OWASP recommended values.",
            ))

        if not cookie.has_nonstandard_attr("HttpOnly"):
            session.add_finding(Finding(
                title=f"Cookie Missing HttpOnly Flag: {cookie.name}",
                severity=Severity.MEDIUM,
                description=f"Session cookie '{cookie.name}' is not marked HttpOnly. JavaScript can access this cookie via document.cookie, making it vulnerable to XSS-based session theft.",
                evidence=cookie_detail,
                remediation="Add the HttpOnly flag to session cookies.",
                url=session.config.target,
                module="headers",
                cwe="CWE-1004",
                confirmed=True,
                location=f"Set-Cookie response header for '{cookie.name}'",
                developer_fix=(
                    f"Add HttpOnly flag when setting the '{cookie.name}' cookie:\n"
                    f"PHP: session.cookie_httponly = 1\n"
                    f"Express: res.cookie('{cookie.name}', value, {{ httpOnly: true }})\n"
                    f"Django: SESSION_COOKIE_HTTPONLY = True"
                ),
                detection_method="Inspected HTTP response headers for missing or misconfigured security headers (X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, etc.) by comparing against OWASP recommended values.",
            ))

        if not cookie.has_nonstandard_attr("SameSite"):
            session.add_finding(Finding(
                title=f"Cookie Missing SameSite Attribute: {cookie.name}",
                severity=Severity.LOW,
                description=f"Session cookie '{cookie.name}' lacks the SameSite attribute, making it susceptible to cross-site request forgery (CSRF) attacks.",
                evidence=cookie_detail,
                remediation="Add 'SameSite=Strict' or 'SameSite=Lax' to cookies.",
                url=session.config.target,
                module="headers",
                cwe="CWE-1275",
                confirmed=True,
                location=f"Set-Cookie response header for '{cookie.name}'",
                developer_fix=(
                    f"Add SameSite attribute when setting the '{cookie.name}' cookie:\n"
                    f"PHP: session.cookie_samesite = \"Strict\"\n"
                    f"Express: res.cookie('{cookie.name}', value, {{ sameSite: 'strict' }})\n"
                    f"Django: SESSION_COOKIE_SAMESITE = 'Strict'"
                ),
                detection_method="Inspected HTTP response headers for missing or misconfigured security headers (X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, etc.) by comparing against OWASP recommended values.",
            ))
