import re
from urllib.parse import urljoin

from scanner.core import Finding, Severity, ScanSession


def run(session: ScanSession) -> None:
    print("\n[*] Checking for security misconfigurations...")

    _check_cors(session)
    _check_methods(session)
    _check_clickjacking(session)
    _check_open_redirect(session)
    _check_host_header_injection(session)
    _check_crlf_injection(session)


def _check_cors(session: ScanSession):
    evil_origin = "https://evil-vulnscan-test.com"
    resp = session.get(
        session.config.target,
        headers={"Origin": evil_origin}
    )
    if not resp:
        return

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*":
        if acac.lower() == "true":
            session.add_finding(Finding(
                title="CORS: Wildcard Origin with Credentials",
                severity=Severity.HIGH,
                description="CORS allows any origin with credentials, enabling cross-origin data theft.",
                evidence=f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                remediation="Never combine wildcard origin with credentials. Whitelist specific origins.",
                url=session.config.target,
                module="misconfig",
                cwe="CWE-942",
                confirmed=True,
            ))
        else:
            session.add_finding(Finding(
                title="CORS: Wildcard Origin",
                severity=Severity.LOW,
                description="CORS allows any origin. Safe only if no sensitive data is served.",
                evidence=f"Access-Control-Allow-Origin: *",
                remediation="Restrict to specific trusted origins if serving sensitive data.",
                url=session.config.target,
                module="misconfig",
                cwe="CWE-942",
                confirmed=True,
            ))

    elif acao == evil_origin:
        severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
        session.add_finding(Finding(
            title="CORS: Origin Reflection",
            severity=severity,
            description="The server reflects arbitrary Origin headers in CORS responses.",
            evidence=f"Sent Origin: {evil_origin}\nReflected: {acao}\nCredentials: {acac}",
            remediation="Validate Origin against a whitelist. Don't reflect arbitrary origins.",
            url=session.config.target,
            module="misconfig",
            cwe="CWE-942",
            confirmed=True,
        ))


def _check_methods(session: ScanSession):
    resp = session.session.options(session.config.target, timeout=session.config.timeout, verify=False)
    allow = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
    if not allow:
        return

    dangerous = {"PUT", "DELETE", "TRACE", "CONNECT"}
    allowed = {m.strip().upper() for m in allow.split(",")}
    found = dangerous & allowed

    if "TRACE" in found:
        trace_resp = session.session.request("TRACE", session.config.target,
                                              timeout=session.config.timeout, verify=False)
        if trace_resp.status_code == 200 and "TRACE" in trace_resp.text.upper():
            session.add_finding(Finding(
                title="HTTP TRACE Method Enabled",
                severity=Severity.MEDIUM,
                description="TRACE method is enabled, potentially allowing Cross-Site Tracing (XST) attacks.",
                evidence=f"TRACE response status: {trace_resp.status_code}",
                remediation="Disable the TRACE HTTP method on the web server.",
                url=session.config.target,
                module="misconfig",
                cwe="CWE-16",
                confirmed=True,
            ))

    dangerous_found = found - {"TRACE"}
    if dangerous_found:
        session.add_finding(Finding(
            title=f"Dangerous HTTP Methods Enabled: {', '.join(dangerous_found)}",
            severity=Severity.LOW,
            description=f"Server allows potentially dangerous HTTP methods.",
            evidence=f"Allow header: {allow}",
            remediation="Disable unnecessary HTTP methods (PUT, DELETE) unless required by the API.",
            url=session.config.target,
            module="misconfig",
            cwe="CWE-16",
            confirmed=True,
        ))


def _check_clickjacking(session: ScanSession):
    resp = session.get(session.config.target)
    if not resp:
        return

    xfo = resp.headers.get("X-Frame-Options", "").lower()
    csp = resp.headers.get("Content-Security-Policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if not xfo and not has_frame_ancestors:
        if "text/html" in resp.headers.get("Content-Type", ""):
            session.add_finding(Finding(
                title="Clickjacking: No Frame Protection",
                severity=Severity.MEDIUM,
                description="Page can be embedded in iframes, enabling clickjacking attacks.",
                evidence="No X-Frame-Options header and no CSP frame-ancestors directive.",
                remediation="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
                url=session.config.target,
                module="misconfig",
                cwe="CWE-1021",
                confirmed=True,
            ))


def _check_open_redirect(session: ScanSession):
    redirect_params = ["url", "redirect", "next", "return", "returnUrl", "redirect_uri",
                        "continue", "dest", "destination", "go", "target", "rurl", "return_to"]
    evil_target = "https://evil-vulnscan-test.com"

    for url in list(session.crawled_urls)[:5]:
        for param in redirect_params[:6]:
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={evil_target}"
            resp = session.get(test_url, allow_redirects=False)
            if not resp:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if location.startswith(evil_target) or location.startswith("//evil-vulnscan-test.com"):
                    session.add_finding(Finding(
                        title=f"Open Redirect via '{param}' Parameter",
                        severity=Severity.MEDIUM,
                        description=f"Parameter '{param}' allows redirects to external domains.",
                        evidence=f"URL: {test_url}\nRedirects to: {location}",
                        remediation="Validate redirect targets against a whitelist. Only allow relative paths.",
                        url=url,
                        module="misconfig",
                        cwe="CWE-601",
                        confirmed=True,
                    ))
                    return


def _check_host_header_injection(session: ScanSession):
    evil_host = "evil-vulnscan-test.com"

    normal_resp = session.get(session.config.target)
    if not normal_resp:
        return
    normal_text = normal_resp.text

    resp = session.get(session.config.target, headers={"Host": evil_host})
    if not resp:
        return

    if evil_host in resp.text:
        import re
        security_contexts = re.findall(
            r'(?:href|action|src)\s*=\s*["\']https?://' + re.escape(evil_host) + r'[^"\']*["\']',
            resp.text, re.IGNORECASE
        )
        if not security_contexts:
            return

        reset_patterns = ["reset", "password", "verify", "confirm", "activate", "token"]
        in_sensitive_context = any(p in resp.text.lower() for p in reset_patterns)

        if in_sensitive_context:
            session.add_finding(Finding(
                title="Host Header Injection in Sensitive Context",
                severity=Severity.MEDIUM,
                description="The application reflects the Host header in URLs on pages with password reset or verification functionality.",
                evidence=f"Injected Host: {evil_host}\nReflected in: {security_contexts[0][:100]}",
                remediation="Validate the Host header server-side. Use a whitelist of allowed hostnames.",
                url=session.config.target,
                module="misconfig",
                cwe="CWE-644",
                confirmed=True,
            ))


def _check_crlf_injection(session: ScanSession):
    payloads = [
        "%0d%0aX-Injected: vulnscan",
        "%0aX-Injected: vulnscan",
        "\r\nX-Injected: vulnscan",
    ]

    for payload in payloads:
        test_url = f"{session.config.target}/{payload}"
        resp = session.get(test_url, allow_redirects=False)
        if not resp:
            continue

        if "x-injected" in {k.lower() for k in resp.headers}:
            session.add_finding(Finding(
                title="CRLF Injection / HTTP Response Splitting",
                severity=Severity.HIGH,
                description="The server is vulnerable to CRLF injection, allowing HTTP response splitting.",
                evidence=f"Payload: {payload}\nInjected header 'X-Injected' appeared in response.",
                remediation="Sanitize CRLF characters from all user input used in HTTP headers.",
                url=session.config.target,
                module="misconfig",
                cwe="CWE-113",
                confirmed=True,
            ))
            return
