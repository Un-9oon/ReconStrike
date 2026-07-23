from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession


CORS_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]


def run(session: ScanSession) -> None:
    print("\n[*] Testing for CORS misconfiguration...")
    target = session.config.target
    parsed = urlparse(target)

    for url in list(session.crawled_urls)[:20]:
        for origin in CORS_ORIGINS:
            resp = session.get(url, headers={"Origin": origin})
            if not resp:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if not acao:
                continue

            curl_cmd = f"curl -k -H 'Origin: {origin}' -I '{url}'"

            if acao == "*" and acac.lower() == "true":
                session.add_finding(Finding(
                    title="CORS: Wildcard with Credentials",
                    severity=Severity.HIGH,
                    description=(
                        "The server returns Access-Control-Allow-Origin: * with "
                        "Access-Control-Allow-Credentials: true. This is a browser-rejected "
                        "combination but indicates a fundamental CORS misconfiguration."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"Origin Sent: {origin}\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    remediation="Restrict ACAO to specific trusted origins. Never combine wildcard with credentials.",
                    url=url,
                    module="cors",
                    cwe="CWE-942",
                    confirmed=True,
                    location=f"CORS headers on {url}",
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Send a request to {url} with header: Origin: {origin}\n"
                        f"2. Observe the response headers.\n"
                        f"3. ACAO is '*' and ACAC is 'true'.\n"
                        f"4. Run: {curl_cmd}"
                    ),
                    developer_fix=(
                        "Never set Access-Control-Allow-Origin: * when credentials are needed.\n"
                        "Use a whitelist of trusted origins:\n"
                        "  allowed = ['https://app.example.com']\n"
                        "  origin = request.headers.get('Origin')\n"
                        "  if origin in allowed:\n"
                        "      response.headers['Access-Control-Allow-Origin'] = origin\n"
                        "      response.headers['Access-Control-Allow-Credentials'] = 'true'"
                    ),
                    affected_component="CORS configuration",
                    references="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                    detection_method="Sent requests with crafted Origin headers (evil.com, attacker.com, null) and inspected Access-Control-Allow-Origin and Access-Control-Allow-Credentials response headers. Misconfigurations like wildcard or origin reflection with credentials are flagged.",
                ))
                return

            if acao == origin and origin not in ("null",):
                if acac.lower() == "true":
                    session.add_finding(Finding(
                        title="CORS: Arbitrary Origin Reflected with Credentials",
                        severity=Severity.HIGH,
                        description=(
                            f"The server reflects the attacker-controlled Origin header '{origin}' "
                            f"in Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials: true. "
                            f"This allows any website to make credentialed cross-origin requests and "
                            f"read the response, enabling data theft from authenticated users."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"Origin Sent: {origin}\n"
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}"
                        ),
                        remediation="Validate the Origin header against a strict whitelist of trusted domains.",
                        url=url,
                        module="cors",
                        cwe="CWE-942",
                        confirmed=True,
                        location=f"CORS headers on {url}",
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Send a request to {url} with header: Origin: {origin}\n"
                            f"2. The server reflects {origin} in ACAO with credentials allowed.\n"
                            f"3. An attacker page at {origin} can read authenticated responses.\n"
                            f"4. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            "Validate Origin against a whitelist of trusted domains:\n"
                            "  ALLOWED_ORIGINS = {'https://app.example.com', 'https://admin.example.com'}\n"
                            "  origin = request.headers.get('Origin', '')\n"
                            "  if origin in ALLOWED_ORIGINS:\n"
                            "      response.headers['Access-Control-Allow-Origin'] = origin\n"
                            "      response.headers['Access-Control-Allow-Credentials'] = 'true'\n"
                            "Do NOT reflect the Origin header without validation."
                        ),
                        affected_component="CORS configuration / middleware",
                        references="https://portswigger.net/web-security/cors",
                        detection_method="Sent requests with crafted Origin headers (evil.com, attacker.com, null) and inspected Access-Control-Allow-Origin and Access-Control-Allow-Credentials response headers. Misconfigurations like wildcard or origin reflection with credentials are flagged.",
                    ))
                    return
                else:
                    session.add_finding(Finding(
                        title="CORS: Arbitrary Origin Reflected",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The server reflects the attacker-controlled Origin header '{origin}' "
                            f"but does not set Allow-Credentials. This limits the impact but "
                            f"indicates the CORS policy is misconfigured."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"Origin Sent: {origin}\n"
                            f"Access-Control-Allow-Origin: {acao}"
                        ),
                        remediation="Validate the Origin header against a whitelist.",
                        url=url,
                        module="cors",
                        cwe="CWE-942",
                        confirmed=True,
                        location=f"CORS headers on {url}",
                        curl_command=curl_cmd,
                        developer_fix="Validate Origin against a strict whitelist of trusted domains before reflecting it.",
                        affected_component="CORS configuration",
                        detection_method="Sent requests with crafted Origin headers (evil.com, attacker.com, null) and inspected Access-Control-Allow-Origin and Access-Control-Allow-Credentials response headers. Misconfigurations like wildcard or origin reflection with credentials are flagged.",
                    ))
                    return

            if acao == "null" and origin == "null":
                session.add_finding(Finding(
                    title="CORS: Null Origin Allowed",
                    severity=Severity.MEDIUM,
                    description=(
                        "The server trusts the 'null' origin. An attacker can trigger a null origin "
                        "using sandboxed iframes or data: URIs to bypass CORS restrictions."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"Origin Sent: null\n"
                        f"Access-Control-Allow-Origin: null"
                    ),
                    remediation="Never whitelist 'null' as a trusted origin.",
                    url=url,
                    module="cors",
                    cwe="CWE-942",
                    confirmed=True,
                    location=f"CORS headers on {url}",
                    curl_command=curl_cmd,
                    reproduction_steps=(
                        f"1. Send a request with Origin: null\n"
                        f"2. Server responds with Access-Control-Allow-Origin: null\n"
                        f"3. Attacker uses <iframe sandbox> to trigger null origin.\n"
                        f"4. Run: {curl_cmd}"
                    ),
                    developer_fix="Remove 'null' from your CORS origin whitelist. Never trust the null origin.",
                    affected_component="CORS configuration",
                    references="https://portswigger.net/web-security/cors",
                    detection_method="Sent requests with crafted Origin headers (evil.com, attacker.com, null) and inspected Access-Control-Allow-Origin and Access-Control-Allow-Credentials response headers. Misconfigurations like wildcard or origin reflection with credentials are flagged.",
                ))
                return
