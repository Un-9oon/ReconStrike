import re
import hashlib

from scanner.core import Finding, Severity, ScanSession

TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {
            r"PHP/(\S+)": "PHP {}",
            r"ASP\.NET": "ASP.NET",
            r"Express": "Express.js",
            r"Servlet": "Java Servlet",
        },
        "Server": {
            r"Apache/(\S+)": "Apache {}",
            r"nginx/(\S+)": "Nginx {}",
            r"Microsoft-IIS/(\S+)": "IIS {}",
            r"Caddy": "Caddy",
            r"LiteSpeed": "LiteSpeed",
            r"gunicorn": "Gunicorn (Python)",
            r"Werkzeug/(\S+)": "Werkzeug {} (Flask)",
            r"uvicorn": "Uvicorn (Python ASGI)",
            r"Kestrel": "ASP.NET Kestrel",
            r"Cowboy": "Cowboy (Erlang/Elixir)",
        },
        "X-Generator": {
            r"(.+)": "Generator: {}",
        },
    },
    "body": [
        (r'<meta[^>]*generator[^>]*content=["\']([^"\']+)', "CMS/Framework: {}"),
        (r'wp-content/|wp-includes/', "WordPress"),
        (r'Joomla!|/media/jui/', "Joomla"),
        (r'/sites/default/files|drupal\.js', "Drupal"),
        (r'cdn\.shopify\.com', "Shopify"),
        (r'Mage\.Cookies|/skin/frontend/|/mage/', "Magento"),
        (r'laravel_session', "Laravel"),
        (r'csrfmiddlewaretoken', "Django"),
        (r'data-turbolinks|action_controller', "Ruby on Rails"),
        (r'/_next/static|__NEXT_DATA__', "Next.js"),
        (r'__NUXT__|/_nuxt/', "Nuxt.js"),
        (r'data-reactroot|__REACT_DEVTOOLS|_reactRoot', "React"),
        (r'ng-app=|ng-controller=|\[ngIf\]', "Angular"),
        (r'v-bind:|v-model=|__VUE__', "Vue.js"),
        (r'__svelte', "Svelte"),
        (r'Werkzeug/', "Flask"),
        (r'connect\.sid', "Express.js"),
        (r'JSESSIONID', "Spring (Java)"),
        (r'phpMyAdmin', "phpMyAdmin"),
    ],
    "cookies": {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java",
        "ASP.NET_SessionId": "ASP.NET",
        "connect.sid": "Express.js",
        "laravel_session": "Laravel",
        "csrftoken": "Django",
        "_rails": "Ruby on Rails",
        "ci_session": "CodeIgniter",
        "CAKEPHP": "CakePHP",
    },
}

WAF_SIGNATURES = [
    {"name": "Cloudflare", "headers": {"Server": "cloudflare", "CF-RAY": ""}, "cookies": ["__cfduid", "__cf_bm", "cf_clearance"]},
    {"name": "AWS WAF", "headers": {"X-AMZ-": "", "X-Amzn-": ""}, "cookies": ["awselb", "AWSALB"]},
    {"name": "Akamai", "headers": {"X-Akamai-": ""}, "cookies": ["AKA_A2", "akamai"]},
    {"name": "Sucuri", "headers": {"X-Sucuri-": ""}, "cookies": ["sucuri_"]},
    {"name": "ModSecurity", "headers": {"Server": "mod_security"}, "cookies": []},
    {"name": "Imperva/Incapsula", "headers": {"X-CDN": "Imperva"}, "cookies": ["visid_incap_", "incap_ses_"]},
    {"name": "F5 BIG-IP", "headers": {}, "cookies": ["BIGipServer", "TS0"]},
    {"name": "Barracuda", "headers": {"barra_counter_session": ""}, "cookies": ["barra_counter_session"]},
    {"name": "Fastly", "headers": {"X-Served-By": "", "X-Cache": "", "Via": ".*varnish"}, "cookies": []},
]


def run(session: ScanSession) -> None:
    print("\n[*] Fingerprinting technologies and detecting WAF...")

    resp = session.get(session.config.target)
    if not resp:
        return

    detected_tech = set()

    for header_name, patterns in TECH_SIGNATURES["headers"].items():
        header_val = resp.headers.get(header_name, "")
        if not header_val:
            continue
        for pattern, label in patterns.items():
            match = re.search(pattern, header_val, re.IGNORECASE)
            if match:
                groups = match.groups()
                tech = label.format(groups[0]) if groups else label
                detected_tech.add(tech)

    body = resp.text
    for pattern, label in TECH_SIGNATURES["body"]:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            groups = match.groups()
            tech = label.format(groups[0]) if groups else label
            detected_tech.add(tech)

    for cookie_name, tech in TECH_SIGNATURES["cookies"].items():
        for cookie in resp.cookies:
            if cookie_name.lower() in cookie.name.lower():
                detected_tech.add(tech)

    if detected_tech:
        tech_list = sorted(detected_tech)
        print(f"  [+] Detected technologies: {', '.join(tech_list)}")

        version_exposed = [t for t in tech_list if re.search(r'\d+\.\d+', t)]
        if version_exposed:
            session.add_finding(Finding(
                title="Technology Stack Fingerprinted (Versions Exposed)",
                severity=Severity.LOW,
                description=f"Server reveals technology versions: {', '.join(version_exposed)}. "
                            "Version information helps attackers find known vulnerabilities.",
                evidence=f"Technologies detected: {', '.join(tech_list)}",
                remediation="Suppress version numbers in Server, X-Powered-By headers. "
                            "Remove generator meta tags.",
                url=session.config.target,
                module="fingerprint",
                cwe="CWE-200",
                confirmed=True,
            ))
        else:
            session.add_finding(Finding(
                title="Technology Stack Identified",
                severity=Severity.INFO,
                description=f"Technologies detected: {', '.join(tech_list)}.",
                evidence=f"Technologies: {', '.join(tech_list)}",
                remediation="Consider removing unnecessary technology indicators.",
                url=session.config.target,
                module="fingerprint",
                cwe="CWE-200",
                confirmed=True,
            ))

    detected_waf = []
    for waf in WAF_SIGNATURES:
        found = False
        for header_name, header_pattern in waf["headers"].items():
            for resp_header, resp_value in resp.headers.items():
                if header_name.lower() in resp_header.lower():
                    if not header_pattern or re.search(header_pattern, resp_value, re.IGNORECASE):
                        found = True
                        break
            if found:
                break

        if not found:
            for cookie_pattern in waf["cookies"]:
                for cookie in resp.cookies:
                    if cookie_pattern.lower() in cookie.name.lower():
                        found = True
                        break
                if found:
                    break

        if found:
            detected_waf.append(waf["name"])

    if detected_waf:
        waf_list = ", ".join(detected_waf)
        print(f"  [+] WAF/CDN detected: {waf_list}")
        session.add_finding(Finding(
            title=f"WAF/CDN Detected: {waf_list}",
            severity=Severity.INFO,
            description=f"Web Application Firewall or CDN detected: {waf_list}. "
                        "Some scan results may be affected by WAF filtering.",
            evidence=f"Detected via header/cookie analysis: {waf_list}",
            remediation="This is informational. WAF provides defense-in-depth but should not be the only protection.",
            url=session.config.target,
            module="fingerprint",
            cwe="CWE-200",
            confirmed=True,
        ))
    else:
        print("  [*] No WAF/CDN detected.")

    _check_version_vulns(session, detected_tech)


def _check_version_vulns(session: ScanSession, tech_set: set):
    known_eol = {
        "PHP 5": "PHP 5.x is End-of-Life and no longer receives security patches.",
        "PHP 7.0": "PHP 7.0 is End-of-Life.",
        "PHP 7.1": "PHP 7.1 is End-of-Life.",
        "PHP 7.2": "PHP 7.2 is End-of-Life.",
        "PHP 7.3": "PHP 7.3 is End-of-Life.",
        "PHP 7.4": "PHP 7.4 is End-of-Life.",
        "PHP 8.0": "PHP 8.0 is End-of-Life.",
        "Apache 2.2": "Apache 2.2 is End-of-Life.",
    }

    for tech in tech_set:
        for pattern, message in known_eol.items():
            if tech.startswith(pattern):
                session.add_finding(Finding(
                    title=f"End-of-Life Software: {tech}",
                    severity=Severity.HIGH,
                    description=f"{message} Running EOL software means no security patches for new vulnerabilities.",
                    evidence=f"Detected: {tech}",
                    remediation=f"Upgrade to a supported version.",
                    url=session.config.target,
                    module="fingerprint",
                    cwe="CWE-1104",
                    confirmed=True,
                ))
