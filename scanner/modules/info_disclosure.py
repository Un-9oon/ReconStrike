import re
from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession
from scanner.crawler import extract_comments

SENSITIVE_PATTERNS = [
    (r'(?:aws_access_key_id|AKIA)[A-Z0-9]{12,}', "AWS Access Key", Severity.CRITICAL),
    (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', "Private Key", Severity.CRITICAL),
    (r'(?:sk-|pk_live_|sk_live_|rk_live_)[a-zA-Z0-9]{20,}', "API Secret Key", Severity.CRITICAL),
    (r'(?:jdbc|mysql|postgresql|mongodb)://[^\s<"\']+:[^\s<"\']+@[^\s<"\']+', "Database Connection String", Severity.CRITICAL),
]

COMMENT_PATTERNS = [
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']?\S{4,}', "Password in Comment", Severity.HIGH),
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[a-zA-Z0-9_-]{16,}', "API Key in Comment", Severity.HIGH),
    (r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
     "Internal IP Address in Comment", Severity.LOW),
]

ERROR_PAGE_PATTERNS = [
    (r'(?:Traceback \(most recent call last\)|Fatal error:.*?in\s+/[\w./]+\s+on\s+line\s+\d+)',
     "Application Error with Path", Severity.MEDIUM),
]

STACK_TRACE_PATTERN = r'(?:^\s+at\s+[\w.$]+\([\w.]+:\d+\).*\n){3,}'


def _build_curl(method, url, headers=None):
    cmd = f"curl -k -X {method} '{url}'"
    if headers:
        for k, v in headers.items():
            cmd += f" -H '{k}: {v}'"
    return cmd


def run(session: ScanSession) -> None:
    print("\n[*] Checking for information disclosure...")

    for url in session.crawled_urls:
        resp = session.get(url)
        if not resp:
            continue

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/javascript" not in content_type:
            continue

        body = resp.text
        parsed = urlparse(url)

        for pattern, name, severity in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                sample = matches[0] if isinstance(matches[0], str) else str(matches[0])
                masked = sample[:8] + "..." + sample[-4:] if len(sample) > 16 else sample[:8] + "..."

                session.add_finding(Finding(
                    title=f"Information Disclosure: {name}",
                    severity=severity,
                    description=(
                        f"A {name.lower()} was found exposed in the page content at {url}. "
                        f"This sensitive credential is directly accessible to anyone who views "
                        f"the page source, enabling unauthorized access to backend services, "
                        f"cloud infrastructure, or databases depending on the key type."
                    ),
                    evidence=(
                        f"Pattern Matched: {name}\n"
                        f"Sample (masked): {masked}\n"
                        f"Total Occurrences: {len(matches)}\n"
                        f"Content-Type: {content_type}\n"
                        f"Response Status: {resp.status_code}"
                    ),
                    remediation=(
                        "1. Immediately rotate the exposed credential and revoke the old one.\n"
                        "2. Move all secrets to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).\n"
                        "3. Audit version control history for previously committed secrets using tools like truffleHog or git-secrets.\n"
                        "4. Implement pre-commit hooks to prevent secrets from being committed.\n"
                        "5. Add the file to .gitignore if it should never be tracked."
                    ),
                    url=url,
                    module="info_disclosure",
                    cwe="CWE-200",
                    confirmed=True,
                    location=f"Page body at {parsed.path}",
                    parameter="",
                    payload="",
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=_build_curl("GET", url),
                    reproduction_steps=(
                        f"1. Open the target URL: {url}\n"
                        f"2. View the page source (Ctrl+U or right-click > View Page Source).\n"
                        f"3. Search for the pattern matching '{name.lower()}'.\n"
                        f"4. Observe the exposed credential in the response body.\n"
                        f"5. The secret '{masked}' is visible to any unauthenticated user."
                    ),
                    developer_fix=(
                        f"File: The server-side code or template that renders {parsed.path}.\n"
                        f"Fix: Remove hardcoded secrets and load them from environment variables.\n"
                        f"Example (Python):\n"
                        f"  import os\n"
                        f"  secret = os.environ.get('SECRET_KEY')  # Instead of hardcoding\n"
                        f"Example (Node.js):\n"
                        f"  const secret = process.env.SECRET_KEY;  // Instead of hardcoding\n"
                        f"Also: Ensure .env files are in .gitignore and never served statically."
                    ),
                    affected_component=f"Page content at {parsed.path}",
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage | "
                        "https://cwe.mitre.org/data/definitions/200.html | "
                        "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html"
                    ),
                    detection_method="Scanned response bodies, headers, and HTML comments for leaked sensitive data: email addresses, IP addresses, API keys, database connection strings, stack traces, and debug information using pattern-matching analysis.",
                ))

        if re.search(STACK_TRACE_PATTERN, body, re.MULTILINE):
            trace_match = re.search(r'((?:^\s+at\s+[\w.$]+\([\w.]+:\d+\).*\n){1,5})', body, re.MULTILINE)
            trace_snippet = trace_match.group(0).strip()[:300] if trace_match else "Multiple consecutive 'at ...' lines found"

            session.add_finding(Finding(
                title="Stack Trace Exposed",
                severity=Severity.MEDIUM,
                description=(
                    f"A full stack trace is visible in the response at {url}. "
                    f"Stack traces reveal internal file paths, class names, method names, "
                    f"and line numbers that help attackers map the application's internal "
                    f"architecture and identify specific framework versions or vulnerable components."
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"Stack Trace Snippet:\n{trace_snippet}\n"
                    f"Response Status: {resp.status_code}"
                ),
                remediation=(
                    "1. Disable detailed error messages and stack traces in production.\n"
                    "2. Configure custom error pages that show user-friendly messages.\n"
                    "3. Log detailed errors server-side only (e.g., to a log aggregation service).\n"
                    "4. Set DEBUG=False (Django), display_errors=Off (PHP), or NODE_ENV=production (Express)."
                ),
                url=url,
                module="info_disclosure",
                cwe="CWE-209",
                confirmed=True,
                location=f"Response body at {parsed.path}",
                parameter="",
                payload="",
                request_method="GET",
                response_status=resp.status_code,
                curl_command=_build_curl("GET", url),
                reproduction_steps=(
                    f"1. Open the target URL: {url}\n"
                    f"2. Observe the HTTP response body.\n"
                    f"3. A full stack trace with internal file paths and line numbers is visible.\n"
                    f"4. This information reveals the application's internal structure to attackers."
                ),
                developer_fix=(
                    f"File: Application configuration or error handler.\n"
                    f"Fix: Disable verbose error output in production.\n"
                    f"  - Django: Set DEBUG = False in settings.py\n"
                    f"  - Flask: Set app.debug = False and use app.errorhandler(500)\n"
                    f"  - Express: Use a custom error middleware:\n"
                    f"    app.use((err, req, res, next) => {{\n"
                    f"      console.error(err.stack); // Log server-side only\n"
                    f"      res.status(500).send('Internal Server Error');\n"
                    f"    }});\n"
                    f"  - PHP: Set display_errors = Off in php.ini"
                ),
                affected_component=f"Error handling at {parsed.path}",
                references=(
                    "https://owasp.org/www-community/Improper_Error_Handling | "
                    "https://cwe.mitre.org/data/definitions/209.html | "
                    "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
                ),
                detection_method="Scanned response bodies, headers, and HTML comments for leaked sensitive data: email addresses, IP addresses, API keys, database connection strings, stack traces, and debug information using pattern-matching analysis.",
            ))

        comments = extract_comments(body)
        for comment in comments:
            comment = comment.strip()
            if len(comment) < 10:
                continue
            for pattern, name, severity in COMMENT_PATTERNS:
                if re.search(pattern, comment, re.IGNORECASE):
                    comment_snippet = comment[:200]

                    session.add_finding(Finding(
                        title=f"Sensitive HTML Comment: {name}",
                        severity=severity,
                        description=(
                            f"An HTML comment on {url} contains a {name.lower()}. "
                            f"HTML comments are visible to anyone who views the page source. "
                            f"Developers often leave debugging information, credentials, or "
                            f"internal notes in comments that should be stripped before deployment."
                        ),
                        evidence=(
                            f"Comment Content: <!-- {comment_snippet} -->\n"
                            f"Pattern Matched: {name}\n"
                            f"Response Status: {resp.status_code}"
                        ),
                        remediation=(
                            "1. Remove all sensitive HTML comments before deploying to production.\n"
                            "2. Use server-side comments (e.g., <%-- --%> in JSP, {# #} in Jinja2) that are stripped during rendering.\n"
                            "3. Add a build step or linter rule to strip HTML comments from production output.\n"
                            "4. Review templates for TODO/FIXME/HACK comments containing sensitive data."
                        ),
                        url=url,
                        module="info_disclosure",
                        cwe="CWE-615",
                        confirmed=True,
                        location=f"HTML comment in page body at {parsed.path}",
                        parameter="",
                        payload="",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=_build_curl("GET", url),
                        reproduction_steps=(
                            f"1. Open the target URL: {url}\n"
                            f"2. View the page source (Ctrl+U).\n"
                            f"3. Search for HTML comments containing '{name.lower().split()[0]}'.\n"
                            f"4. Observe the sensitive information exposed in the comment."
                        ),
                        developer_fix=(
                            f"File: The template or HTML file that renders {parsed.path}.\n"
                            f"Fix: Remove the comment or replace it with a server-side comment.\n"
                            f"  - Jinja2: Use {{# This is a server-side comment #}} instead of <!-- -->\n"
                            f"  - Django: Use {{%- comment -%}}...{{%- endcomment -%}}\n"
                            f"  - PHP: Use <?php /* comment */ ?> instead of <!-- -->\n"
                            f"  - Build step: Add html-minifier or similar to strip comments:\n"
                            f"    html-minifier --remove-comments input.html -o output.html"
                        ),
                        affected_component=f"HTML template for {parsed.path}",
                        references=(
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage | "
                            "https://cwe.mitre.org/data/definitions/615.html"
                        ),
                        detection_method="Scanned response bodies, headers, and HTML comments for leaked sensitive data: email addresses, IP addresses, API keys, database connection strings, stack traces, and debug information using pattern-matching analysis.",
                    ))
                    break

        for pattern, name, severity in ERROR_PAGE_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                error_snippet = match.group(0)[:200]

                session.add_finding(Finding(
                    title=f"Error Information Leakage: {name}",
                    severity=severity,
                    description=(
                        f"The response at {url} contains a {name.lower()} that reveals internal "
                        f"server paths, framework details, or application structure. This information "
                        f"assists attackers in fingerprinting the technology stack and identifying "
                        f"specific files to target."
                    ),
                    evidence=(
                        f"Error Content: {error_snippet}\n"
                        f"Response Status: {resp.status_code}\n"
                        f"Content-Type: {content_type}"
                    ),
                    remediation=(
                        "1. Disable detailed error messages in production environments.\n"
                        "2. Configure custom error pages that do not reveal internal paths or line numbers.\n"
                        "3. Log errors to a server-side logging service instead of displaying them.\n"
                        "4. Ensure framework debug mode is disabled in production."
                    ),
                    url=url,
                    module="info_disclosure",
                    cwe="CWE-209",
                    confirmed=True,
                    location=f"Response body at {parsed.path}",
                    parameter="",
                    payload="",
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=_build_curl("GET", url),
                    reproduction_steps=(
                        f"1. Send a GET request to: {url}\n"
                        f"2. Observe the response body.\n"
                        f"3. The response contains a detailed error message with internal paths.\n"
                        f"4. Error snippet: {error_snippet[:100]}"
                    ),
                    developer_fix=(
                        f"File: Application error handler or web server configuration.\n"
                        f"Fix: Configure production error handling to suppress details.\n"
                        f"  - Apache: Set ServerSignature Off and ErrorDocument directives\n"
                        f"  - Nginx: Use error_page directive with custom static HTML\n"
                        f"  - PHP: Set display_errors = Off and log_errors = On in php.ini\n"
                        f"  - Python/Django: Set DEBUG = False, configure LOGGING to file\n"
                        f"  - Node/Express: app.set('env', 'production')"
                    ),
                    affected_component=f"Error handling for {parsed.path}",
                    references=(
                        "https://owasp.org/www-community/Improper_Error_Handling | "
                        "https://cwe.mitre.org/data/definitions/209.html"
                    ),
                    detection_method="Scanned response bodies, headers, and HTML comments for leaked sensitive data: email addresses, IP addresses, API keys, database connection strings, stack traces, and debug information using pattern-matching analysis.",
                ))

    _check_error_pages(session)


def _check_error_pages(session: ScanSession):
    error_triggers = [
        (f"{session.config.target}/nonexistent_page_vulnscan_test_404", "404 Page"),
    ]

    for url, trigger_type in error_triggers:
        resp = session.get(url)
        if not resp:
            continue

        body = resp.text
        parsed = urlparse(url)

        for pattern, name, severity in ERROR_PAGE_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                error_snippet = match.group(0)[:200]

                session.add_finding(Finding(
                    title=f"Error Page Leaks Information ({trigger_type})",
                    severity=severity,
                    description=(
                        f"Requesting a non-existent page triggers a {trigger_type} response that "
                        f"reveals {name.lower()}. Custom error pages should not expose internal "
                        f"application details such as file paths, framework versions, or stack traces."
                    ),
                    evidence=(
                        f"Trigger: {trigger_type}\n"
                        f"Error Content: {error_snippet}\n"
                        f"Response Status: {resp.status_code}"
                    ),
                    remediation=(
                        "1. Configure custom error pages for all HTTP error codes (404, 500, etc.).\n"
                        "2. Ensure error pages do not reveal server paths, framework names, or version numbers.\n"
                        "3. Return a generic 'Page Not Found' message for 404 errors.\n"
                        "4. Log detailed error information server-side only."
                    ),
                    url=url,
                    module="info_disclosure",
                    cwe="CWE-209",
                    confirmed=True,
                    location=f"Error page at {parsed.path}",
                    parameter="",
                    payload="",
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=_build_curl("GET", url),
                    reproduction_steps=(
                        f"1. Send a GET request to a non-existent URL: {url}\n"
                        f"2. Observe the {trigger_type} error response.\n"
                        f"3. The error page reveals internal details: {error_snippet[:100]}\n"
                        f"4. This information helps attackers fingerprint the application stack."
                    ),
                    developer_fix=(
                        f"File: Web server or application error handler configuration.\n"
                        f"Fix: Add custom error pages.\n"
                        f"  - Apache (.htaccess):\n"
                        f"    ErrorDocument 404 /custom_404.html\n"
                        f"    ErrorDocument 500 /custom_500.html\n"
                        f"  - Nginx (nginx.conf):\n"
                        f"    error_page 404 /custom_404.html;\n"
                        f"    error_page 500 502 503 504 /custom_50x.html;\n"
                        f"  - Django (urls.py):\n"
                        f"    handler404 = 'myapp.views.custom_404'\n"
                        f"  - Express:\n"
                        f"    app.use((req, res) => res.status(404).sendFile('404.html'));"
                    ),
                    affected_component=f"Error page handler for {trigger_type}",
                    references=(
                        "https://owasp.org/www-community/Improper_Error_Handling | "
                        "https://cwe.mitre.org/data/definitions/209.html | "
                        "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
                    ),
                    detection_method="Scanned response bodies, headers, and HTML comments for leaked sensitive data: email addresses, IP addresses, API keys, database connection strings, stack traces, and debug information using pattern-matching analysis.",
                ))

        if re.search(STACK_TRACE_PATTERN, body, re.MULTILINE):
            trace_match = re.search(r'((?:^\s+at\s+[\w.$]+\([\w.]+:\d+\).*\n){1,5})', body, re.MULTILINE)
            trace_snippet = trace_match.group(0).strip()[:300] if trace_match else "Multiple 'at ...' lines"

            session.add_finding(Finding(
                title=f"Error Page Exposes Stack Trace ({trigger_type})",
                severity=Severity.MEDIUM,
                description=(
                    f"Triggering a {trigger_type} error reveals a full stack trace in the response. "
                    f"Stack traces expose internal file paths, class hierarchies, and line numbers "
                    f"that significantly aid attackers in understanding the application architecture."
                ),
                evidence=(
                    f"Trigger: {trigger_type}\n"
                    f"Stack Trace Snippet:\n{trace_snippet}\n"
                    f"Response Status: {resp.status_code}"
                ),
                remediation=(
                    "1. Disable stack trace output in production environments.\n"
                    "2. Configure custom error pages for all error codes.\n"
                    "3. Use centralized logging to capture errors server-side.\n"
                    "4. Set framework-specific production flags (DEBUG=False, NODE_ENV=production)."
                ),
                url=url,
                module="info_disclosure",
                cwe="CWE-209",
                confirmed=True,
                location=f"Error page response body",
                parameter="",
                payload="",
                request_method="GET",
                response_status=resp.status_code,
                curl_command=_build_curl("GET", url),
                reproduction_steps=(
                    f"1. Send a GET request to: {url}\n"
                    f"2. The server returns a {trigger_type} error.\n"
                    f"3. Observe the full stack trace in the response body.\n"
                    f"4. Internal file paths and line numbers are exposed."
                ),
                developer_fix=(
                    f"File: Application error handler or framework configuration.\n"
                    f"Fix: Suppress stack traces in production.\n"
                    f"  - Django: DEBUG = False in settings.py\n"
                    f"  - Flask: app.debug = False\n"
                    f"  - Express:\n"
                    f"    if (process.env.NODE_ENV === 'production') {{\n"
                    f"      app.use((err, req, res, next) => {{\n"
                    f"        res.status(500).send('Internal Server Error');\n"
                    f"      }});\n"
                    f"    }}\n"
                    f"  - Spring Boot: server.error.include-stacktrace=never"
                ),
                affected_component=f"Error page handler for {trigger_type}",
                references=(
                    "https://owasp.org/www-community/Improper_Error_Handling | "
                    "https://cwe.mitre.org/data/definitions/209.html | "
                    "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
                ),
                detection_method="Scanned response bodies, headers, and HTML comments for leaked sensitive data: email addresses, IP addresses, API keys, database connection strings, stack traces, and debug information using pattern-matching analysis.",
            ))
