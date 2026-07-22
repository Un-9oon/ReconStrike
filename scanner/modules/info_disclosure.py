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

        for pattern, name, severity in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                sample = matches[0] if isinstance(matches[0], str) else str(matches[0])
                session.add_finding(Finding(
                    title=f"Information Disclosure: {name}",
                    severity=severity,
                    description=f"Found {name.lower()} in page content at {url}.",
                    evidence=f"Match: {sample[:60]}... ({len(matches)} occurrence(s))",
                    remediation="Remove sensitive data from client-facing responses. Use environment variables for secrets.",
                    url=url,
                    module="info_disclosure",
                    cwe="CWE-200",
                    confirmed=True,
                ))

        if re.search(STACK_TRACE_PATTERN, body, re.MULTILINE):
            session.add_finding(Finding(
                title="Stack Trace Exposed",
                severity=Severity.MEDIUM,
                description="A full stack trace is visible in the response.",
                evidence=f"URL: {url}\nMultiple consecutive 'at ...' lines found",
                remediation="Disable detailed error messages in production. Use custom error pages.",
                url=url,
                module="info_disclosure",
                cwe="CWE-209",
                confirmed=True,
            ))

        comments = extract_comments(body)
        for comment in comments:
            comment = comment.strip()
            if len(comment) < 10:
                continue
            for pattern, name, severity in COMMENT_PATTERNS:
                if re.search(pattern, comment, re.IGNORECASE):
                    session.add_finding(Finding(
                        title=f"Sensitive HTML Comment: {name}",
                        severity=severity,
                        description=f"An HTML comment contains potentially sensitive information.",
                        evidence=f"Comment: {comment[:200]}",
                        remediation="Remove sensitive comments from production HTML.",
                        url=url,
                        module="info_disclosure",
                        cwe="CWE-615",
                        confirmed=True,
                    ))
                    break

        for pattern, name, severity in ERROR_PAGE_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                session.add_finding(Finding(
                    title=f"Error Information Leakage: {name}",
                    severity=severity,
                    description=f"{name} found in response at {url}.",
                    evidence=f"Match: {match.group(0)[:200]}",
                    remediation="Disable detailed error messages in production.",
                    url=url,
                    module="info_disclosure",
                    cwe="CWE-209",
                    confirmed=True,
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
        for pattern, name, severity in ERROR_PAGE_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                session.add_finding(Finding(
                    title=f"Error Page Leaks Information ({trigger_type})",
                    severity=severity,
                    description=f"Triggering {trigger_type} reveals {name.lower()}.",
                    evidence=f"Trigger: {trigger_type}\nMatch: {match.group(0)[:200]}",
                    remediation="Use custom error pages that don't reveal internal details.",
                    url=url,
                    module="info_disclosure",
                    cwe="CWE-209",
                    confirmed=True,
                ))

        if re.search(STACK_TRACE_PATTERN, body, re.MULTILINE):
            session.add_finding(Finding(
                title=f"Error Page Exposes Stack Trace ({trigger_type})",
                severity=Severity.MEDIUM,
                description=f"Error page reveals a full stack trace.",
                evidence=f"Trigger: {trigger_type}",
                remediation="Use custom error pages.",
                url=url,
                module="info_disclosure",
                cwe="CWE-209",
                confirmed=True,
            ))
