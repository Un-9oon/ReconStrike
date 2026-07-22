import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession

ID_PARAMS = [
    "id", "uid", "user_id", "userid", "account", "account_id",
    "profile", "profile_id", "doc_id", "order_id", "invoice_id",
    "file_id", "record_id", "pid", "project_id",
]

EXCLUDE_PARAMS = {
    "page", "offset", "limit", "sort", "order", "per_page", "pagesize",
    "start", "count", "skip", "cursor", "tab", "step", "index",
    "category", "cat", "type", "lang", "year", "month", "day",
}

ID_PATH_PATTERNS = [
    r"/users?/(\d+)",
    r"/profiles?/(\d+)",
    r"/accounts?/(\d+)",
    r"/orders?/(\d+)",
    r"/invoices?/(\d+)",
]

PII_PATTERNS = [
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    r'\b\d{3}-\d{2}-\d{4}\b',
    r'(?:balance|salary|income|credit|debit)\s*[:=]\s*[\d$]',
]


def _contains_pii(text: str) -> bool:
    for pattern in PII_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def _responses_differ_meaningfully(resp1_text: str, resp2_text: str) -> bool:
    if resp1_text == resp2_text:
        return False
    len_ratio = len(resp2_text) / max(len(resp1_text), 1)
    if len_ratio < 0.5 or len_ratio > 2.0:
        return True
    common = set(resp1_text.split()) & set(resp2_text.split())
    total = set(resp1_text.split()) | set(resp2_text.split())
    if not total:
        return False
    return len(common) / len(total) < 0.80


def _check_param_idor(session: ScanSession, url: str, param: str, original: str):
    if not original.isdigit():
        return

    original_int = int(original)
    resp_original = session.get(url)
    if not resp_original or resp_original.status_code != 200:
        return

    test_id = str(original_int + 1) if original_int > 0 else "1"
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [test_id]
    test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(test_url)
    if not resp or resp.status_code != 200:
        return

    if not _responses_differ_meaningfully(resp_original.text, resp.text):
        return

    if _contains_pii(resp.text) and not _contains_pii(resp_original.text):
        session.add_finding(Finding(
            title=f"Insecure Direct Object Reference (IDOR)",
            severity=Severity.HIGH,
            description=f"Parameter '{param}' allows access to other users' data by changing the ID. "
                        f"Response for ID {test_id} contains PII not present in original response.",
            evidence=f"Original ID: {original}\nTest ID: {test_id}\n"
                     f"Both returned HTTP 200 with different content. Test response contains PII patterns.",
            remediation="Implement server-side authorization checks. Use indirect references (UUIDs).",
            url=url,
            module="idor",
            cwe="CWE-639",
            confirmed=True,
        ))
    elif _contains_pii(resp.text):
        session.add_finding(Finding(
            title=f"Potential IDOR: Sequential ID Accessible",
            severity=Severity.MEDIUM,
            description=f"Parameter '{param}' returns different data with PII when ID is changed.",
            evidence=f"Original ID: {original}, Test ID: {test_id}\nBoth returned HTTP 200.",
            remediation="Verify server-side authorization. Use UUIDs instead of sequential IDs.",
            url=url,
            module="idor",
            cwe="CWE-639",
            confirmed=False,
        ))


def _check_path_idor(session: ScanSession, url: str):
    for pattern in ID_PATH_PATTERNS:
        match = re.search(pattern, url)
        if not match:
            continue

        original_id = match.group(1)
        original_int = int(original_id)

        resp_original = session.get(url)
        if not resp_original or resp_original.status_code != 200:
            continue

        test_id = str(original_int + 1) if original_int > 0 else "1"
        test_url = url[:match.start(1)] + test_id + url[match.end(1):]
        resp = session.get(test_url)
        if not resp or resp.status_code != 200:
            continue

        if _responses_differ_meaningfully(resp_original.text, resp.text) and _contains_pii(resp.text):
            session.add_finding(Finding(
                title="Potential IDOR via URL Path",
                severity=Severity.MEDIUM,
                description=f"URL path contains sequential ID that returns different data with PII when modified.",
                evidence=f"Original: {url}\nModified: {test_url}",
                remediation="Implement authorization checks. Use non-guessable identifiers.",
                url=url,
                module="idor",
                cwe="CWE-639",
                confirmed=False,
            ))
            return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Insecure Direct Object References (IDOR)...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param, values in params.items():
            if param.lower() in EXCLUDE_PARAMS:
                continue
            if param.lower() in ID_PARAMS or (values and values[0].isdigit()):
                _check_param_idor(session, url, param, values[0] if values else "")

        _check_path_idor(session, url)
