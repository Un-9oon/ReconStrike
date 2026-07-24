import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession, build_curl

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

    curl_original = build_curl(url)
    curl_test = build_curl(test_url)

    if _contains_pii(resp.text) and not _contains_pii(resp_original.text):
        session.add_finding(Finding(
            title=f"Insecure Direct Object Reference (IDOR)",
            severity=Severity.HIGH,
            description=(
                f"The parameter '{param}' allows access to other users' data by changing the numeric ID. "
                f"Response for ID {test_id} contains PII (email addresses, phone numbers, or financial data) "
                f"not present in the original response for ID {original}, confirming unauthorized data access."
            ),
            evidence=(
                f"Parameter: {param}\n"
                f"Original ID: {original}\n"
                f"Test ID: {test_id}\n"
                f"Both returned HTTP 200 with different content.\n"
                f"Test response contains PII patterns not in original."
            ),
            remediation=(
                "1. Implement server-side authorization checks on every data access.\n"
                "2. Use indirect references (UUIDs) instead of sequential IDs.\n"
                "3. Verify the authenticated user owns the requested resource."
            ),
            url=url,
            module="idor",
            cwe="CWE-639",
            confirmed=True,
            location=f"URL parameter '{param}' in {parsed.path}",
            parameter=param,
            request_method="GET",
            response_status=resp.status_code,
            curl_command=f"Original: {curl_original}\nModified: {curl_test}",
            reproduction_steps=(
                f"1. Access: {url} (original ID: {original})\n"
                f"2. Change '{param}' to {test_id}: {test_url}\n"
                f"3. Both URLs return HTTP 200 with different content.\n"
                f"4. The modified response contains PII from another user.\n"
                f"5. Run both:\n   {curl_original}\n   {curl_test}"
            ),
            developer_fix=(
                f"File: Server-side handler for '{parsed.path}' that retrieves data by '{param}'.\n\n"
                f"VULNERABLE:\n"
                f"  data = db.query('SELECT * FROM records WHERE id = ?', [request.params['{param}']])\n"
                f"  return data  # No auth check!\n\n"
                f"SECURE:\n"
                f"  data = db.query('SELECT * FROM records WHERE id = ? AND user_id = ?', [request.params['{param}'], current_user.id])\n"
                f"  if not data: return 403\n\n"
                f"Also consider using UUIDs instead of sequential integer IDs."
            ),
            affected_component=f"Data access in route handler for {parsed.path}",
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            detection_method="Modified numeric ID parameters in URLs (e.g., id=1 to id=2) and compared responses. If different valid data is returned for adjacent IDs without authorization checks, this confirms insecure direct object reference.",
        ))
    elif _contains_pii(resp.text):
        session.add_finding(Finding(
            title=f"Potential IDOR: Sequential ID Accessible",
            severity=Severity.MEDIUM,
            description=f"Parameter '{param}' returns different data with PII when ID is changed from {original} to {test_id}.",
            evidence=f"Original ID: {original}, Test ID: {test_id}\nBoth returned HTTP 200 with different content containing PII.",
            remediation="Verify server-side authorization. Use UUIDs instead of sequential IDs.",
            url=url,
            module="idor",
            cwe="CWE-639",
            confirmed=False,
            location=f"URL parameter '{param}' in {parsed.path}",
            parameter=param,
            curl_command=curl_test,
            developer_fix="Add authorization checks to verify the authenticated user owns the requested resource before returning data.",
            references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            detection_method="Modified numeric ID parameters in URLs (e.g., id=1 to id=2) and compared responses. If different valid data is returned for adjacent IDs without authorization checks, this confirms insecure direct object reference.",
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
                description=f"URL path contains sequential ID that returns different data with PII when modified from {original_id} to {test_id}.",
                evidence=f"Original: {url}\nModified: {test_url}\nBoth returned HTTP 200 with different PII-containing content.",
                remediation="Implement authorization checks. Use non-guessable identifiers (UUIDs).",
                url=url,
                module="idor",
                cwe="CWE-639",
                confirmed=False,
                location=f"Sequential ID in URL path: {pattern}",
                curl_command=f"curl -k '{test_url}'",
                reproduction_steps=(
                    f"1. Access original URL: {url}\n"
                    f"2. Change the ID in the path to: {test_id}\n"
                    f"3. Access modified URL: {test_url}\n"
                    f"4. Both return HTTP 200 with different user data."
                ),
                developer_fix="Add server-side authorization to verify the requesting user owns the resource at the given path ID.",
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                detection_method="Modified numeric ID parameters in URLs (e.g., id=1 to id=2) and compared responses. If different valid data is returned for adjacent IDs without authorization checks, this confirms insecure direct object reference.",
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
