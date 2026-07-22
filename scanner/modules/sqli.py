import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession

ERROR_PATTERNS = [
    (r"SQL syntax.*?MySQL", "MySQL"),
    (r"Warning.*?\Wmysqli?_", "MySQL"),
    (r"MySQLSyntaxErrorException", "MySQL"),
    (r"check the manual that (?:corresponds to|fits) your MySQL server version", "MySQL"),
    (r"PostgreSQL.*?ERROR", "PostgreSQL"),
    (r"pg_query\(\).*?failed", "PostgreSQL"),
    (r"PSQLException", "PostgreSQL"),
    (r"org\.postgresql\.util\.PSQLException", "PostgreSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"SQLServerException", "MSSQL"),
    (r"ORA-\d{5}", "Oracle"),
    (r"oracle\.jdbc", "Oracle"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"SQLITE_ERROR", "SQLite"),
    (r"unrecognized token:", "SQLite"),
    (r"SQLSTATE\[\w+\]", "Generic"),
    (r"Syntax error.*?in query expression", "Generic"),
]

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "1' AND '1'='1",
    "' UNION SELECT NULL--",
    "') OR ('1'='1",
]

TIME_PAYLOADS = [
    ("' OR SLEEP(5)-- ", 5),
    ("' AND (SELECT * FROM (SELECT SLEEP(5))a)-- ", 5),
    ("'; WAITFOR DELAY '0:0:5'-- ", 5),
    ("' OR pg_sleep(5)-- ", 5),
]


def _get_baseline(session, url, param, original):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [original or "harmless"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(baseline_url)
    return resp.text if resp else ""


def _check_error_based(session: ScanSession, url: str, param: str, original_value: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    baseline_text = _get_baseline(session, url, param, original_value)

    for payload in SQLI_PAYLOADS:
        params[param] = [original_value + payload]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        resp = session.get(test_url)
        if not resp or resp.status_code in (404, 403):
            continue

        body = resp.text
        for pattern, db_type in ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if re.search(pattern, baseline_text, re.IGNORECASE):
                    continue
                session.add_finding(Finding(
                    title=f"SQL Injection (Error-Based) - {db_type}",
                    severity=Severity.CRITICAL,
                    description=f"Parameter '{param}' is vulnerable to error-based SQL injection. Database: {db_type}.",
                    evidence=f"Payload: {payload}\nURL: {test_url}\nMatched pattern: {pattern}",
                    remediation="Use parameterized queries / prepared statements.",
                    url=url,
                    module="sqli",
                    cwe="CWE-89",
                    confirmed=True,
                ))
                return True
    return False


def _check_time_based(session: ScanSession, url: str, param: str, original_value: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    baseline_times = []
    params[param] = [original_value or "harmless"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    for _ in range(2):
        start = time.time()
        session.get(baseline_url)
        baseline_times.append(time.time() - start)
    baseline_max = max(baseline_times)

    for payload, delay in TIME_PAYLOADS:
        params[param] = [original_value + payload]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        hits = 0
        for _ in range(2):
            start = time.time()
            resp = session.get(test_url)
            elapsed = time.time() - start

            expected_min = baseline_max + delay - 1.5
            expected_max = baseline_max + delay + 3
            if resp and expected_min <= elapsed <= expected_max:
                hits += 1

        if hits >= 2:
            session.add_finding(Finding(
                title="SQL Injection (Time-Based Blind)",
                severity=Severity.CRITICAL,
                description=f"Parameter '{param}' is vulnerable to time-based blind SQL injection.",
                evidence=f"Payload: {payload}\nBaseline max: {baseline_max:.2f}s\nBoth injected requests matched expected delay window",
                remediation="Use parameterized queries / prepared statements.",
                url=url,
                module="sqli",
                cwe="CWE-89",
                confirmed=True,
            ))
            return True
    return False


def _check_form_sqli(session: ScanSession, form: dict):
    baseline_data = {}
    for inp in form["inputs"]:
        name = inp.get("name")
        if name:
            baseline_data[name] = inp.get("value", "test")

    if form["method"] == "post":
        baseline_resp = session.post(form["action"], data=baseline_data)
    else:
        baseline_resp = session.get(form["action"], params=baseline_data)
    baseline_text = baseline_resp.text if baseline_resp else ""

    for inp in form["inputs"]:
        name = inp.get("name")
        if not name or inp.get("type") in ("hidden", "submit", "button", "checkbox", "radio", "file"):
            continue

        for payload in SQLI_PAYLOADS[:4]:
            post_data = dict(baseline_data)
            post_data[name] = payload

            if form["method"] == "post":
                resp = session.post(form["action"], data=post_data)
            else:
                resp = session.get(form["action"], params=post_data)

            if not resp or resp.status_code in (404, 403):
                continue

            for pattern, db_type in ERROR_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    if re.search(pattern, baseline_text, re.IGNORECASE):
                        continue
                    session.add_finding(Finding(
                        title=f"SQL Injection in Form (Error-Based) - {db_type}",
                        severity=Severity.CRITICAL,
                        description=f"Form field '{name}' at {form['action']} is vulnerable to SQL injection.",
                        evidence=f"Field: {name}, Payload: {payload}\nMatched: {pattern}",
                        remediation="Use parameterized queries / prepared statements.",
                        url=form.get("source_url", form["action"]),
                        module="sqli",
                        cwe="CWE-89",
                        confirmed=True,
                    ))
                    return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for SQL Injection...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param, values in params.items():
            original = values[0] if values else ""
            if not _check_error_based(session, url, param, original):
                _check_time_based(session, url, param, original)

    for form in session.forms:
        _check_form_sqli(session, form)
