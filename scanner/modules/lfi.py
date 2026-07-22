import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession

LFI_PAYLOADS = [
    ("../../../etc/passwd", r"root:[x*]:0:0:"),
    ("....//....//....//etc/passwd", r"root:[x*]:0:0:"),
    ("..%2f..%2f..%2fetc%2fpasswd", r"root:[x*]:0:0:"),
    ("..%252f..%252f..%252fetc%252fpasswd", r"root:[x*]:0:0:"),
    ("....\\....\\....\\windows\\win.ini", r"^\[fonts\]", ),
    ("../../../windows/win.ini", r"^\[fonts\]"),
    ("/etc/passwd", r"root:[x*]:0:0:"),
    ("file:///etc/passwd", r"root:[x*]:0:0:"),
]

PATH_TRAVERSAL_PARAMS = [
    "file", "path", "page", "template", "include", "doc", "document",
    "folder", "root", "pg", "style", "pdf", "img", "filename",
    "preview", "load", "read", "content", "download", "view",
]


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Local File Inclusion / Path Traversal...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param, values in params.items():
            if param.lower() not in PATH_TRAVERSAL_PARAMS:
                original = values[0] if values else ""
                if not any(c in original for c in "./\\"):
                    continue

            _test_param(session, url, param, values[0] if values else "")

    base_url = session.config.target.rstrip("/")
    for param in PATH_TRAVERSAL_PARAMS[:5]:
        test_url = f"{base_url}?{param}=test"
        resp = session.get(test_url)
        if resp and resp.status_code == 200:
            _test_param(session, test_url, param, "test")


def _test_param(session: ScanSession, url: str, param: str, original: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    params[param] = [original or "harmless_value"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    baseline_resp = session.get(baseline_url)
    baseline_text = baseline_resp.text if baseline_resp else ""

    for payload, indicator in LFI_PAYLOADS:
        params[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        resp = session.get(test_url)
        if not resp or resp.status_code in (404, 403):
            continue

        match = re.search(indicator, resp.text, re.IGNORECASE | re.MULTILINE)
        if match and not re.search(indicator, baseline_text, re.IGNORECASE | re.MULTILINE):
            matched_text = match.group(0)
            if _looks_like_passwd(resp.text, indicator) or _looks_like_winini(resp.text, indicator):
                session.add_finding(Finding(
                    title=f"Local File Inclusion / Path Traversal",
                    severity=Severity.CRITICAL,
                    description=f"Parameter '{param}' is vulnerable to local file inclusion.",
                    evidence=f"Payload: {payload}\nURL: {test_url}\nMatched: {matched_text}",
                    remediation="Never use user input in file paths. Use a whitelist of allowed files.",
                    url=url,
                    module="lfi",
                    cwe="CWE-98",
                    confirmed=True,
                ))
                return


def _looks_like_passwd(text: str, indicator: str) -> bool:
    if "root:" not in indicator:
        return True
    lines = [l for l in text.split("\n") if re.match(r"^[a-z_][\w-]*:[^:]*:\d+:\d+:", l)]
    return len(lines) >= 3


def _looks_like_winini(text: str, indicator: str) -> bool:
    if "fonts" not in indicator:
        return True
    return "[fonts]" in text.lower() and "[extensions]" in text.lower()
