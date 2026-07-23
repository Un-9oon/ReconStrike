import re
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession


def _random_tag():
    return "vs" + "".join(random.choices(string.ascii_lowercase, k=8))


REFLECTION_PAYLOADS = [
    ("<{tag}>", "<{tag}>"),
    ("<img src=x onerror={tag}>", "<img src=x onerror={tag}>"),
    ("<svg onload={tag}>", "<svg onload={tag}>"),
    ("'\"><{tag}>", "<{tag}>"),
    ("<script>{tag}</script>", "<script>{tag}</script>"),
    ("<details open ontoggle={tag}>", "<details open ontoggle={tag}>"),
]

SAFE_CONTEXTS_RE = re.compile(
    r'<!--.*?-->|<textarea[^>]*>.*?</textarea>|<title[^>]*>.*?</title>',
    re.DOTALL | re.IGNORECASE
)


def _is_in_safe_context(body: str, needle: str) -> bool:
    for match in SAFE_CONTEXTS_RE.finditer(body):
        if needle in match.group(0):
            return True
    return False


def _detect_context(body: str, marker: str) -> str:
    idx = body.find(marker)
    if idx == -1:
        return "none"
    before = body[max(0, idx - 200):idx]
    if re.search(r'<script[^>]*>[^<]*$', before, re.IGNORECASE | re.DOTALL):
        return "js_string"
    if re.search(r'=\s*["\'][^"\']*$', before):
        return "html_attr"
    return "html_body"


def _build_curl(method, url, headers=None, data=None):
    cmd = f"curl -k -X {method} '{url}'"
    if headers:
        for k, v in headers.items():
            cmd += f" -H '{k}: {v}'"
    if data:
        cmd += f" -d '{data}'"
    return cmd


def _check_url_params(session: ScanSession, url: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    for param, values in params.items():
        tag = _random_tag()

        params_test = dict(params)
        params_test[param] = [tag]
        test_url = urlunparse(parsed._replace(query=urlencode(params_test, doseq=True)))
        resp = session.get(test_url)
        if not resp or tag not in resp.text:
            continue

        if _is_in_safe_context(resp.text, tag):
            continue

        context = _detect_context(resp.text, tag)
        if context == "none":
            continue

        for payload_tpl, check in REFLECTION_PAYLOADS:
            tag2 = _random_tag()
            payload = payload_tpl.format(tag=tag2)
            expected = check.format(tag=tag2)
            params_test[param] = [payload]
            test_url2 = urlunparse(parsed._replace(query=urlencode(params_test, doseq=True)))
            resp2 = session.get(test_url2)
            if not resp2:
                continue

            if expected in resp2.text:
                if _is_in_safe_context(resp2.text, expected):
                    continue

                idx = resp2.text.find(expected)
                snippet_start = max(0, idx - 40)
                snippet_end = min(len(resp2.text), idx + len(expected) + 40)
                snippet = resp2.text[snippet_start:snippet_end].replace('\n', ' ')

                session.add_finding(Finding(
                    title="Reflected XSS via URL Parameter",
                    severity=Severity.HIGH,
                    description=(
                        f"The URL parameter '{param}' is reflected in the HTTP response without "
                        f"proper output encoding. The reflection occurs in a '{context}' context, "
                        f"allowing injection of arbitrary HTML/JavaScript that executes in the "
                        f"victim's browser when they visit the crafted URL."
                    ),
                    evidence=(
                        f"Parameter: {param}\n"
                        f"Injection Context: {context}\n"
                        f"Payload Sent: {payload}\n"
                        f"Reflected As: {expected}\n"
                        f"Response Snippet: ...{snippet}...\n"
                        f"Response Status: {resp2.status_code}"
                    ),
                    remediation=(
                        "1. Apply context-aware output encoding on all user input before rendering in HTML.\n"
                        "2. Use framework auto-escaping (Jinja2 autoescape, React JSX, Django templates).\n"
                        "3. Implement Content-Security-Policy header to restrict inline script execution.\n"
                        "4. Use HttpOnly flag on session cookies to limit impact of XSS."
                    ),
                    url=url,
                    module="xss",
                    cwe="CWE-79",
                    confirmed=True,
                    location=f"URL parameter '{param}' in query string",
                    parameter=param,
                    payload=payload,
                    request_method="GET",
                    response_status=resp2.status_code,
                    curl_command=_build_curl("GET", test_url2),
                    reproduction_steps=(
                        f"1. Open the target URL: {url}\n"
                        f"2. Modify the '{param}' parameter value to: {payload}\n"
                        f"3. Send the request (full URL: {test_url2})\n"
                        f"4. Observe the payload is reflected unencoded in the {context} context of the response body.\n"
                        f"5. The injected HTML/script executes in the browser."
                    ),
                    developer_fix=(
                        f"File: The server-side code that handles the '{parsed.path}' route and renders the "
                        f"'{param}' parameter value into HTML output.\n"
                        f"Fix: Replace direct output of the parameter with HTML-encoded output.\n"
                        f"Example: Instead of outputting '{param}' raw, use your framework's escaping:\n"
                        f"  - Python/Jinja2: {{{{ {param} | e }}}}\n"
                        f"  - PHP: htmlspecialchars(${param}, ENT_QUOTES, 'UTF-8')\n"
                        f"  - Node/Express: Use a template engine with auto-escaping enabled"
                    ),
                    affected_component=f"Route handler for {parsed.path}",
                    references="https://owasp.org/www-community/attacks/xss/ | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    detection_method="Injected XSS payloads (script tags, event handlers, SVG/IMG vectors) into URL parameters and form fields, then checked if the payload appeared unescaped in the response HTML. Baseline comparison eliminates pre-existing content matches.",
                ))
                return


def _check_forms(session: ScanSession, form: dict):
    for inp in form["inputs"]:
        name = inp.get("name")
        if not name or inp.get("type") in ("hidden", "submit", "button", "file"):
            continue

        tag = _random_tag()
        post_data = {}
        for other in form["inputs"]:
            other_name = other.get("name")
            if not other_name:
                continue
            if other_name == name:
                post_data[other_name] = tag
            else:
                post_data[other_name] = other.get("value", "test")

        if form["method"] == "post":
            resp = session.post(form["action"], data=post_data)
        else:
            resp = session.get(form["action"], params=post_data)

        if not resp or tag not in resp.text:
            continue

        if _is_in_safe_context(resp.text, tag):
            continue

        for payload_tpl, check in REFLECTION_PAYLOADS[:4]:
            tag2 = _random_tag()
            payload = payload_tpl.format(tag=tag2)
            expected = check.format(tag=tag2)

            post_data[name] = payload
            if form["method"] == "post":
                resp2 = session.post(form["action"], data=post_data)
            else:
                resp2 = session.get(form["action"], params=post_data)

            if resp2 and expected in resp2.text:
                if _is_in_safe_context(resp2.text, expected):
                    continue

                method = form["method"].upper()
                data_str = "&".join(f"{k}={v}" for k, v in post_data.items())
                source_url = form.get("source_url", form["action"])

                session.add_finding(Finding(
                    title="Reflected XSS via Form Input",
                    severity=Severity.HIGH,
                    description=(
                        f"The form field '{name}' submitted to {form['action']} reflects "
                        f"user input in the response without proper sanitization. An attacker "
                        f"can craft a malicious form submission that injects arbitrary JavaScript "
                        f"into the page, potentially stealing session cookies or performing "
                        f"actions on behalf of authenticated users."
                    ),
                    evidence=(
                        f"Form Action: {form['action']}\n"
                        f"Form Method: {method}\n"
                        f"Vulnerable Field: {name}\n"
                        f"Field Type: {inp.get('type', 'text')}\n"
                        f"Payload Sent: {payload}\n"
                        f"Reflected As: {expected}\n"
                        f"Response Status: {resp2.status_code}"
                    ),
                    remediation=(
                        "1. HTML-encode all form input values before rendering in responses.\n"
                        "2. Implement Content-Security-Policy to block inline scripts.\n"
                        "3. Validate and sanitize input on the server side.\n"
                        "4. Use framework auto-escaping features."
                    ),
                    url=source_url,
                    module="xss",
                    cwe="CWE-79",
                    confirmed=True,
                    location=f"Form field '{name}' (type: {inp.get('type', 'text')}) at {form['action']}",
                    parameter=name,
                    payload=payload,
                    request_method=method,
                    request_body=data_str,
                    response_status=resp2.status_code,
                    curl_command=_build_curl(method, form["action"], data=data_str) if method == "POST" else _build_curl("GET", f"{form['action']}?{data_str}"),
                    reproduction_steps=(
                        f"1. Navigate to the page containing the form: {source_url}\n"
                        f"2. Locate the form that submits to: {form['action']}\n"
                        f"3. Enter the following payload in the '{name}' field: {payload}\n"
                        f"4. Submit the form.\n"
                        f"5. Observe the payload is reflected unencoded in the response body."
                    ),
                    developer_fix=(
                        f"File: The server-side handler for {method} {form['action']} that processes "
                        f"the '{name}' form field and includes it in the response HTML.\n"
                        f"Fix: Apply output encoding when rendering the '{name}' value.\n"
                        f"Also: Add Content-Security-Policy header to prevent inline script execution."
                    ),
                    affected_component=f"{method} {form['action']} - form field '{name}'",
                    references="https://owasp.org/www-community/attacks/xss/",
                    detection_method="Injected XSS payloads (script tags, event handlers, SVG/IMG vectors) into URL parameters and form fields, then checked if the payload appeared unescaped in the response HTML. Baseline comparison eliminates pre-existing content matches.",
                ))
                return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Cross-Site Scripting (XSS)...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        if parsed.query:
            _check_url_params(session, url)

    for form in session.forms:
        _check_forms(session, form)
