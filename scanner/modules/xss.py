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
                session.add_finding(Finding(
                    title="Reflected XSS via URL Parameter",
                    severity=Severity.HIGH,
                    description=f"Parameter '{param}' reflects HTML/script tags without encoding in {context} context.",
                    evidence=f"Parameter: {param}\nPayload: {payload}\nReflected: {expected}\nContext: {context}",
                    remediation="Encode all user-controlled output. Use Content-Security-Policy.",
                    url=url,
                    module="xss",
                    cwe="CWE-79",
                    confirmed=True,
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
                session.add_finding(Finding(
                    title="Reflected XSS via Form Input",
                    severity=Severity.HIGH,
                    description=f"Form field '{name}' at {form['action']} reflects input without sanitization.",
                    evidence=f"Field: {name}\nPayload: {payload}\nReflected: {expected}",
                    remediation="Encode all user-controlled output in HTML responses.",
                    url=form.get("source_url", form["action"]),
                    module="xss",
                    cwe="CWE-79",
                    confirmed=True,
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
