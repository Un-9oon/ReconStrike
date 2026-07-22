import re
import random
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession


def _make_payloads():
    a = random.randint(71, 97)
    b = random.randint(103, 127)
    expected = str(a * b)
    return a, b, expected


ENGINES = [
    ("Jinja2/Twig", "{{{a}*{b}}}", [("{{config}}", r"<Config|SECRET_KEY"), ("{{7*'7'}}", "7777777")]),
    ("FreeMarker/Mako", "${{{a}*{b}}}", []),
    ("Ruby ERB / Java EL", "#{{{a}*{b}}}", []),
    ("ERB/ASP", "<%= {a}*{b} %>", []),
    ("Razor", "@({a}*{b})", []),
]


def _confirm_ssti(session, url_or_action, param, method, form_data, engine_confirms, is_form):
    for confirm_payload, confirm_pattern in engine_confirms:
        if is_form:
            data = dict(form_data)
            data[param] = confirm_payload
            if method == "post":
                resp = session.post(url_or_action, data=data)
            else:
                resp = session.get(url_or_action, params=data)
        else:
            parsed = urlparse(url_or_action)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [confirm_payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            resp = session.get(test_url)

        if resp and re.search(confirm_pattern, resp.text):
            return True

    a2 = random.randint(201, 299)
    b2 = random.randint(301, 399)
    expected2 = str(a2 * b2)
    verify_payload = f"{{{{{a2}*{b2}}}}}"

    if is_form:
        data = dict(form_data)
        data[param] = verify_payload
        if method == "post":
            resp = session.post(url_or_action, data=data)
        else:
            resp = session.get(url_or_action, params=data)
    else:
        parsed = urlparse(url_or_action)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [verify_payload]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        resp = session.get(test_url)

    if resp and expected2 in resp.text:
        baseline_check = f"nontemplate{expected2}marker"
        if is_form:
            data[param] = baseline_check
            if method == "post":
                resp_b = session.post(url_or_action, data=data)
            else:
                resp_b = session.get(url_or_action, params=data)
        else:
            params[param] = [baseline_check]
            resp_b = session.get(urlunparse(parsed._replace(query=urlencode(params, doseq=True))))
        if resp_b and expected2 not in resp_b.text:
            return True

    return False


def _test_param_url(session: ScanSession, url: str, param: str, original: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    canary = f"vulnscancanary{random.randint(100000, 999999)}"
    params[param] = [canary]
    test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(test_url)
    if not resp or canary not in resp.text:
        return

    a, b, expected = _make_payloads()

    for engine_name, tpl, confirms in ENGINES:
        payload = tpl.format(a=a, b=b)
        params[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        resp = session.get(test_url)
        if not resp:
            continue

        if expected in resp.text:
            if _confirm_ssti(session, url, param, "get", None, confirms, is_form=False):
                session.add_finding(Finding(
                    title=f"Server-Side Template Injection ({engine_name})",
                    severity=Severity.CRITICAL,
                    description=f"Parameter '{param}' is vulnerable to SSTI via {engine_name}. This can lead to Remote Code Execution.",
                    evidence=f"Payload: {payload}\nExpected: {expected}\nEngine: {engine_name}\nURL: {test_url}",
                    remediation="Never pass user input directly into template engines. Use sandboxed rendering.",
                    url=url,
                    module="ssti",
                    cwe="CWE-1336",
                    confirmed=True,
                ))
                return


def _test_form(session: ScanSession, form: dict):
    for inp in form["inputs"]:
        name = inp.get("name")
        if not name or inp.get("type") in ("hidden", "submit", "button", "file"):
            continue

        canary = f"vulnscancanary{random.randint(100000, 999999)}"
        base_data = {}
        for other in form["inputs"]:
            other_name = other.get("name")
            if not other_name:
                continue
            base_data[other_name] = canary if other_name == name else other.get("value", "test")

        if form["method"] == "post":
            resp = session.post(form["action"], data=base_data)
        else:
            resp = session.get(form["action"], params=base_data)

        if not resp or canary not in resp.text:
            continue

        a, b, expected = _make_payloads()

        for engine_name, tpl, confirms in ENGINES:
            payload = tpl.format(a=a, b=b)
            test_data = dict(base_data)
            test_data[name] = payload

            if form["method"] == "post":
                resp2 = session.post(form["action"], data=test_data)
            else:
                resp2 = session.get(form["action"], params=test_data)

            if resp2 and expected in resp2.text:
                if _confirm_ssti(session, form["action"], name, form["method"], base_data, confirms, is_form=True):
                    session.add_finding(Finding(
                        title=f"Server-Side Template Injection in Form ({engine_name})",
                        severity=Severity.CRITICAL,
                        description=f"Form field '{name}' at {form['action']} is vulnerable to SSTI.",
                        evidence=f"Field: {name}\nPayload: {payload}\nExpected: {expected}\nEngine: {engine_name}",
                        remediation="Never pass user input directly into template engines.",
                        url=form.get("source_url", form["action"]),
                        module="ssti",
                        cwe="CWE-1336",
                        confirmed=True,
                    ))
                    return


def run(session: ScanSession) -> None:
    print("\n[*] Testing for Server-Side Template Injection (SSTI)...")

    for url in session.crawled_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param, values in params.items():
            _test_param_url(session, url, param, values[0] if values else "")

    for form in session.forms:
        _test_form(session, form)
