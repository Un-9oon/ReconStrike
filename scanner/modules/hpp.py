import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core import Finding, Severity, ScanSession


def _build_curl(method, url, data=None):
    cmd = f"curl -k -X {method} '{url}'"
    if data:
        cmd += f" -d '{data}'"
    return cmd


def _get_baseline(session, url, param, value):
    """Get a baseline response with the original parameter value."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value or "1"]
    baseline_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    resp = session.get(baseline_url)
    return resp


def _detect_handling(baseline_text, test_text, val1, val2):
    """Detect how the server handles duplicate parameters."""
    if not baseline_text or not test_text:
        return None

    has_val1 = val1 in test_text
    has_val2 = val2 in test_text
    has_both = has_val1 and has_val2
    combined = f"{val1},{val2}"
    has_combined = combined in test_text
    concatenated = f"{val1}{val2}"
    has_concat = concatenated in test_text

    if has_combined or has_concat:
        return "concatenated"
    elif has_both:
        return "both"
    elif has_val2 and not has_val1:
        return "last"
    elif has_val1 and not has_val2:
        return "first"
    return None


def _response_differs_significantly(baseline_resp, test_resp):
    """Check if responses differ beyond trivial variance."""
    if not baseline_resp or not test_resp:
        return False
    if baseline_resp.status_code != test_resp.status_code:
        return True
    baseline_len = len(baseline_resp.text)
    test_len = len(test_resp.text)
    if baseline_len == 0:
        return test_len > 50
    ratio = abs(test_len - baseline_len) / max(baseline_len, 1)
    return ratio > 0.1


MARKER_VAL1 = "hpp_first_7291"
MARKER_VAL2 = "hpp_second_3847"


def _test_url_params(session, url):
    """Test URL parameters for HTTP Parameter Pollution."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return

    for param, values in params.items():
        original = values[0] if values else ""

        # Get baseline with a single known value
        baseline_resp = _get_baseline(session, url, param, original or "1")
        if not baseline_resp:
            continue

        # Build URL with duplicate parameter: param=val1&param=val2
        # We use marker values to detect which one the server uses
        val1 = original or MARKER_VAL1
        val2 = MARKER_VAL2

        # Manually build query to ensure duplicate params
        other_params = []
        for p, vs in params.items():
            if p != param:
                for v in vs:
                    other_params.append(f"{p}={v}")

        dup_parts = other_params + [f"{param}={val1}", f"{param}={val2}"]
        dup_query = "&".join(dup_parts)
        test_url = urlunparse(parsed._replace(query=dup_query))

        resp = session.get(test_url)
        if not resp or resp.status_code in (404, 500):
            continue

        handling = _detect_handling(
            baseline_resp.text, resp.text, val1, val2
        )

        differs = _response_differs_significantly(baseline_resp, resp)

        if handling or differs:
            # Now test with potentially dangerous duplicate values
            # e.g., param=legit&param=malicious to test WAF bypass
            attack_val1 = original or "1"
            attack_val2 = "1 OR 1=1"
            attack_parts = other_params + [
                f"{param}={attack_val1}",
                f"{param}={attack_val2}"
            ]
            attack_query = "&".join(attack_parts)
            attack_url = urlunparse(parsed._replace(query=attack_query))
            attack_resp = session.get(attack_url)

            # Also test reversed order
            reverse_parts = other_params + [
                f"{param}={attack_val2}",
                f"{param}={attack_val1}"
            ]
            reverse_query = "&".join(reverse_parts)
            reverse_url = urlunparse(parsed._replace(query=reverse_query))
            reverse_resp = session.get(reverse_url)

            waf_bypass_indicator = False
            if attack_resp and attack_resp.status_code == 200:
                # If a single malicious param gets blocked (403) but duplicate doesn't
                single_attack_params = dict(params)
                single_attack_params[param] = [attack_val2]
                single_query = urlencode(single_attack_params, doseq=True)
                single_url = urlunparse(parsed._replace(query=single_query))
                single_resp = session.get(single_url)
                if single_resp and single_resp.status_code in (403, 406, 429):
                    waf_bypass_indicator = True

            handling_desc = {
                "first": "uses the FIRST occurrence",
                "last": "uses the LAST occurrence",
                "both": "uses BOTH values",
                "concatenated": "CONCATENATES the values",
            }.get(handling, "produces different behavior")

            severity = Severity.MEDIUM if waf_bypass_indicator else Severity.LOW
            confirmed = waf_bypass_indicator

            curl_cmd = _build_curl("GET", test_url)
            session.add_finding(Finding(
                title=f"HTTP Parameter Pollution (GET) - Server {handling_desc}",
                severity=severity,
                description=(
                    f"The URL parameter '{param}' is susceptible to HTTP Parameter Pollution. "
                    f"When duplicate parameters are supplied ('{param}' appears twice), the "
                    f"server {handling_desc}. "
                    + (
                        "Additionally, a WAF bypass was detected: a single malicious parameter "
                        "was blocked, but the same payload passed through when duplicated."
                        if waf_bypass_indicator else
                        "This behavior inconsistency can be exploited for WAF bypass, "
                        "logic flaws, or parameter precedence attacks."
                    )
                ),
                evidence=(
                    f"Parameter: {param}\n"
                    f"Test URL: {test_url}\n"
                    f"Server Handling: {handling_desc}\n"
                    f"Baseline Status: {baseline_resp.status_code}\n"
                    f"Duplicate Param Status: {resp.status_code}\n"
                    f"Response Differs: {differs}\n"
                    f"WAF Bypass Detected: {waf_bypass_indicator}"
                    + (f"\n  Single malicious param blocked, duplicate allowed" if waf_bypass_indicator else "")
                ),
                remediation=(
                    "1. Explicitly handle duplicate parameters in server-side code:\n"
                    "   - Accept only the first value or reject the request entirely.\n"
                    "2. Ensure WAF/proxy and application see the same parameter value.\n"
                    "3. Use a framework that rejects duplicate parameters by default.\n"
                    "4. Validate parameters after any proxying/load-balancing layer.\n"
                    "5. If using multiple layers (proxy + app), ensure both use the same parameter."
                ),
                url=url,
                module="hpp",
                cwe="CWE-235",
                confirmed=confirmed,
                location=f"URL parameter '{param}' in query string of {parsed.path}",
                parameter=param,
                payload=f"{param}={val1}&{param}={val2}",
                request_method="GET",
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Open: {url}\n"
                    f"2. Add a duplicate parameter: {test_url}\n"
                    f"3. Observe which value the server uses ({handling_desc}).\n"
                    f"4. Run: {curl_cmd}\n"
                    f"5. Compare the response with the baseline (single param) response."
                    + (f"\n6. WAF bypass: single malicious value was blocked, duplicate was allowed." if waf_bypass_indicator else "")
                ),
                developer_fix=(
                    f"File: The server-side code handling '{parsed.path}'.\n\n"
                    f"Explicitly extract only a single value for each parameter:\n\n"
                    f"  Python/Flask:\n"
                    f"    value = request.args.get('{param}')  # Gets first value only\n"
                    f"    # NOT: request.args.getlist('{param}')  # Gets all values\n\n"
                    f"  Node.js/Express:\n"
                    f"    const value = Array.isArray(req.query.{param})\n"
                    f"      ? req.query.{param}[0]\n"
                    f"      : req.query.{param};\n\n"
                    f"  PHP:\n"
                    f"    // PHP natively uses last value; be aware of param[] array syntax"
                ),
                affected_component=f"Parameter handling in route for {parsed.path}",
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution | https://book.hacktricks.xyz/pentesting-web/parameter-pollution",
                detection_method=f"Sent duplicate URL parameters ('{param}' appearing twice with different values) and analyzed which value the server used in its response. Server {handling_desc}.",
            ))


def _test_form_params(session, form):
    """Test form parameters for HTTP Parameter Pollution via POST."""
    action = form.get("action", "")
    method = form.get("method", "post").lower()
    inputs = form.get("inputs", [])
    source_url = form.get("source_url", action)

    if method != "post":
        return

    baseline_data = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            baseline_data[name] = inp.get("value", "test")

    baseline_resp = session.post(action, data=baseline_data)
    if not baseline_resp:
        return

    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue

        original = inp.get("value", "test")
        val1 = original
        val2 = MARKER_VAL2

        # Build POST body with duplicate parameter using raw string
        # requests normally deduplicates dict keys, so we use a list of tuples
        dup_data = []
        for k, v in baseline_data.items():
            if k != name:
                dup_data.append((k, v))
        dup_data.append((name, val1))
        dup_data.append((name, val2))

        resp = session.post(action, data=dup_data)
        if not resp or resp.status_code in (404, 500):
            continue

        handling = _detect_handling(
            baseline_resp.text, resp.text, val1, val2
        )

        differs = _response_differs_significantly(baseline_resp, resp)

        if handling or differs:
            handling_desc = {
                "first": "uses the FIRST occurrence",
                "last": "uses the LAST occurrence",
                "both": "uses BOTH values",
                "concatenated": "CONCATENATES the values",
            }.get(handling, "produces different behavior")

            post_body = "&".join(f"{k}={v}" for k, v in dup_data)
            curl_cmd = _build_curl("POST", action, data=post_body)

            session.add_finding(Finding(
                title=f"HTTP Parameter Pollution (POST Form) - Server {handling_desc}",
                severity=Severity.LOW,
                description=(
                    f"The form field '{name}' at '{action}' is susceptible to HTTP Parameter "
                    f"Pollution via POST. When the field appears twice in the POST body with "
                    f"different values, the server {handling_desc}. This can lead to logic "
                    f"flaws, WAF bypass, or parameter precedence attacks."
                ),
                evidence=(
                    f"Form Action: {action}\n"
                    f"Form Method: POST\n"
                    f"Field: {name}\n"
                    f"Duplicate Values: {val1}, {val2}\n"
                    f"Server Handling: {handling_desc}\n"
                    f"Baseline Status: {baseline_resp.status_code}\n"
                    f"Duplicate Param Status: {resp.status_code}\n"
                    f"Response Differs: {differs}"
                ),
                remediation=(
                    "1. Explicitly handle duplicate POST parameters on the server side.\n"
                    "2. Reject requests with duplicate parameter names.\n"
                    "3. Ensure WAF and application agree on which value to use.\n"
                    "4. Use a strict parameter parser that does not silently merge values."
                ),
                url=source_url,
                module="hpp",
                cwe="CWE-235",
                confirmed=False,
                location=f"Form field '{name}' in form at {action}",
                parameter=name,
                payload=f"{name}={val1}&{name}={val2}",
                request_method="POST",
                request_body=post_body,
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Navigate to: {source_url}\n"
                    f"2. Locate the form that submits to {action}\n"
                    f"3. Using an intercepting proxy, duplicate the '{name}' field:\n"
                    f"   {name}={val1}&{name}={val2}\n"
                    f"4. Submit and observe which value the server uses.\n"
                    f"5. Run: {curl_cmd}"
                ),
                developer_fix=(
                    f"File: The server-side handler for POST {action}.\n\n"
                    f"Explicitly extract a single value:\n\n"
                    f"  Python/Flask:\n"
                    f"    value = request.form.get('{name}')  # First value only\n\n"
                    f"  Node.js/Express:\n"
                    f"    const value = Array.isArray(req.body.{name})\n"
                    f"      ? req.body.{name}[0]\n"
                    f"      : req.body.{name};\n\n"
                    f"  Or reject duplicates:\n"
                    f"    if (Array.isArray(req.body.{name})) return res.status(400).json({{error: 'Invalid input'}});"
                ),
                affected_component=f"POST parameter handling in form handler for {action}",
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution",
                detection_method=f"Submitted duplicate POST form parameters ('{name}' appearing twice) and detected the server {handling_desc} based on response content comparison.",
            ))


def run(session: ScanSession) -> None:
    print("\n[*] Testing for HTTP Parameter Pollution...")

    for url in session.crawled_urls:
        _test_url_params(session, url)

    for form in session.forms:
        _test_form_params(session, form)
