import re
import random
import string

from scanner.core import Finding, Severity, ScanSession

UPLOAD_PAYLOADS = [
    {
        "name": "PHP Web Shell",
        "filename": "test.php",
        "content": '<?php echo "VULNSCAN_UPLOAD_" . "CONFIRMED"; ?>',
        "content_type": "application/x-php",
        "indicator": "VULNSCAN_UPLOAD_CONFIRMED",
        "severity": Severity.CRITICAL,
        "desc": "PHP file execution",
    },
    {
        "name": "PHP Double Extension",
        "filename": "test.php.jpg",
        "content": '<?php echo "VULNSCAN_UPLOAD_" . "CONFIRMED"; ?>',
        "content_type": "image/jpeg",
        "indicator": "VULNSCAN_UPLOAD_CONFIRMED",
        "severity": Severity.CRITICAL,
        "desc": "Double extension bypass",
    },
    {
        "name": "PHP Null Byte",
        "filename": "test.php%00.jpg",
        "content": '<?php echo "VULNSCAN_UPLOAD_" . "CONFIRMED"; ?>',
        "content_type": "image/jpeg",
        "indicator": "VULNSCAN_UPLOAD_CONFIRMED",
        "severity": Severity.CRITICAL,
        "desc": "Null byte extension bypass",
    },
    {
        "name": "JSP Upload",
        "filename": "test.jsp",
        "content": '<%= "VULNSCAN_UPLOAD_" + "CONFIRMED" %>',
        "content_type": "application/octet-stream",
        "indicator": "VULNSCAN_UPLOAD_CONFIRMED",
        "severity": Severity.CRITICAL,
        "desc": "JSP file execution",
    },
    {
        "name": "ASP Upload",
        "filename": "test.asp",
        "content": '<% Response.Write("VULNSCAN_UPLOAD_" & "CONFIRMED") %>',
        "content_type": "application/octet-stream",
        "indicator": "VULNSCAN_UPLOAD_CONFIRMED",
        "severity": Severity.CRITICAL,
        "desc": "ASP file execution",
    },
    {
        "name": "SVG XSS",
        "filename": "test.svg",
        "content": '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert("VULNSCAN_XSS")</script></svg>',
        "content_type": "image/svg+xml",
        "indicator": 'alert("VULNSCAN_XSS")',
        "severity": Severity.HIGH,
        "desc": "SVG with embedded JavaScript",
    },
    {
        "name": "HTML Upload",
        "filename": "test.html",
        "content": '<html><body><script>document.write("VULNSCAN_UPLOAD_CONFIRMED")</script></body></html>',
        "content_type": "text/html",
        "indicator": "VULNSCAN_UPLOAD_CONFIRMED",
        "severity": Severity.HIGH,
        "desc": "HTML file with JavaScript",
    },
    {
        "name": ".htaccess Upload",
        "filename": ".htaccess",
        "content": 'AddType application/x-httpd-php .jpg',
        "content_type": "application/octet-stream",
        "indicator": None,
        "severity": Severity.CRITICAL,
        "desc": ".htaccess override",
    },
]


def run(session: ScanSession) -> None:
    print("\n[*] Testing for file upload vulnerabilities...")

    for form in session.forms:
        file_inputs = [inp for inp in form["inputs"] if inp.get("type") == "file"]
        if not file_inputs:
            continue

        print(f"  [*] Found file upload form at {form['action']}")

        for file_input in file_inputs:
            field_name = file_input.get("name", "file")

            other_data = {}
            for inp in form["inputs"]:
                name = inp.get("name")
                if not name or inp.get("type") == "file":
                    continue
                other_data[name] = inp.get("value", "test")

            for payload in UPLOAD_PAYLOADS:
                marker = "".join(random.choices(string.ascii_lowercase, k=6))
                filename = payload["filename"].replace("test", f"vstest_{marker}")

                files = {field_name: (filename, payload["content"], payload["content_type"])}
                resp = session.post(form["action"], files=files, data=other_data)
                if not resp:
                    continue

                if resp.status_code in (200, 201, 301, 302):
                    upload_confirmed = False
                    uploaded_url = ""

                    url_patterns = [
                        rf'(?:src|href|url|path|file)\s*[=:]\s*["\']?([^"\'>\s]*{re.escape(filename)}[^"\'>\s]*)',
                        rf'["\']([^"\']*uploads?[^"\']*{re.escape(marker)}[^"\']*)["\']',
                        rf'["\']([^"\']*files?[^"\']*{re.escape(marker)}[^"\']*)["\']',
                    ]

                    for pattern in url_patterns:
                        match = re.search(pattern, resp.text, re.IGNORECASE)
                        if match:
                            uploaded_url = match.group(1)
                            break

                    if uploaded_url:
                        from urllib.parse import urljoin
                        full_url = urljoin(form["action"], uploaded_url)
                        file_resp = session.get(full_url)

                        if file_resp and payload["indicator"] and payload["indicator"] in file_resp.text:
                            upload_confirmed = True
                            session.add_finding(Finding(
                                title=f"Unrestricted File Upload: {payload['name']}",
                                severity=payload["severity"],
                                description=f"File upload accepts {payload['desc']} and the uploaded file is executable/accessible. "
                                            f"This can lead to Remote Code Execution.",
                                evidence=f"Uploaded: {filename}\nAccessible at: {full_url}\n"
                                         f"Content executed/rendered successfully.",
                                remediation="Validate file types server-side (magic bytes, not just extension). "
                                            "Store uploads outside web root. Use random filenames. "
                                            "Set Content-Disposition: attachment for downloads.",
                                url=form.get("source_url", form["action"]),
                                module="file_upload",
                                cwe="CWE-434",
                                confirmed=True,
                            ))
                            return

                    if not upload_confirmed and payload["filename"] == ".htaccess":
                        if resp.status_code in (200, 201):
                            error_indicators = ["error", "invalid", "not allowed", "rejected",
                                                 "failed", "denied", "forbidden", "unsupported"]
                            body_lower = resp.text.lower()
                            if not any(ind in body_lower for ind in error_indicators):
                                session.add_finding(Finding(
                                    title="File Upload Accepts .htaccess",
                                    severity=Severity.HIGH,
                                    description=".htaccess file was accepted by the upload handler.",
                                    evidence=f"Uploaded .htaccess, server returned {resp.status_code} without error message.",
                                    remediation="Block uploads of server configuration files (.htaccess, web.config).",
                                    url=form.get("source_url", form["action"]),
                                    module="file_upload",
                                    cwe="CWE-434",
                                    confirmed=False,
                                ))

            _check_size_limit(session, form, field_name, other_data)


def _check_size_limit(session: ScanSession, form: dict, field_name: str, other_data: dict):
    large_content = "A" * (10 * 1024 * 1024)
    files = {field_name: ("largefile.txt", large_content, "text/plain")}
    try:
        resp = session.post(form["action"], files=files, data=other_data)
        if resp and resp.status_code in (200, 201):
            session.add_finding(Finding(
                title="No File Size Limit on Upload",
                severity=Severity.LOW,
                description="File upload accepts very large files (10MB+) without rejection.",
                evidence=f"Uploaded 10MB file, server returned {resp.status_code}.",
                remediation="Implement server-side file size limits.",
                url=form.get("source_url", form["action"]),
                module="file_upload",
                cwe="CWE-770",
                confirmed=True,
            ))
    except Exception:
        pass
