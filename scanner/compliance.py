from scanner.core import ScanSession, Severity, Finding

OWASP_TOP_10 = {
    "A01:2021 Broken Access Control": {
        "modules": ["idor", "directory", "misconfig"],
        "cwes": ["CWE-639", "CWE-548", "CWE-284", "CWE-601", "CWE-942"],
    },
    "A02:2021 Cryptographic Failures": {
        "modules": ["ssl", "headers"],
        "cwes": ["CWE-319", "CWE-326", "CWE-295", "CWE-311", "CWE-614"],
    },
    "A03:2021 Injection": {
        "modules": ["sqli", "xss", "cmdi", "ssti", "lfi", "xxe"],
        "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-1336", "CWE-98", "CWE-611"],
    },
    "A04:2021 Insecure Design": {
        "modules": ["auth", "csrf"],
        "cwes": ["CWE-352", "CWE-521", "CWE-204"],
    },
    "A05:2021 Security Misconfiguration": {
        "modules": ["misconfig", "headers", "directory", "fingerprint"],
        "cwes": ["CWE-16", "CWE-200", "CWE-1021", "CWE-644", "CWE-113"],
    },
    "A06:2021 Vulnerable Components": {
        "modules": ["fingerprint"],
        "cwes": ["CWE-1104"],
    },
    "A07:2021 Auth Failures": {
        "modules": ["auth", "jwt"],
        "cwes": ["CWE-798", "CWE-345", "CWE-321", "CWE-613"],
    },
    "A08:2021 Data Integrity Failures": {
        "modules": ["jwt", "csrf"],
        "cwes": ["CWE-345", "CWE-352"],
    },
    "A09:2021 Logging & Monitoring": {
        "modules": [],
        "cwes": [],
    },
    "A10:2021 SSRF": {
        "modules": ["ssrf"],
        "cwes": ["CWE-918"],
    },
}

PCI_DSS_CHECKS = {
    "6.5.1 Injection Flaws": ["sqli", "cmdi", "lfi", "ssti", "xxe"],
    "6.5.2 Buffer Overflows": [],
    "6.5.3 Insecure Cryptographic Storage": ["ssl", "info"],
    "6.5.4 Insecure Communications": ["ssl", "headers"],
    "6.5.5 Improper Error Handling": ["info"],
    "6.5.7 XSS": ["xss"],
    "6.5.8 Improper Access Control": ["idor", "directory", "auth"],
    "6.5.9 CSRF": ["csrf"],
    "6.5.10 Broken Auth": ["auth", "jwt"],
}


def generate_compliance_report(session: ScanSession) -> dict:
    report = {"owasp": {}, "pci_dss": {}}

    for category, info in OWASP_TOP_10.items():
        findings = [
            f for f in session.findings
            if f.module in info["modules"] or f.cwe in info["cwes"]
        ]
        max_sev = None
        for f in findings:
            if max_sev is None or f.severity.score > max_sev.score:
                max_sev = f.severity

        report["owasp"][category] = {
            "status": "FAIL" if findings else "PASS",
            "finding_count": len(findings),
            "max_severity": max_sev.value if max_sev else None,
            "findings": findings,
        }

    for requirement, modules in PCI_DSS_CHECKS.items():
        findings = [f for f in session.findings if f.module in modules]
        report["pci_dss"][requirement] = {
            "status": "FAIL" if findings else "PASS",
            "finding_count": len(findings),
            "findings": findings,
        }

    return report


def print_compliance_summary(report: dict):
    from colorama import Fore, Style

    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  OWASP TOP 10 (2021) COMPLIANCE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    passed = 0
    for category, data in report["owasp"].items():
        if data["status"] == "PASS":
            passed += 1
            print(f"  {Fore.GREEN}PASS{Style.RESET_ALL}  {category}")
        else:
            sev = data["max_severity"]
            count = data["finding_count"]
            print(f"  {Fore.RED}FAIL{Style.RESET_ALL}  {category} ({count} findings, max: {sev})")

    total = len(report["owasp"])
    print(f"\n  Score: {passed}/{total} categories passing")

    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  PCI DSS v4.0 RELEVANT CHECKS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    pci_passed = 0
    for req, data in report["pci_dss"].items():
        if data["status"] == "PASS":
            pci_passed += 1
            print(f"  {Fore.GREEN}PASS{Style.RESET_ALL}  {req}")
        else:
            count = data["finding_count"]
            print(f"  {Fore.RED}FAIL{Style.RESET_ALL}  {req} ({count} findings)")

    pci_total = len(report["pci_dss"])
    print(f"\n  Score: {pci_passed}/{pci_total} requirements passing")


def generate_compliance_html(report: dict, target: str) -> str:
    import html as html_mod
    severity_colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706",
        "LOW": "#2563eb", "INFO": "#6b7280",
    }

    owasp_rows = ""
    for category, data in report["owasp"].items():
        status_color = "#22c55e" if data["status"] == "PASS" else "#dc2626"
        sev_html = ""
        if data["max_severity"]:
            sev_color = severity_colors.get(data["max_severity"], "#6b7280")
            sev_html = f'<span style="color:{sev_color};font-weight:600;">{data["max_severity"]}</span>'
        owasp_rows += f"""
        <tr>
            <td style="color:{status_color};font-weight:700;">{data['status']}</td>
            <td>{html_mod.escape(category)}</td>
            <td>{data['finding_count']}</td>
            <td>{sev_html}</td>
        </tr>"""

    pci_rows = ""
    for req, data in report["pci_dss"].items():
        status_color = "#22c55e" if data["status"] == "PASS" else "#dc2626"
        pci_rows += f"""
        <tr>
            <td style="color:{status_color};font-weight:700;">{data['status']}</td>
            <td>{html_mod.escape(req)}</td>
            <td>{data['finding_count']}</td>
        </tr>"""

    owasp_pass = sum(1 for d in report["owasp"].values() if d["status"] == "PASS")
    pci_pass = sum(1 for d in report["pci_dss"].values() if d["status"] == "PASS")

    return f"""
    <h2 class="section-title">OWASP Top 10 (2021) Compliance — {owasp_pass}/{len(report['owasp'])}</h2>
    <div style="overflow-x:auto;margin-bottom:24px;">
    <table style="width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;">
        <thead><tr style="background:#0f172a;">
            <th style="padding:10px 16px;text-align:left;color:#94a3b8;width:60px;">Status</th>
            <th style="padding:10px 16px;text-align:left;color:#94a3b8;">Category</th>
            <th style="padding:10px 16px;text-align:left;color:#94a3b8;width:80px;">Findings</th>
            <th style="padding:10px 16px;text-align:left;color:#94a3b8;width:80px;">Severity</th>
        </tr></thead>
        <tbody>{owasp_rows}</tbody>
    </table></div>

    <h2 class="section-title">PCI DSS v4.0 Compliance — {pci_pass}/{len(report['pci_dss'])}</h2>
    <div style="overflow-x:auto;margin-bottom:24px;">
    <table style="width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;">
        <thead><tr style="background:#0f172a;">
            <th style="padding:10px 16px;text-align:left;color:#94a3b8;width:60px;">Status</th>
            <th style="padding:10px 16px;text-align:left;color:#94a3b8;">Requirement</th>
            <th style="padding:10px 16px;text-align:left;color:#94a3b8;width:80px;">Findings</th>
        </tr></thead>
        <tbody>{pci_rows}</tbody>
    </table></div>
    """
